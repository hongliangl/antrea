//go:build ignore

// Antrea eBPF host-network datapath (WIP).
//
// Programs:
//   - hostdp_egress (transport egress):  NodePort reply un-DNAT; Egress SNAT (member Pod -> Egress IP);
//                                        Pod-to-external masquerade (SNAT to the Node transport IP).
//   - hostdp_ingress (transport ingress): NodePort DNAT (node_ip:nodePort -> backend, address + port);
//                                        reverse masquerade / Egress un-SNAT; forwards to the member's
//                                        Node when the restored destination is a remote Pod.
//   - hostdp_fwd (gateway ingress):      Pod-to-remote-Pod forwarding (pod_routes next hop + L2 via
//                                        bpf_fib_lookup + bpf_redirect); Egress steering (member Pod's
//                                        external traffic forwarded to the Egress Node untouched).
//
// These replace the host-stack rules programmed by pkg/agent/route: the masquerade and NodePort iptables
// rules, the `podCIDR via peerNodeIP` routes, and the Egress fwmark policy routing. Masquerade/Egress SNAT
// keeps the Pod's source port when possible and remaps it on collision (two Pods using the same source port
// to the same peer), tracked in the snat_ct/nat_ct pair. IPv4 only, no IP options (ihl==5). OVS is untouched.
//
// Compile: clang -O2 -g -target bpfel -c hostdp.bpf.c -o hostdp_bpfel.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#define SEC(name) __attribute__((section(name), used))
#define ETH_P_IP 0x0800
#define BPF_F_PSEUDO_HDR (1ULL << 4)
#define BPF_FIB_LOOKUP_DIRECT (1U << 0)
#define BPF_FIB_LKUP_RET_SUCCESS 0

// --- helpers (declared manually to avoid a libbpf/vmlinux dependency) ---
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) = (void *)BPF_FUNC_skb_store_bytes;
static long (*bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 size) = (void *)BPF_FUNC_l3_csum_replace;
static long (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) = (void *)BPF_FUNC_l4_csum_replace;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)BPF_FUNC_redirect;
static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags) = (void *)BPF_FUNC_fib_lookup;

// --- maps ---

// pod_cidrs: LPM trie of all cluster Pod CIDRs (replaces antreaPodIPSet). Used to exclude Pod-to-Pod traffic
// from masquerade. addr is network-order bytes (byte array to keep the LPM layout unambiguous vs. the loader).
struct pod_cidr_key {
	__u32 prefixlen;
	__u8 addr[4];
};
struct {
	int (*type)[BPF_MAP_TYPE_LPM_TRIE];
	int (*max_entries)[1024];
	int (*map_flags)[BPF_F_NO_PREALLOC];
	struct pod_cidr_key *key;
	__u8 *value;
} pod_cidrs SEC(".maps");

// node_config (all values network order except the prefix lengths):
//   0 = Node transport IPv4; 1 = transport subnet prefix len; 2 = local Pod CIDR network; 3 = local Pod CIDR prefix len.
struct {
	int (*type)[BPF_MAP_TYPE_ARRAY];
	int (*max_entries)[4];
	__u32 *key;
	__u32 *value;
} node_config SEC(".maps");
#define CFG_NODE_IP 0
#define CFG_LOCAL_POD_NET 2
#define CFG_LOCAL_POD_PREFIX 3

// nat_ct: reverse conntrack for masquerade / Egress SNAT. Key identifies a reply as seen arriving at the
// Node; value is the original Pod address and source port to restore (the source port may have been remapped
// to resolve a collision between two Pods using the same port to the same peer).
struct nat_key {
	__u32 node_addr; // SNAT'd address (Node transport IP or an Egress IP)
	__u32 ext_addr;  // external peer address
	__u16 port;      // translated source port; ICMP id for ICMP
	__u16 peer_port; // external peer port; ICMP id for ICMP
	__u8 proto;
	__u8 pad[3];
};
struct nat_val {
	__u32 pod_addr;
	__u16 pod_port; // the Pod's original source port (== nat_key.port unless remapped)
	__u16 pad;
};
struct {
	int (*type)[BPF_MAP_TYPE_LRU_HASH];
	int (*max_entries)[65536];
	struct nat_key *key;
	struct nat_val *value;
} nat_ct SEC(".maps");

// snat_ct: forward conntrack for masquerade / Egress SNAT, so an established flow keeps its translated source
// port across packets (needed once ports can be remapped on collision).
struct snat_key {
	__u32 pod_addr;
	__u32 ext_addr;
	__u16 pod_port;
	__u16 peer_port;
	__u8 proto;
	__u8 pad[3];
};
struct snat_val {
	__u16 port; // translated source port
	__u16 pad;
};
struct {
	int (*type)[BPF_MAP_TYPE_LRU_HASH];
	int (*max_entries)[65536];
	struct snat_key *key;
	struct snat_val *value;
} snat_ct SEC(".maps");

// pod_routes: LPM trie mapping a remote Pod CIDR to the next-hop (peer Node transport IP, network order).
// This replaces the kernel route `podCIDR via peerNodeIP`; the kernel FIB is used only to resolve the L2
// neighbor of the (on-link) next hop.
struct {
	int (*type)[BPF_MAP_TYPE_LPM_TRIE];
	int (*max_entries)[1024];
	int (*map_flags)[BPF_F_NO_PREALLOC];
	struct pod_cidr_key *key;
	__u32 *value;
} pod_routes SEC(".maps");

// egress_steer: member Pod IP -> Egress Node transport IP (programmed on the member Pod's Node). The Pod's
// external-bound traffic is forwarded to the Egress Node untouched; the Egress Node SNATs it to the Egress IP.
// Replaces the Egress fwmark policy routing (ip rule fwmark -> table -> default via egressNodeIP).
struct {
	int (*type)[BPF_MAP_TYPE_HASH];
	int (*max_entries)[4096];
	__u32 *key;
	__u32 *value;
} egress_steer SEC(".maps");

// egress_snat: member Pod IP -> Egress IP (programmed on the Egress Node, for local and remote members).
// Replaces the member ipset + mark-based SNAT iptables rules on the Egress Node.
struct {
	int (*type)[BPF_MAP_TYPE_HASH];
	int (*max_entries)[4096];
	__u32 *key;
	__u32 *value;
} egress_snat SEC(".maps");

// nodeport: {NodePort, proto} -> backend. Replaces the NodePort DNAT iptables rules. All fields network order.
struct np_key {
	__u16 port;
	__u8 proto;
	__u8 pad;
};
struct np_backend {
	__u32 addr;
	__u16 port;
	__u16 pad;
};
struct {
	int (*type)[BPF_MAP_TYPE_HASH];
	int (*max_entries)[1024];
	struct np_key *key;
	struct np_backend *value;
} nodeport SEC(".maps");

// np_ct: reverse conntrack for NodePort DNAT — identifies a backend's reply and restores the Node IP +
// NodePort as its source.
struct np_ct_key {
	__u32 backend_addr;
	__u32 client_addr;
	__u16 backend_port;
	__u16 client_port;
	__u8 proto;
	__u8 pad[3];
};
struct np_ct_val {
	__u16 node_port;
	__u16 pad;
};
struct {
	int (*type)[BPF_MAP_TYPE_LRU_HASH];
	int (*max_entries)[65536];
	struct np_ct_key *key;
	struct np_ct_val *value;
} np_ct SEC(".maps");

// stats: per-verdict counters.
struct {
	int (*type)[BPF_MAP_TYPE_ARRAY];
	int (*max_entries)[8];
	__u32 *key;
	__u64 *value;
} stats SEC(".maps");
#define STAT_SNAT 0
#define STAT_UNSNAT 1
#define STAT_PASS 2
#define STAT_FWD 3
#define STAT_FWD_MISS 4
#define STAT_ESNAT 5
#define STAT_NP_DNAT 6
#define STAT_NP_SNAT 7

static __always_inline void count(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &slot);
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline __u32 cfg(__u32 idx)
{
	__u32 *v = bpf_map_lookup_elem(&node_config, &idx);
	return v ? *v : 0;
}

static __always_inline int is_pod_ip(__u32 addr)
{
	struct pod_cidr_key key = {.prefixlen = 32};
	__builtin_memcpy(key.addr, &addr, 4);
	return bpf_map_lookup_elem(&pod_cidrs, &key) != 0;
}

static __always_inline int is_local_pod_ip(__u32 addr)
{
	__u32 net = cfg(CFG_LOCAL_POD_NET);
	__u32 prefix = cfg(CFG_LOCAL_POD_PREFIX);
	if (prefix == 0 || prefix > 32)
		return 0;
	__u32 mask = prefix == 32 ? 0xffffffff : __builtin_bswap32(~((1u << (32 - prefix)) - 1));
	return (addr & mask) == (net & mask);
}

// L4 offsets assuming IPv4 with no options (ihl==5): eth(14) + ip(20).
#define L4_OFF (ETH_HLEN + 20)
#define IP_CHECK_OFF (ETH_HLEN + 10)
#define IP_SADDR_OFF (ETH_HLEN + 12)
#define IP_DADDR_OFF (ETH_HLEN + 16)

// l4 checksum field offset within the L4 header, or -1 if the protocol/packet has no updatable checksum here.
static __always_inline int l4_check_off(__u8 proto, void *l4, void *data_end)
{
	if (proto == IPPROTO_TCP) {
		struct tcphdr *t = l4;
		if ((void *)(t + 1) > data_end)
			return -1;
		return L4_OFF + 16;
	}
	if (proto == IPPROTO_UDP) {
		struct udphdr *u = l4;
		if ((void *)(u + 1) > data_end)
			return -1;
		if (u->check == 0) // UDP with no checksum: must not touch it
			return -1;
		return L4_OFF + 6;
	}
	return -1; // ICMP handled separately (no pseudo-header, addr change doesn't affect its checksum)
}

// Extract the (port, peer_port) identifying a flow. For TCP/UDP these are the transport ports; for ICMP echo
// they are both the ICMP id. Returns 0 on success, and whether this is ICMP.
static __always_inline int flow_ports(__u8 proto, void *l4, void *data_end, int egress, __u16 *self, __u16 *peer)
{
	if (proto == IPPROTO_TCP) {
		struct tcphdr *t = l4;
		if ((void *)(t + 1) > data_end)
			return -1;
		*self = egress ? t->source : t->dest;
		*peer = egress ? t->dest : t->source;
		return 0;
	}
	if (proto == IPPROTO_UDP) {
		struct udphdr *u = l4;
		if ((void *)(u + 1) > data_end)
			return -1;
		*self = egress ? u->source : u->dest;
		*peer = egress ? u->dest : u->source;
		return 0;
	}
	if (proto == IPPROTO_ICMP) {
		struct icmphdr *ic = l4;
		if ((void *)(ic + 1) > data_end)
			return -1;
		*self = ic->un.echo.id;
		*peer = ic->un.echo.id;
		return 0;
	}
	return -1;
}

static __always_inline int parse_ipv4(struct __sk_buff *skb, struct iphdr **ip_out, void **l4_out)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;
	if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
		return -1;
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return -1;
	if (ip->ihl != 5) // IP options not supported yet
		return -1;
	*ip_out = ip;
	*l4_out = (void *)ip + sizeof(*ip);
	return 0;
}

// Forward the packet to an on-link next hop: resolve its L2 neighbor + output interface via the kernel FIB
// (L2 only — the L3 decision was already made from our maps), rewrite the Ethernet header, redirect.
static __always_inline int fwd_to_next_hop(struct __sk_buff *skb, __u32 nh)
{
	struct bpf_fib_lookup fib = {};
	fib.family = AF_INET;
	fib.ipv4_dst = nh;
	fib.ifindex = skb->ifindex;
	long rc = bpf_fib_lookup(skb, &fib, sizeof(fib), BPF_FIB_LOOKUP_DIRECT);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
		// Neighbor unresolved or no route to the next hop: fall back to the stack so it can resolve/ARP.
		count(STAT_FWD_MISS);
		return TC_ACT_OK;
	}
	bpf_skb_store_bytes(skb, 0, fib.dmac, 6, 0);
	bpf_skb_store_bytes(skb, 6, fib.smac, 6, 0);
	count(STAT_FWD);
	return bpf_redirect(fib.ifindex, 0);
}

// If addr is a remote Pod (per pod_routes), forward the packet to its Node; otherwise let the stack deliver.
static __always_inline int fwd_if_remote_pod(struct __sk_buff *skb, __u32 addr)
{
	struct pod_cidr_key rkey = {.prefixlen = 32};
	__builtin_memcpy(rkey.addr, &addr, 4);
	__u32 *nh = bpf_map_lookup_elem(&pod_routes, &rkey);
	if (!nh)
		return TC_ACT_OK;
	return fwd_to_next_hop(skb, *nh);
}

// Rewrite the source address (and for NodePort replies the source port), fixing IP and L4 checksums.
static __always_inline void snat_source(struct __sk_buff *skb, __u32 from, __u32 to, int l4off)
{
	bpf_skb_store_bytes(skb, IP_SADDR_OFF, &to, 4, 0);
	bpf_l3_csum_replace(skb, IP_CHECK_OFF, from, to, 4);
	if (l4off >= 0)
		bpf_l4_csum_replace(skb, l4off, from, to, 4 | BPF_F_PSEUDO_HDR);
}

// SNAT the packet's source to snat_addr (masquerade to the Node IP, or Egress SNAT to an Egress IP),
// remapping the source port when another Pod already owns {snat_addr, daddr, port, peer_port} in nat_ct
// (two Pods using the same source port to the same peer). The chosen port is remembered in snat_ct so the
// flow keeps it, and the reverse entry in nat_ct lets ingress restore both the address and the port.
static __always_inline void do_snat(struct __sk_buff *skb, __u32 saddr, __u32 daddr, __u32 snat_addr,
				    __u16 self_port, __u16 peer_port, __u8 proto, int l4off)
{
	int can_remap = proto == IPPROTO_TCP || proto == IPPROTO_UDP;
	__u16 new_port = self_port;
	struct snat_key fk = {.pod_addr = saddr, .ext_addr = daddr, .pod_port = self_port, .peer_port = peer_port, .proto = proto};
	struct snat_val *fv = bpf_map_lookup_elem(&snat_ct, &fk);
	if (fv) {
		new_port = fv->port; // established flow: keep its translated port
	} else if (can_remap) {
		// Prefer the Pod's own port; on collision scan a few candidates (ports are network order, so
		// convert for the arithmetic). A slot is usable if free or already owned by this exact flow.
		struct nat_key probe = {.node_addr = snat_addr, .ext_addr = daddr, .peer_port = peer_port, .proto = proto};
		__u16 host_port = __builtin_bswap16(self_port);
#pragma unroll
		for (int i = 0; i < 8; i++) {
			__u16 cand_h = host_port + i;
			if (cand_h == 0)
				cand_h = 1024;
			__u16 cand = __builtin_bswap16(cand_h);
			probe.port = cand;
			struct nat_val *rv = bpf_map_lookup_elem(&nat_ct, &probe);
			if (!rv || (rv->pod_addr == saddr && rv->pod_port == self_port)) {
				new_port = cand;
				break;
			}
			// All candidates taken: keep self_port (best effort; last owner wins, as before).
		}
	}

	struct nat_key rk = {.node_addr = snat_addr, .ext_addr = daddr, .port = new_port, .peer_port = peer_port, .proto = proto};
	struct nat_val rv = {.pod_addr = saddr, .pod_port = self_port};
	bpf_map_update_elem(&nat_ct, &rk, &rv, BPF_ANY);
	struct snat_val sv = {.port = new_port};
	bpf_map_update_elem(&snat_ct, &fk, &sv, BPF_ANY);

	snat_source(skb, saddr, snat_addr, l4off);
	if (can_remap && new_port != self_port) {
		if (l4off >= 0)
			bpf_l4_csum_replace(skb, l4off, self_port, new_port, 2);
		bpf_skb_store_bytes(skb, L4_OFF, &new_port, 2, 0);
	}
}

SEC("tc")
int hostdp_egress(struct __sk_buff *skb)
{
	struct iphdr *ip;
	void *l4;
	if (parse_ipv4(skb, &ip, &l4) < 0) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	void *data_end = (void *)(long)skb->data_end;
	__u32 saddr = ip->saddr, daddr = ip->daddr;
	__u8 proto = ip->protocol;

	// Pod-to-Pod is never NAT'd.
	if (is_pod_ip(daddr)) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	__u16 self_port, peer_port;
	if (flow_ports(proto, l4, data_end, 1, &self_port, &peer_port) < 0) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	int l4off = l4_check_off(proto, l4, data_end);

	// NodePort reply: a backend Pod answering a NodePort client — restore the Node IP + NodePort source.
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		struct np_ct_key npk = {.backend_addr = saddr, .client_addr = daddr, .backend_port = self_port, .client_port = peer_port, .proto = proto};
		struct np_ct_val *npv = bpf_map_lookup_elem(&np_ct, &npk);
		if (npv) {
			__u32 node_ip = cfg(CFG_NODE_IP);
			__u16 node_port = npv->node_port;
			snat_source(skb, saddr, node_ip, l4off);
			if (l4off >= 0)
				bpf_l4_csum_replace(skb, l4off, self_port, node_port, 2);
			bpf_skb_store_bytes(skb, L4_OFF, &node_port, 2, 0);
			count(STAT_NP_SNAT);
			return TC_ACT_OK;
		}
	}

	// Egress: a member Pod (local or remote) leaving through this (Egress) Node is SNAT'd to its Egress IP.
	__u32 *egress_ip = bpf_map_lookup_elem(&egress_snat, &saddr);
	if (egress_ip) {
		do_snat(skb, saddr, daddr, *egress_ip, self_port, peer_port, proto, l4off);
		count(STAT_ESNAT);
		return TC_ACT_OK;
	}
	// A steered Egress member's traffic leaves this (source) Node untouched; the Egress Node SNATs it.
	if (bpf_map_lookup_elem(&egress_steer, &saddr)) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}

	// Default masquerade: local Pod -> external is SNAT'd to the Node transport IP.
	if (!is_local_pod_ip(saddr)) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	__u32 node_ip = cfg(CFG_NODE_IP);
	if (node_ip == 0) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}

	do_snat(skb, saddr, daddr, node_ip, self_port, peer_port, proto, l4off);
	count(STAT_SNAT);
	return TC_ACT_OK;
}

SEC("tc")
int hostdp_ingress(struct __sk_buff *skb)
{
	struct iphdr *ip;
	void *l4;
	if (parse_ipv4(skb, &ip, &l4) < 0) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	void *data_end = (void *)(long)skb->data_end;
	__u32 saddr = ip->saddr, daddr = ip->daddr;
	__u8 proto = ip->protocol;

	__u16 self_port, peer_port;
	if (flow_ports(proto, l4, data_end, 0, &self_port, &peer_port) < 0) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	int l4off = l4_check_off(proto, l4, data_end);

	// NodePort: client -> node_ip:nodePort is DNAT'd (address + port) to the backend Pod.
	__u32 node_ip = cfg(CFG_NODE_IP);
	if (daddr == node_ip && (proto == IPPROTO_TCP || proto == IPPROTO_UDP)) {
		struct np_key k = {.port = self_port, .proto = proto};
		struct np_backend *b = bpf_map_lookup_elem(&nodeport, &k);
		if (b) {
			__u32 baddr = b->addr;
			__u16 bport = b->port;
			// Record the reverse mapping so the backend's replies restore node_ip:nodePort.
			struct np_ct_key npk = {.backend_addr = baddr, .client_addr = saddr, .backend_port = bport, .client_port = peer_port, .proto = proto};
			struct np_ct_val npv = {.node_port = self_port};
			bpf_map_update_elem(&np_ct, &npk, &npv, BPF_ANY);
			bpf_skb_store_bytes(skb, IP_DADDR_OFF, &baddr, 4, 0);
			bpf_l3_csum_replace(skb, IP_CHECK_OFF, daddr, baddr, 4);
			if (l4off >= 0) {
				bpf_l4_csum_replace(skb, l4off, daddr, baddr, 4 | BPF_F_PSEUDO_HDR);
				bpf_l4_csum_replace(skb, l4off, self_port, bport, 2);
			}
			bpf_skb_store_bytes(skb, L4_OFF + 2, &bport, 2, 0);
			count(STAT_NP_DNAT);
			// Local backend: the stack delivers it via the gateway; remote backend: forward to its Node.
			return fwd_if_remote_pod(skb, baddr);
		}
	}

	// Reverse masquerade / Egress SNAT: a reply to a translated source (Node transport IP or an Egress IP —
	// whatever address the flow was SNAT'd to is the nat_ct key) restores the original Pod destination.
	struct nat_key key = {.node_addr = daddr, .ext_addr = saddr, .port = self_port, .peer_port = peer_port, .proto = proto};
	struct nat_val *val = bpf_map_lookup_elem(&nat_ct, &key);
	if (!val) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	__u32 pod_ip = val->pod_addr;
	__u16 pod_port = val->pod_port;

	// Rewrite destination address (and port, if it was remapped) back to the Pod's; fix checksums.
	bpf_skb_store_bytes(skb, IP_DADDR_OFF, &pod_ip, 4, 0);
	bpf_l3_csum_replace(skb, IP_CHECK_OFF, daddr, pod_ip, 4);
	if (l4off >= 0)
		bpf_l4_csum_replace(skb, l4off, daddr, pod_ip, 4 | BPF_F_PSEUDO_HDR);
	if (pod_port != self_port && (proto == IPPROTO_TCP || proto == IPPROTO_UDP)) {
		if (l4off >= 0)
			bpf_l4_csum_replace(skb, l4off, self_port, pod_port, 2);
		bpf_skb_store_bytes(skb, L4_OFF + 2, &pod_port, 2, 0);
	}
	count(STAT_UNSNAT);
	// Local Pod: the stack delivers it via the gateway; remote member Pod (Egress reply on the Egress Node):
	// forward it to the member's Node.
	return fwd_if_remote_pod(skb, pod_ip);
}

// hostdp_fwd forwards a local Pod's packet destined to a remote Pod directly to the peer Node, replacing the
// kernel route `remotePodCIDR via peerNodeIP`. It runs on the gateway (Pod-facing) interface ingress, where
// Pod traffic enters the host from OVS, so it redirects before the host routing decision.
//
// L3 next hop comes from pod_routes (our map, = the replaced route); the kernel FIB is consulted only via
// bpf_fib_lookup to resolve the on-link next hop's L2 neighbor (the peer Node MAC) and output interface. Then
// the Ethernet header is rewritten and the packet is redirected to that interface's egress. Pod-to-external
// and Pod-to-local-Pod traffic is left to pass (external is masqueraded on the transport egress hook; local
// delivery uses the retained local-Pod route via the gateway).
SEC("tc")
int hostdp_fwd(struct __sk_buff *skb)
{
	struct iphdr *ip;
	void *l4;
	if (parse_ipv4(skb, &ip, &l4) < 0)
		return TC_ACT_OK;
	__u32 saddr = ip->saddr, daddr = ip->daddr;

	if (!is_local_pod_ip(saddr))
		return TC_ACT_OK;

	// Local Pod -> remote Pod: forward to the peer Node from pod_routes.
	struct pod_cidr_key rkey = {.prefixlen = 32};
	__builtin_memcpy(rkey.addr, &daddr, 4);
	__u32 *nh = bpf_map_lookup_elem(&pod_routes, &rkey);
	if (nh)
		return fwd_to_next_hop(skb, *nh);

	// Local Egress member Pod -> external: steer to the Egress Node untouched (it SNATs to the Egress IP).
	// Replaces the Egress fwmark policy routing on the source Node.
	if (!is_pod_ip(daddr)) {
		__u32 *steer = bpf_map_lookup_elem(&egress_steer, &saddr);
		if (steer)
			return fwd_to_next_hop(skb, *steer);
	}

	// Everything else (Pod -> external without Egress, local delivery): let the stack handle it.
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
