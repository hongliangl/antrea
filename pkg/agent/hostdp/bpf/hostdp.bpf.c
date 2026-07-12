//go:build ignore

// Antrea eBPF host-network datapath (WIP).
//
// Step 2: Pod-to-external masquerade on the Node transport interface with tc.
//   - egress hook  (hostdp_egress):  a local Pod's external-bound packet is SNAT'd, source address ->
//                                    the Node transport IP (port-preserving), and a reverse conntrack
//                                    entry is recorded.
//   - ingress hook (hostdp_ingress): a reply to the Node transport IP is looked up in the reverse
//                                    conntrack map and DNAT'd back to the original Pod IP.
// This replaces the iptables `masquerade Pod to external packets` rule. Address-only (port-preserving)
// translation: correct for non-colliding flows; port re-allocation on collision is a follow-up. IPv4 only,
// no IP options (ihl==5). OVS is untouched.
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

// --- helpers (declared manually to avoid a libbpf/vmlinux dependency) ---
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) = (void *)BPF_FUNC_skb_store_bytes;
static long (*bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 size) = (void *)BPF_FUNC_l3_csum_replace;
static long (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) = (void *)BPF_FUNC_l4_csum_replace;

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

// nat_ct: reverse conntrack for masquerade. Key identifies a reply as seen arriving at the Node; value is the
// original Pod address to restore.
struct nat_key {
	__u32 node_addr; // SNAT'd (Node) address
	__u32 ext_addr;  // external peer address
	__u16 port;      // Pod/Node port (preserved); ICMP id for ICMP
	__u16 peer_port; // external peer port; ICMP id for ICMP
	__u8 proto;
	__u8 pad[3];
};
struct nat_val {
	__u32 pod_addr;
	__u32 pad;
};
struct {
	int (*type)[BPF_MAP_TYPE_LRU_HASH];
	int (*max_entries)[65536];
	struct nat_key *key;
	struct nat_val *value;
} nat_ct SEC(".maps");

// stats: per-verdict counters. 0=snat, 1=unsnat, 2=passthrough.
struct {
	int (*type)[BPF_MAP_TYPE_ARRAY];
	int (*max_entries)[8];
	__u32 *key;
	__u64 *value;
} stats SEC(".maps");
#define STAT_SNAT 0
#define STAT_UNSNAT 1
#define STAT_PASS 2

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

	// Masquerade only local Pod -> external (dst is not any cluster Pod). Everything else passes through.
	if (!is_local_pod_ip(saddr) || is_pod_ip(daddr)) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	__u16 self_port, peer_port;
	if (flow_ports(proto, l4, data_end, 1, &self_port, &peer_port) < 0) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	__u32 node_ip = cfg(CFG_NODE_IP);
	if (node_ip == 0) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}

	// Record the reverse mapping so replies to node_ip:self_port from ext_addr:peer_port restore saddr.
	struct nat_key key = {.node_addr = node_ip, .ext_addr = daddr, .port = self_port, .peer_port = peer_port, .proto = proto};
	struct nat_val val = {.pod_addr = saddr};
	bpf_map_update_elem(&nat_ct, &key, &val, BPF_ANY);

	int l4off = l4_check_off(proto, l4, data_end);
	// Rewrite source address; fix IP and (for TCP/UDP) L4 pseudo-header checksums.
	bpf_skb_store_bytes(skb, IP_SADDR_OFF, &node_ip, 4, 0);
	bpf_l3_csum_replace(skb, IP_CHECK_OFF, saddr, node_ip, 4);
	if (l4off >= 0)
		bpf_l4_csum_replace(skb, l4off, saddr, node_ip, 4 | BPF_F_PSEUDO_HDR);
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

	__u32 node_ip = cfg(CFG_NODE_IP);
	if (node_ip == 0 || daddr != node_ip) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	__u16 self_port, peer_port;
	if (flow_ports(proto, l4, data_end, 0, &self_port, &peer_port) < 0) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	// Reply arriving at node_ip:self_port from saddr:peer_port -> look up the original Pod address.
	struct nat_key key = {.node_addr = node_ip, .ext_addr = saddr, .port = self_port, .peer_port = peer_port, .proto = proto};
	struct nat_val *val = bpf_map_lookup_elem(&nat_ct, &key);
	if (!val) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	__u32 pod_ip = val->pod_addr;

	int l4off = l4_check_off(proto, l4, data_end);
	// Rewrite destination address back to the Pod IP; fix checksums.
	bpf_skb_store_bytes(skb, IP_DADDR_OFF, &pod_ip, 4, 0);
	bpf_l3_csum_replace(skb, IP_CHECK_OFF, node_ip, pod_ip, 4);
	if (l4off >= 0)
		bpf_l4_csum_replace(skb, l4off, node_ip, pod_ip, 4 | BPF_F_PSEUDO_HDR);
	count(STAT_UNSNAT);
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
