//go:build ignore

// Antrea eBPF host-network datapath (WIP).
//
// Step 1: attach on the Node transport interface with tc, classify traffic against the Pod-CIDR / node-config
// maps, count per verdict, and pass everything through (TC_ACT_OK). This proves the load/attach/map pipeline
// without changing any forwarding. SNAT / forwarding / DNAT are layered on top in later steps.
//
// Compile:
//   clang -O2 -g -target bpfel -c hostdp.bpf.c -o hostdp_bpfel.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

#define SEC(name) __attribute__((section(name), used))

#define ETH_P_IP 0x0800

// --- helpers (declared manually to avoid a libbpf/vmlinux dependency) ---
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;

// --- maps ---

// pod_cidrs: LPM trie of all cluster Pod CIDRs (replaces antreaPodIPSet). A hit means "this IPv4 is a Pod IP".
// addr is a raw 4-byte array in network order: the LPM trie matches the data left-to-right, so it must be
// network order, and a byte array avoids host-endianness ambiguity between this program and the Go loader.
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

// node_config: index 0 = this Node's transport IPv4 (network byte order); index 1 = transport subnet mask.
struct {
	int (*type)[BPF_MAP_TYPE_ARRAY];
	int (*max_entries)[4];
	__u32 *key;
	__u32 *value;
} node_config SEC(".maps");

// stats: per-verdict packet counters. 0=pod->pod, 1=pod->external, 2=other.
struct {
	int (*type)[BPF_MAP_TYPE_ARRAY];
	int (*max_entries)[8];
	__u32 *key;
	__u64 *value;
} stats SEC(".maps");

#define STAT_POD_TO_POD 0
#define STAT_POD_TO_EXTERNAL 1
#define STAT_OTHER 2

static __always_inline void count(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &slot);
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline int is_pod_ip(__u32 addr)
{
	struct pod_cidr_key key = {.prefixlen = 32};
	__builtin_memcpy(key.addr, &addr, 4); // addr is __be32; copies the network-order bytes
	return bpf_map_lookup_elem(&pod_cidrs, &key) != 0;
}

static __always_inline int classify(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	int src_pod = is_pod_ip(ip->saddr);
	int dst_pod = is_pod_ip(ip->daddr);
	if (src_pod && dst_pod)
		count(STAT_POD_TO_POD);
	else if (src_pod && !dst_pod)
		count(STAT_POD_TO_EXTERNAL);
	else
		count(STAT_OTHER);
	return TC_ACT_OK;
}

SEC("tc")
int hostdp_egress(struct __sk_buff *skb)
{
	return classify(skb);
}

SEC("tc")
int hostdp_ingress(struct __sk_buff *skb)
{
	return classify(skb);
}

char LICENSE[] SEC("license") = "GPL";
