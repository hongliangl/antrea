//go:build ignore

// Antrea eBPF host network datapath: cross-Node Pod forwarding.
//
// In noEncap mode the host stack forwards a packet from a local Pod to a remote Pod through the route
// "remotePodCIDR via peerNodeIP" which pkg/agent/route installs. These two programs do that forwarding
// before the stack does, in both directions:
//
//   - hostdp_fwd    (gateway ingress):   a local Pod's packet to a remote Pod CIDR is redirected to the
//                                        transport interface, towards the peer Node.
//   - hostdp_return (transport ingress): a remote Pod's packet to a local Pod is redirected to the gateway
//                                        interface, towards OVS.
//
// Both directions are handled so that a connection is either seen by the host stack in both directions or in
// neither. Redirecting only the request would leave conntrack with a reply and no request, which a Node whose
// FORWARD policy accepts established connections only would then drop.
//
// Nothing else is moved out of the host stack: a packet which is not a cross-Node Pod packet is passed to the
// stack untouched, and so is one this datapath cannot handle. The routes it replaces are still installed, so
// the stack forwards those packets exactly as it does without this datapath. Every fallback is therefore a
// slower path, never a lost packet. That also makes the neighbor entries this relies on stay resolved: the
// kernel is the only one which resolves them, and it does so when it forwards a packet itself.
//
// IPv4 only, and no IP options (ihl != 5 goes to the stack). OVS is untouched.
//
// Everything here is written out rather than hidden behind macros, so that the file can be read without
// expanding anything first. The three attributes it uses are explained where they first appear.
//
// Compile: clang -O2 -g -target bpfel -c hostdp.bpf.c -o hostdp_bpfel.o

#include <linux/bpf.h>      // the BPF_FUNC_ helper numbers, the BPF_MAP_TYPE_ types, struct __sk_buff
#include <linux/if_ether.h> // struct ethhdr
#include <linux/ip.h>       // struct iphdr
#include <linux/pkt_cls.h>  // TC_ACT_OK

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// The value of h_proto in the Ethernet header when the payload is IPv4.
#define ETH_P_IP 0x0800

// The flag passed to bpf_fib_lookup which asks for the routing table only, leaving policy routing out of the
// answer.
#define BPF_FIB_LOOKUP_DIRECT 1

// What bpf_fib_lookup returns when it found an answer.
#define BPF_FIB_LKUP_RET_SUCCESS 0

// The address family of IPv4, the same value socket code uses.
#define AF_INET 2

// Offsets into the packet, in bytes from its first one. The Ethernet header is 14 bytes, six of destination
// address, six of source address and two of type. The IPv4 header follows it and holds the TTL at its eighth
// byte and the header checksum at its tenth.
#define ETH_HLEN     14
#define IP_TTL_OFF   (ETH_HLEN + 8)
#define IP_CHECK_OFF (ETH_HLEN + 10)

// The slots of the node_config map below, which is an array, so these are its indices.
#define CFG_LOCAL_POD_NET    0 // the local Pod CIDR, which identifies the Pods of this Node
#define CFG_LOCAL_POD_PREFIX 1 // its prefix length; 0 means the datapath is not configured yet
#define CFG_TRANSPORT_MTU    2 // the MTU of the transport interface, which hostdp_fwd sends to
#define CFG_GATEWAY_MTU      3 // the MTU of the gateway interface, which hostdp_return sends to
#define CFG_GATEWAY_IFINDEX  4 // the gateway interface, so a redirect to it can be recognized
#define CFG_GATEWAY_IP       5 // the gateway's own address, which is in the Pod CIDR without being a Pod

// The slots of the stats map, read through the Interface for logging and troubleshooting.
#define STAT_FWD         0 // redirected to the peer Node
#define STAT_FWD_MISS    1 // meant for a peer Node, but left to the stack
#define STAT_RETURN      2 // redirected to the gateway
#define STAT_RETURN_MISS 3 // meant for a local Pod, but left to the stack
#define STAT_PASS        4 // not a cross-Node Pod packet
#define STAT_TTL_EXPIRED 5 // left to the stack, which replies with ICMP Time Exceeded
#define STAT_TOO_BIG     6 // left to the stack, which fragments it or replies with ICMP Frag Needed

// ---------------------------------------------------------------------------
// The helpers the kernel provides
//
// A program cannot call an ordinary library function. It calls one of the helpers the kernel exposes, through
// the instruction "call N", where N is the number the kernel gave that helper.
//
// Each line below declares a pointer to a function and sets it to that number. clang turns a call made
// through a pointer whose value is a constant into "call N", so the pointer is only ever a place to keep the
// number and is never used as an address. Declaring them here is what libbpf's headers do as well, and doing
// it by hand is what lets this file compile without libbpf and without a vmlinux.h.
//
// The declarations read from the inside out. In "long (*bpf_redirect)(__u32, __u64)", bpf_redirect is a
// pointer, because of the star; what it points at is a function, because of the parentheses which follow; and
// that function returns long. The parentheses around the name are required, as "long *bpf_redirect(...)"
// would declare an ordinary function returning a pointer instead.
// ---------------------------------------------------------------------------

// Looks a key up in a map. Returns a pointer to the value, or NULL.
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

// Writes bytes into the packet at the given offset.
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len,
                                   __u64 flags) = (void *)9;

// Updates an IP header checksum for a field which changed, without recomputing the whole header.
static long (*bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to,
                                   __u64 size) = (void *)10;

// Sends the packet out of the given interface.
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)23;

// Asks the kernel routing and neighbor tables where an address is reached.
static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags) = (void *)69;

// ---------------------------------------------------------------------------
// The maps
//
// Creating a map takes five values, and the three definitions below are those five values written out as
// ordinary global variables. Each variable carries two attributes:
//
//   section(".hostdp_maps")  puts it in a section of its own instead of the default one for data
//   used                     keeps the compiler from removing it, as nothing in the C reads it
//
// hack/gen-bpf-objects reads that section at build time, twenty bytes per map, and the loader creates the
// maps from what it read. This is the reason the loader needs no BTF: BTF is the general description of a
// layout, and the layout here is one this repository defines.
//
// The fields are named in the initializers rather than given in order, so that reading a definition does not
// mean counting positions.
// ---------------------------------------------------------------------------

struct hostdp_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

// pod_routes: the remote Pod CIDRs and the transport address of the Node hosting each of them, which is what
// the "remotePodCIDR via peerNodeIP" routes hold.
//
// The shape of the key is the kernel's: a prefix length first, then the bytes to compare. An LPM trie
// compares those bytes one at a time from the front, which is why the address is four separate bytes rather
// than a __u32. On a little endian machine a __u32 holding 10.10.1.0 sits in memory as 00 01 0a 0a, the
// reverse of the order it has on the wire, and a comparison from the front then matches nothing at all and
// reports no error. Four bytes is also what makes this IPv4 only, as IPv6 would need sixteen.
struct pod_route_key {
	__u32 prefixlen;
	__u8 addr[4];
};

struct hostdp_map_def pod_routes __attribute__((section(".hostdp_maps"), used)) = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct pod_route_key),
	.value_size = sizeof(__u32), // the transport address of the peer Node
	.max_entries = 1024,
	.map_flags = BPF_F_NO_PREALLOC, // an LPM trie uses memory for the entries it holds
};

// node_config: the Node-level values the programs need, in network order except the prefix length and the
// MTUs. Written once at startup, and again if an interface changes.
struct hostdp_map_def node_config __attribute__((section(".hostdp_maps"), used)) = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32), // the index
	.value_size = sizeof(__u32),
	.max_entries = 6,
	.map_flags = 0,
};

// stats: the counters.
struct hostdp_map_def stats __attribute__((section(".hostdp_maps"), used)) = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32), // the index
	.value_size = sizeof(__u64),
	.max_entries = 7,
	.map_flags = 0,
};

// ---------------------------------------------------------------------------
// The steps the two programs are built from
//
// Each carries three modifiers. static keeps it out of the symbol table, inline suggests expanding it where
// it is called, and the always_inline attribute makes that mandatory rather than a suggestion.
//
// The last one is what matters. A function which is not expanded is called through a BPF to BPF call, whose
// offset the loader would have to fix up when it loads the program. With every one of them expanded, .text
// is empty, the object holds no such call, and the loader has one less thing to do. hack/gen-bpf-objects
// refuses an object whose .text is not empty, so this cannot regress without being noticed.
// ---------------------------------------------------------------------------

// cfg reads one slot of node_config, and reports 0 for a slot which cannot be read.
static inline __attribute__((always_inline)) __u32 cfg(__u32 slot)
{
	__u32 *v = bpf_map_lookup_elem(&node_config, &slot);
	// The verifier requires the result of every lookup to be checked before it is read.
	if (v == 0)
		return 0;
	return *v;
}

// count adds one to a counter.
static inline __attribute__((always_inline)) void count(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &slot);
	if (v == 0)
		return;
	// The program runs on every CPU at once, so the increment has to be atomic.
	__sync_fetch_and_add(v, 1);
}

// parse_ipv4 reports whether this is a packet the programs handle, and hands out its IPv4 header. It returns
// a negative value for a packet which is the stack's.
static inline __attribute__((always_inline)) int parse_ipv4(struct __sk_buff *skb, struct iphdr **ip_out)
{
	// data and data_end delimit the packet. They are declared as __u32 in __sk_buff but hold addresses, so
	// they go through long on the way to a pointer, which keeps the high half on a 64 bit machine.
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	// eth + 1 is the address just past a whole ethhdr, so this asks whether all 14 bytes are there. The
	// check is not defensive: the verifier rejects a program which reads packet bytes without one.
	if ((void *)(eth + 1) > data_end)
		return -1;
	// h_proto is in network order in the packet. The constant is swapped instead of the field, which costs
	// nothing because the swap of a constant happens at build time.
	if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
		return -1;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return -1;
	// ihl is the header length in units of four bytes, so 5 is the 20 byte header of a packet without
	// options. The offsets used further down assume that length, and a packet with options is the stack's.
	if (ip->ihl != 5)
		return -1;

	*ip_out = ip;
	return 0;
}

// is_local_pod_ip reports whether an address belongs to a Pod of this Node.
//
// The gateway holds an address of the Pod CIDR without being a Pod, and the Node sends traffic from it, so it
// is excluded here rather than in each program. Without that, a packet the Node itself exchanges with a
// remote Pod is handled asymmetrically: hostdp_fwd redirects the request, while the reply is one the Node
// receives rather than forwards, so bpf_fib_lookup refuses it and the host network stack sees that direction
// only. Excluding the address keeps both directions with the stack, which is the property the two programs
// exist to preserve, and it keeps the return misses counting the packets which resolve a neighbor.
static inline __attribute__((always_inline)) int is_local_pod_ip(__u32 addr)
{
	__u32 prefix = cfg(CFG_LOCAL_POD_PREFIX);
	if (prefix == 0 || prefix > 32) // not configured yet
		return 0;
	if (addr == cfg(CFG_GATEWAY_IP))
		return 0;

	// The mask in host order. For a prefix of 24: 32 - 24 is 8, 1 << 8 is 0x100, one less than that is
	// 0x000000ff, and inverting it gives 0xffffff00.
	__u32 host_mask = ~((1u << (32 - prefix)) - 1);
	// The address comes out of the packet in network order, so the mask has to be in that order too.
	__u32 mask = __builtin_bswap32(host_mask);

	return (addr & mask) == (cfg(CFG_LOCAL_POD_NET) & mask);
}

// next_hop_of returns the transport address of the Node hosting the Pod with this address, or 0.
static inline __attribute__((always_inline)) __u32 next_hop_of(__u32 addr)
{
	// A prefix length of 32 asks the trie to match this whole address. What it holds are the shorter
	// prefixes of the Pod CIDRs, and it answers with the longest one which covers the address. The field
	// left out of the initializer is zeroed, and the copy below then fills it.
	struct pod_route_key key = {.prefixlen = 32};
	// The four bytes are copied as they are, with no swap, because the trie compares them in the order the
	// packet has them. __builtin_memcpy is an ordinary memcpy which the compiler turns into stores when the
	// length is a constant, and a program cannot call the library one.
	__builtin_memcpy(key.addr, &addr, 4);

	__u32 *nh = bpf_map_lookup_elem(&pod_routes, &key);
	if (nh == 0)
		return 0;
	return *nh;
}

// dec_ttl decrements the TTL and updates the header checksum, as the stack does when it forwards. It returns
// a negative value when the TTL is spent, which is the stack's to report with an ICMP Time Exceeded.
static inline __attribute__((always_inline)) int dec_ttl(struct __sk_buff *skb, struct iphdr *ip)
{
	__u8 ttl = ip->ttl;
	if (ttl <= 1)
		return -1;
	__u8 new_ttl = ttl - 1;

	// The checksum is computed over the header as 16 bit words, so updating it takes the word which
	// changed, before and after. The TTL is the eighth byte of the header and the protocol the ninth, which
	// puts them in the same word, and only the TTL changes. Both values are in the packet's own byte order.
	__u16 old_word = ((__u16)ttl << 8) | ip->protocol;
	__u16 new_word = ((__u16)new_ttl << 8) | ip->protocol;

	if (bpf_skb_store_bytes(skb, IP_TTL_OFF, &new_ttl, 1, 0) < 0)
		return -1;
	if (bpf_l3_csum_replace(skb, IP_CHECK_OFF, __builtin_bswap16(old_word), __builtin_bswap16(new_word),
	                        2) < 0)
		return -1;
	return 0;
}

// redirect_via reports where a packet has to be sent to reach next_hop and sends it there. The kernel FIB is
// asked for the link layer address and the outgoing interface only: which Node the packet goes to was decided
// from pod_routes above, and BPF_FIB_LOOKUP_DIRECT keeps policy routing out of the answer.
//
// The lookup fails while the neighbor is unresolved, and the packet then goes to the stack, which resolves it
// and forwards this one itself. So a miss is how a neighbor comes to be resolved, and it is also how one is
// kept resolved: the kernel ages an entry it never sees used, and it does not see this datapath use it.
//
// A return of TC_ACT_OK leaves the packet to the stack. Anything else means it has been sent.
static inline __attribute__((always_inline)) int redirect_via(struct __sk_buff *skb, struct iphdr *ip,
                                                              __u32 next_hop, __u32 mtu, __u32 miss_stat)
{
	if (mtu != 0 && skb->len > mtu) {
		// Too big for the outgoing interface. The stack fragments it or reports it to the sender.
		count(STAT_TOO_BIG);
		return TC_ACT_OK;
	}

	// The empty braces zero every field, and the three which are set are the question being asked.
	struct bpf_fib_lookup fib = {0};
	fib.family = AF_INET;
	fib.ipv4_dst = next_hop;
	fib.ifindex = skb->ifindex; // the interface the packet arrived on

	if (bpf_fib_lookup(skb, &fib, sizeof(fib), BPF_FIB_LOOKUP_DIRECT) != BPF_FIB_LKUP_RET_SUCCESS) {
		count(miss_stat);
		return TC_ACT_OK;
	}
	if (dec_ttl(skb, ip) < 0) {
		count(STAT_TTL_EXPIRED);
		return TC_ACT_OK;
	}
	// The first six bytes of the packet are the destination address and the six after them the source.
	if (bpf_skb_store_bytes(skb, 0, fib.dmac, 6, 0) < 0 ||
	    bpf_skb_store_bytes(skb, 6, fib.smac, 6, 0) < 0) {
		count(miss_stat);
		return TC_ACT_OK;
	}
	// A flag of 0 sends the packet out of that interface.
	return bpf_redirect(fib.ifindex, 0);
}

// ---------------------------------------------------------------------------
// The two programs
//
// section("tc") is what marks a function as one of the programs to load, and used keeps the compiler from
// removing it, as nothing in the C calls either of them.
// ---------------------------------------------------------------------------

// hostdp_fwd runs on the gateway interface ingress, where the packets of the local Pods enter the host from
// OVS, before the stack makes a routing decision.
__attribute__((section("tc"), used)) int hostdp_fwd(struct __sk_buff *skb)
{
	struct iphdr *ip;
	if (parse_ipv4(skb, &ip) < 0) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	if (!is_local_pod_ip(ip->saddr)) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	__u32 next_hop = next_hop_of(ip->daddr);
	if (next_hop == 0) {
		// Not bound for a remote Pod. Everything else, a Pod leaving the cluster in particular, is the
		// stack's, which still holds the rules for it.
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	int ret = redirect_via(skb, ip, next_hop, cfg(CFG_TRANSPORT_MTU), STAT_FWD_MISS);
	if (ret != TC_ACT_OK)
		count(STAT_FWD);
	return ret;
}

// hostdp_return runs on the transport interface ingress and sends back what hostdp_fwd sends out, so that a
// connection between two Pods is handled the same way in both directions.
__attribute__((section("tc"), used)) int hostdp_return(struct __sk_buff *skb)
{
	struct iphdr *ip;
	if (parse_ipv4(skb, &ip) < 0) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	// Only what the other direction forwards: a remote Pod's packet to a Pod of this Node. The source is
	// checked so that this stays the counterpart of hostdp_fwd, and so that a packet reaching a Pod from
	// anywhere else keeps being the stack's, along with the rules which apply to it.
	if (!is_local_pod_ip(ip->daddr) || next_hop_of(ip->saddr) == 0) {
		count(STAT_PASS);
		return TC_ACT_OK;
	}
	// The next hop is the Pod itself: the route to the local Pod CIDR through the gateway is a connected
	// one, which the stack keeps whether this datapath runs or not.
	int ret = redirect_via(skb, ip, ip->daddr, cfg(CFG_GATEWAY_MTU), STAT_RETURN_MISS);
	if (ret != TC_ACT_OK)
		count(STAT_RETURN);
	return ret;
}

// bpf_fib_lookup and bpf_redirect are only available to a GPL program, and the kernel reads this to know.
char LICENSE[] __attribute__((section("license"), used)) = "GPL";
