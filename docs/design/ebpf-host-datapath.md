# eBPF Host Network Datapath

## Table of Contents

<!-- toc -->
- [Packet path](#packet-path)
- [Kernel fallback](#kernel-fallback)
- [Neighbor refresh](#neighbor-refresh)
- [Build and loading](#build-and-loading)
- [Counters and limits](#counters-and-limits)
- [Limitations](#limitations)
<!-- /toc -->

The `EBPFHostDataPath` feature gate enables cross-Node Pod TCP/UDP forwarding with eBPF.
It is Alpha and disabled by default. It supports IPv4, IPv6 and dual-stack Nodes in
noEncap and hybrid modes. Only traffic that uses direct routing to the peer Node is
accelerated. In hybrid mode, traffic between Nodes in the same transport subnet is
accelerated; traffic between Nodes in different transport subnets keeps using tunnels.

## Packet path

Normally, OVS sends a remote Pod packet through `antrea-gw0`, then the host network
stack routes it to the peer Node. The eBPF programs redirect it between interfaces,
skipping host IP forwarding and netfilter:

```text
Outbound: Pod -> OVS -> antrea-gw0 ingress -> hostdp_fwd -> transport interface -> peer Node
Inbound:  peer Node -> transport ingress -> hostdp_return -> antrea-gw0 -> OVS -> Pod
```

Both directions are handled to avoid having only one direction of a connection pass
through host conntrack. OVS still handles Pod networking, Service translation and
Antrea NetworkPolicy. This feature adds no NAT or connection tracking in eBPF.

The Node route controller copies remote Pod CIDRs and peer Node IPs into the
`pod_routes` and `pod_routes6` BPF maps only when `NeedsDirectRoutingToPeer` is true.
Peers reached through tunnels are excluded from both maps. For each matching packet,
the program:

1. Finds the peer Node IP in the route map, or selects the local Pod IP for inbound traffic.
2. Calls `bpf_fib_lookup` to get the output interface and MAC addresses from the kernel's
   routing and neighbor tables.
3. Decrements IPv4 TTL or IPv6 Hop Limit, updates the IPv4 header checksum, rewrites the
   Ethernet addresses and redirects the packet.

Pod addresses are identified by Pod CIDRs. The local gateway IP is excluded so that
Node-originated traffic keeps using the host stack. Loading fails if the Node's own
transport IP falls inside its local Pod CIDR.

## Kernel fallback

Antrea continues to install the normal kernel routes. A program returns `TC_ACT_OK`
to let the host stack handle traffic it cannot accelerate, including:

- ICMP, ICMPv6, SCTP and other protocols outside TCP/UDP.
- IPv4 options, IPv6 extension headers, IPv6 fragments and IPv6 jumbograms.
- Missing route-map entries or unresolved neighbors.
- Expired TTL or Hop Limit, and packets that need kernel MTU handling.

GRO aggregates can be redirected while preserving their segmentation metadata.
Ordinary oversized packets fall back to the stack. Aggregates also fall back when
the outgoing MTU is smaller than the incoming MTU, or the incoming MTU is unknown.

Failure to load the programs is logged; the Antrea Agent continues using the host stack.
Accelerated packets are redirected at TC ingress before reaching the host's
netfilter `FORWARD` hook, so iptables/nftables rules at that hook do not apply to them.

## Neighbor refresh

A successful `bpf_fib_lookup` can return a cached MAC even when the neighbor is
`STALE`. Redirecting traffic does not trigger normal kernel neighbor probing, so
lookup failures alone cannot keep MAC addresses fresh.

The Antrea Agent registers peer Node IPs on the transport interface and local Pod IPs on
`antrea-gw0` with `NTF_EXT_MANAGED` and `NTF_EXT_LEARNED`. The kernel then resolves
and refreshes these entries using ARP for IPv4 and NDP for IPv6. Existing
`PERMANENT` and `NOARP` entries are left unchanged.

Redirects start disabled. The first successful neighbor reconciliation enables them;
a later reconciliation error pauses them until reconciliation succeeds again.
Node route changes and CNI Pod updates trigger reconciliation. A 30-second check
also reads local Pod addresses from the interface store and repairs registrations.
The kernel runs the probes; the Antrea Agent does not send ARP or NDP probes itself.

A runtime check verifies managed-neighbor support for each enabled address family
before attaching the programs. This requires Linux 5.16 or a kernel with the feature
backported. If the check fails, traffic stays on the host stack.

## Build and loading

The implementation has three parts: C programs process packets, the Go client manages
their maps and lifecycle, and a build-time generator embeds the compiled programs in Go.

```text
pkg/agent/ebpf/
  bpf/                C datapath programs and map definitions
  internal/objects/   Generated Go instructions and map metadata
  internal/bpf/       Linux BPF syscalls and TC attachment
  *.go                Go client: Node configuration, route maps and managed neighbors

hack/gen-bpf-objects/  Build-time ELF-to-Go generator
```

```text
C source --clang--> ELF object --Go generator--> Generated Go data
                                                    |
                                              Antrea Agent build
                                                    |
                                              Antrea Agent binary
                                                    |
                                              Initialization
                                                    |
                                          Kernel maps + TC programs
```

When changing the datapath:

1. Edit the C source, then run `make bpf-objects`. This uses Docker to compile with
   clang 18 and regenerate the program instructions, map metadata and map references.
   It runs natively on amd64 and arm64 Linux containers, including on macOS hosts;
   no host clang or Go installation is needed for this step.
2. If a map's key or value layout changes, update the corresponding Go layout and
   map access code as well. Field sizes, padding and byte order must match C.
3. Include the regenerated Go data with the source changes, then rebuild the Antrea Agent.
   Generated files should not be edited directly. Changes only to the Go client do
   not require regenerating the BPF objects.

Normal Antrea Agent builds use the committed Go data and need neither clang nor an eBPF library.
CI uses the same Docker build to check that the committed BPF objects are up to date.

At initialization, the Antrea Agent creates maps, writes Node configuration and loads the programs.
It tries BPF link attachment first and falls back to a clsact TC filter.
BPF links detach when their descriptors close. TC filters can survive an Antrea Agent crash;
the Antrea Agent replaces its filters on startup and removes its attachments on shutdown.
The 30-second check restores missing program attachments on the original interfaces.
Missing or replaced interfaces are logged as errors. Interface indices and MTUs are fixed at initialization.

## Counters and limits

`antrea_agent_ebpf_packets_total` exports these results:

- `host_dp_forwarded`: redirect requested toward a peer Node.
- `host_dp_returned`: redirect requested toward OVS through `antrea-gw0`.
- `host_dp_forward_miss`: outbound lookup or packet rewrite failed; traffic falls back to the host stack.
- `host_dp_return_miss`: inbound lookup or packet rewrite failed; traffic falls back to the host stack.
- `host_dp_passed`: packet is outside the acceleration scope.
- `host_dp_ttl_expired`: TTL or Hop Limit exhausted, or the IPv4 TTL/checksum update failed.
- `host_dp_too_big`: packet falls back to the host stack for MTU handling.

Redirect counters record attempts, not confirmed delivery. Miss counters do not
distinguish lookup failures from packet rewrite failures.

Each route map holds up to 1024 CIDR entries. IPv4 and IPv6 use separate maps;
both families share one Node configuration structure and one set of counters. Route keys store IP bytes in
network order for longest-prefix matching.

## Limitations

- NodePortLocal or hostPort connections that preserve a directly routed remote Pod's
  source IP (for example, noEncap with `noSNAT: true`) are not supported. Backend
  replies can bypass host reverse NAT and break the connection, for both IPv4 and IPv6.
- Interface replacement or MTU changes require restarting the Antrea Agent.
- CNI Pod updates trigger registration or release after updating the interface store;
  the periodic check repairs any missed updates.
- Neighbor flag ownership is tracked only in memory. An Antrea Agent crash can leave managed
  registrations behind; cleanup of orphaned registrations across restarts is not implemented.
- Neighbor recovery time depends on kernel settings and peer reachability.
- Verifier errors report instruction indices without mapping them back to C source lines.
