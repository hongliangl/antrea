# eBPF host-network datapath (design, WIP)

## Goal

Replace Antrea's host-network datapath — the iptables/ip route/ip rule/ipset rules programmed by
`pkg/agent/route/route_linux.go` — with a pure eBPF datapath attached with `tc` on the Node's transport and
gateway interfaces, loaded via the `cilium/ebpf` library. OVS and the in-OVS pipeline are unchanged; only the
part of the datapath that today lives in the Linux host network stack (forwarding, NAT, policy routing) moves
to eBPF.

Gated behind the `EBPFHostDataPath` feature gate (Alpha, default off). When off, the existing route client is
used unchanged.

## What the host datapath does today (the replacement surface)

Focusing on noEncap mode (the first target), `route_linux.go` programs:

- **Forwarding (`AddRoutes`)**: for a peer Node on the same subnet, `podCIDR via peerNodeIP` — plain L3
  routing of Pod-to-remote-Pod traffic, next hop = peer transport IP. Local Pod CIDR routes via `antrea-gw0`.
- **NAT (`*nat` postrouting)**: `masquerade Pod to external` (SNAT Pod->external to the Node IP, excluding
  Pod->Pod via `antreaPodIPSet`), Egress mark-based SNAT (`AddSNATRule`), NodePort DNAT, LOCAL/virtual-IP
  masquerade.
- **Policy routing (`*ip rule`)**: Egress `fwmark -> table` steering.
- **conntrack notrack (`*raw`)**: skip conntrack for encap / external-destined packets.
- **ipsets**: `antreaPodIPSet` (all Pod CIDRs), Node IPs, NodePort/externalIP sets — pure classification.

## eBPF mapping

| Host mechanism | eBPF replacement |
|---|---|
| ipset `antreaPodIPSet` (Pod CIDRs) | `pod_cidrs` LPM-trie map |
| Node IP / transport subnet | `node_config` array map |
| `masquerade Pod to external` | tc-egress SNAT + a BPF NAT map (reverse translation on tc-ingress) |
| `podCIDR via peerNodeIP` forwarding | `pod_routes` LPM map (next hop) + tc `bpf_fib_lookup` (L2 only) + `bpf_redirect` |
| Egress fwmark policy routing | tc classification against a per-Egress map |

## Attach model

- `tc` (tcx) on the transport interface (`nodeConfig.NodeTransportInterfaceName`) and the gateway interface.
- transport **egress** hook: classify (src Pod / dst external) via maps; SNAT Pod->external; count.
- transport **ingress** hook: reverse NAT for replies; NodePort DNAT.
- gateway **ingress** hook: forward local-Pod -> remote-Pod to the peer Node (`pod_routes` + redirect).
- Programs + maps loaded and pinned by a `cilium/ebpf` loader in `pkg/agent/hostdp`; maps are populated from
  the same events that drive `route_linux.go` today (Pod CIDR add/delete, Node config).

## Incremental plan

1. **Skeleton (done)**: load a tc program on the transport interface via `cilium/ebpf`, program the
   `pod_cidrs` / `node_config` maps, classify Pod-vs-external traffic and count it, pass everything through
   (`TC_ACT_OK`). Proves the load/attach/generate/map pipeline inside Antrea without changing any forwarding.
2. **Pod->external masquerade (done)**: SNAT + NAT map + reverse on ingress.
3. **noEncap Pod-to-Pod forwarding (done)**: `bpf_fib_lookup` + redirect.
4. Egress steering; NodePort DNAT; policy-routing equivalents.

Each step is gated and independently verifiable; the traditional route client remains the default and the
fallback.

### Step 3: Pod-to-remote-Pod forwarding

The `hostdp_fwd` program replaces the kernel route `remotePodCIDR via peerNodeIP` for noEncap Pod-to-Pod
traffic. It is attached to the **gateway (Pod-facing) interface ingress** — where Pod traffic enters the host
from OVS, before the routing decision — while the masquerade programs stay on the transport interface. For a
local Pod destined to a remote Pod:

1. The L3 next hop comes from the `pod_routes` LPM map (remote Pod CIDR -> peer Node transport IP), our own
   replacement for the removed kernel route. The kernel FIB is **not** consulted for the routing decision.
2. `bpf_fib_lookup` (with the on-link next hop as the destination) is used **only** to resolve the peer Node's
   L2 neighbor (MAC) and output interface — the one thing that legitimately stays the kernel's job (ARP).
3. The Ethernet header is rewritten (dst = peer Node MAC, src = output-interface MAC) and the packet is
   `bpf_redirect`ed to the transport interface's egress. On that egress the masquerade program runs but skips
   it (dst is in `pod_cidrs`), so the Pod source is preserved.

Pod-to-external and Pod-to-local-Pod traffic falls through (`TC_ACT_OK`): external is masqueraded on the
transport egress hook; local delivery uses the retained connected/local-Pod route via the gateway.

**Consequence to be aware of:** once the remote-Pod route lives only in eBPF, the kernel has no reverse path
for return traffic from remote Pods, so `rp_filter` must be off on the eBPF datapath Node (Antrea already
manages `rp_filter` for its datapath). Validated in a two-Node netns testbed (`fwdtest.sh`): Pod<->remote-Pod
TCP + ICMP work purely via the eBPF forward with the source preserved (not masqueraded), while the Node
deliberately has no kernel route to the remote Pod CIDR.
