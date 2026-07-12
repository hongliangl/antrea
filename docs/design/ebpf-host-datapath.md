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
| Egress fwmark policy routing (source Node) | `egress_steer` map: member Pod IP -> Egress Node; forward untouched |
| Egress member ipset + mark SNAT (Egress Node) | `egress_snat` map: member Pod IP -> Egress IP; tc-egress SNAT |
| NodePort DNAT | `nodeport` map + tc-ingress DNAT (address + port) + `np_ct` reverse map |

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
4. **Egress steering + Egress-IP SNAT + NodePort DNAT (done)**: see below.
5. **Agent wiring (done for forwarding + masquerade)**: with the gate on, the agent loads the programs on
   the transport and gateway interfaces at startup, seeds `node_config` / the local Pod CIDR, and the
   NodeRouteController mirrors peer Pod CIDRs into `pod_cidrs` (always) and `pod_routes` (when the peer is
   directly routable) alongside the traditional route client. The route client keeps running: the kernel
   rules remain as a fallback, and eBPF takes over where it runs first (forwarding intercepts on gateway
   ingress before the kernel route; the iptables masquerade still wins on the SNAT path until it is removed).
   Egress/NodePort controller wiring and masquerade hardening (port re-allocation on collision, IPv6, IP
   options) are follow-ups.

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

### Step 4: Egress and NodePort

**Egress** replaces the tunnel-free Egress host machinery (fwmark policy routing on the source Node; member
ipset + mark-based SNAT on the Egress Node) with two maps:

- On a member Pod's Node, `egress_steer` (member Pod IP -> Egress Node transport IP) is consulted in
  `hostdp_fwd` for external-bound traffic: the packet is forwarded to the Egress Node **untouched** (the
  masquerade program also checks the map and skips these flows).
- On the Egress Node, `egress_snat` (member Pod IP -> Egress IP, local and remote members) is consulted on
  transport egress: the source is SNAT'd to the Egress IP, with the reverse entry recorded in the same
  `nat_ct` map the masquerade uses (`nat_ct` is keyed by the SNAT'd address, so one un-SNAT lookup on
  ingress serves both the Node IP and any number of Egress IPs). When the restored destination is a remote
  member Pod, the reply is forwarded straight back to the member's Node from the ingress hook
  (`fwd_if_remote_pod`).

**NodePort** DNAT lives on transport ingress: `nodeport` maps {port, proto} to a backend, and the packet's
destination address *and* port are rewritten (the only port-rewriting translation in the datapath). A
`np_ct` reverse entry lets transport egress restore `nodeIP:nodePort` as the source of the backend's
replies. The client address is not SNAT'd (externalTrafficPolicy=Local semantics); a remote backend is
reached via `fwd_if_remote_pod`.

Validated in netns testbeds: `egresstest.sh` (4 namespaces, member Pod on Node A, Egress Node B owning the
Egress IP on its wan interface — the external server sees the Egress IP, replies round-trip, no Node
masquerades the steered traffic) and the NodePort cases in `nstest.sh` (DNAT + reply un-DNAT with port
translation, real client IP preserved).
