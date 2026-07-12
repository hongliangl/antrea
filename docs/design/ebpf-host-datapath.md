# eBPF host-network datapath (design, WIP)

## Goal

Replace Antrea's host-network datapath — the iptables/ip route/ip rule/ipset rules programmed by
`pkg/agent/route/route_linux.go` — with a pure eBPF datapath attached with `tc` on the Node's transport
interface, loaded via the `cilium/ebpf` library. OVS and the in-OVS pipeline are unchanged; only the part of
the datapath that today lives in the Linux host network stack (forwarding, NAT, policy routing) moves to eBPF.

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
| `podCIDR via peerNodeIP` forwarding | tc `bpf_fib_lookup` + `bpf_redirect` (or leave to the FIB initially) |
| Egress fwmark policy routing | tc classification against a per-Egress map |

## Attach model

- `tc` clsact qdisc on the transport interface (`nodeConfig.NodeTransportInterfaceName`).
- **egress** hook: classify (src Pod / dst external) via maps; SNAT Pod->external; count.
- **ingress** hook: reverse NAT for replies; NodePort DNAT.
- Programs + maps loaded and pinned by a `cilium/ebpf` loader in `pkg/agent/hostdp`; maps are populated from
  the same events that drive `route_linux.go` today (Pod CIDR add/delete, Node config).

## Incremental plan

1. **Skeleton (this change)**: load a tc program on the transport interface via `cilium/ebpf`, program the
   `pod_cidrs` / `node_config` maps, classify Pod-vs-external traffic and count it, pass everything through
   (`TC_ACT_OK`). Proves the load/attach/generate/map pipeline inside Antrea without changing any forwarding.
2. Pod->external masquerade (SNAT + NAT map + reverse on ingress).
3. noEncap Pod-to-Pod forwarding (`bpf_fib_lookup` + redirect).
4. Egress steering; NodePort DNAT; policy-routing equivalents.

Each step is gated and independently verifiable; the traditional route client remains the default and the
fallback.
