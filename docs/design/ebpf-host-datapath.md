# eBPF Host Network Datapath

## Status

Alpha, behind the `EBPFHostDataPath` feature gate, off by default. What is implemented is the forwarding of
the traffic between the Pods of two Nodes, and nothing else. This document describes what it does, what it
deliberately leaves alone, and what is known to be missing.

## What it replaces

In noEncap and hybrid modes, a packet from a local Pod to a remote Pod leaves OVS through the Antrea gateway,
goes through the host network stack, and is forwarded by the route the route client installs:

```text
remotePodCIDR via peerNodeIP dev <transport interface>
```

Two eBPF programs do that forwarding before the stack does:

| Program | Hook | What it forwards |
| --- | --- | --- |
| `hostdp_fwd` | gateway, ingress | a local Pod's packet bound for a remote Pod CIDR, to the transport interface |
| `hostdp_return` | transport, ingress | a remote Pod's packet bound for a local Pod, to the gateway interface |

The path becomes this, where the boxes the packet no longer enters are the routing decision and netfilter:

```text
Pod -> OVS -> antrea-gw0 -> [tc ingress: hostdp_fwd] -> eth0 -> peer Node
                                  (routing and netfilter are skipped)
```

The decision of which Node a packet goes to is made from the `pod_routes` map, which mirrors the routes above.
The kernel FIB is consulted only for the link layer address of the next hop and the interface to send on.

## What it deliberately does not replace

Everything else the Agent programs in the host network stack stays where it is: the masquerade of the traffic
leaving the cluster, Egress, Service handling including NodePort, and the Node network policies.

The reason is that all of those need connection state. Moving them means reimplementing the part of conntrack
they rely on, and the parts which are easy to leave out are the ones which are only missed once a cluster is
under load:

- Timeouts and TCP state tracking. An LRU map evicts the least recently used entry, not the entry whose
  connection ended. An idle long lived connection is evicted when short lived ones fill the map, and its
  replies then find no entry.
- The translation of the ICMP errors which carry the original header. Without it, path MTU discovery is
  broken for every translated flow, which shows up as small packets working and large transfers hanging.
- Fragments. Only the first fragment carries the L4 header, so the others cannot be matched to a flow.
- Port allocation on collision. The kernel searches the whole range; a simple implementation scans a few
  candidates and fails beyond that.
- The operator tooling. `conntrack -L` shows nothing, so an equivalent has to be built.

Forwarding needs none of this, which is why it is the part that was implemented.

## Everything falls back to the host network stack

The routes this replaces are still installed. Whenever the programs cannot handle a packet they return
`TC_ACT_OK`, and the stack forwards it exactly as it does without them. That is true of:

- a packet which is not a cross-Node Pod packet, which includes all the traffic leaving the cluster;
- a packet with IP options, which the parser does not handle;
- a packet too big for the outgoing interface, which the stack fragments or reports to the sender;
- a packet whose TTL is spent, which the stack reports with an ICMP Time Exceeded;
- a packet whose next hop is not resolved yet.

So enabling the feature changes how a packet is forwarded, never whether it is. Failing to load the programs
is logged and does not stop the Agent.

### The fallback is also what keeps the datapath working

This is the least obvious property of the design and the easiest one to break.

`bpf_fib_lookup` returns the link layer address of the next hop only once the neighbor is resolved. The
programs never send an ARP request, and they never will: generating one in eBPF is possible but pointless
while the kernel is right there. The kernel resolves a neighbor when it forwards a packet to it itself, which
is what the fallback makes it do. The first packet of a flow to a new peer therefore goes through the stack,
and the ones after it go through the programs.

The same applies to keeping a neighbor resolved. The kernel moves an entry it has not seen used to a stale
state and eventually reclaims it, and a redirect does not count as a use. So a neighbor entry is refreshed
only by the packets which fall back.

The practical consequence is that the forward misses counter is expected to grow slowly. A counter which
stays at exactly zero for a long time means the kernel has not refreshed those entries, which is the state to
worry about, not the other way round.

## What changes on a Node once it is enabled

Both of these follow from the packets no longer going through the host network stack, and both are visible to
an operator.

**Rules in the netfilter `FORWARD` chain no longer apply to the traffic between the Pods of two Nodes.** A
Node which restricts that traffic there has to restrict it elsewhere. Antrea's own rules are not affected: the
ones it installs there accept that traffic unconditionally, and they were checked for this.

**The connections do not appear in conntrack.** `conntrack -L` does not list them, and the counters of the
iptables rules they used to traverse do not move. Reading those counters to tell whether traffic is flowing
gives the wrong answer, and the `Stats` of the datapath is what replaces them.

### What counts as a Pod

The programs tell a Pod from anything else by the local Pod CIDR and the remote ones, and two addresses need
saying out loud because they sit close to that line.

The gateway holds an address of the local Pod CIDR without being a Pod, and the Node sends traffic from it.
It is excluded, so a packet from or to it stays with the host network stack in both directions. Without the
exclusion only one of the two directions leaves the stack: the request is redirected, while the reply is one
the Node receives rather than forwards, so `bpf_fib_lookup` refuses it. That is the asymmetry the two
programs exist to avoid, and it also puts packets which can never be forwarded into the return misses, which
are meant to count the ones which resolve a neighbor.

A Node whose transport address is inside the local Pod CIDR is refused when the datapath loads. Nothing in
the programs could tell that address from a Pod's, so the Node's own traffic, and the traffic of every host
network Pod with it, would be forwarded as a Pod's.

## Why both directions

Only the request direction has to be redirected for the forwarding to work. Both are redirected so that a
connection is either seen by the host network stack in both directions or in neither.

Redirecting only the request leaves conntrack with a reply and no request, so it records the reply as a new
connection. A Node whose `FORWARD` policy is to drop with an exception for established connections then drops
the replies. That configuration is not hypothetical: it is the one the host network rules Antrea installs
exist for.

Handling both directions also means the acceleration applies to both, which matters because the bulk of a
download is in the reply direction.

## Loading without an eBPF library

The programs are loaded without cilium/ebpf or libbpf. The Agent binary carries no eBPF library, which was
verified: `go list -deps ./cmd/antrea-agent | grep cilium` returns nothing.

The work a library does is split between build time and run time:

```text
build time                                          run time
----------                                          --------
bpf/hostdp.bpf.c                                    objects_linux.go
      | clang                                             | bpf() syscalls
      v                                                   v
   hostdp.o  --> hack/gen-bpf-objects --> objects_linux.go --> maps, programs, attachment
```

`hack/gen-bpf-objects` reads the object clang produced with `debug/elf` and writes out three things: the
instructions of each program, the map definitions, and the list of instructions holding a map reference. At
run time the loader creates the maps, writes each map's file descriptor into the instructions which refer to
it, hands them to the kernel and attaches them. There is no ELF parsing and no relocation logic on the Node.

Two things make this small enough to be worth doing.

**BTF is not needed.** Reading map definitions out of BTF is most of what a general purpose loader does. The C
file writes them into a section of its own instead, as a plain structure this repository defines, so the
generator reads a layout it owns rather than a general one.

**There are no BPF to BPF calls.** Every helper in the C file is inlined, so `.text` is empty and no call
offsets have to be fixed up. The generator refuses an object where `.text` is not empty rather than producing
a program with a dangling call, so this cannot regress silently.

The generated file is committed, so the normal build needs neither clang nor the generator. `make bpf-objects`
regenerates it, and `TestObjectsMatchSource` compares the hash of the C file with the one recorded in the
generated file, so changing one without the other fails a test instead of silently loading older
instructions.

### What was given up by not using a library

The verifier reports a rejection by instruction index. A library uses the line information clang emits to
translate that into a source line. Here the log is printed as the kernel gives it, and the instruction has to
be looked up against the compiled program. This is acceptable during development and is the thing to improve
first if a program is ever rejected on a customer kernel. The generator already reads the object at build
time, so the line table can be emitted alongside the instructions without any run time cost.

## Attaching, and kernel versions

| Kernel | Mechanism | Lifetime |
| --- | --- | --- |
| 6.6 and later | BPF link | the kernel detaches when the descriptor is closed |
| 4.18 to 6.5 | clsact qdisc and a traffic control filter | outlives the process |

The link is tried first and the filter is used when the kernel does not know the command. Both are needed:
Photon OS 5 runs a 6.1, and it is a target platform.

The filter outliving the process is the reason the Agent removes any filter of its own, recognized by name
and priority, both when it starts and when it stops. Without that, a filter added by a previous Agent keeps
running instructions from whatever version it was built from, and nothing in the process shows it.

Note the asymmetry: the link is cleaner but does not survive an Agent restart, so the datapath is absent for
the few seconds a restart takes. That is harmless here only because the routes are still installed.

## Maps

| Map | Type | Entries | Contents |
| --- | --- | --- | --- |
| `pod_routes` | LPM trie | 1024 | remote Pod CIDR to the transport address of the Node hosting it |
| `node_config` | array | 6 | the local Pod CIDR and prefix length, the two MTUs, the gateway interface index and address |
| `stats` | array | 7 | the counters |

An LPM trie is not preallocated, so it uses memory for the entries it holds, which is a few dozen per Node.
The two arrays are a few hundred bytes. Total resident memory is under half a megabyte, which matters because
the kernel charges the memory of a map to the cgroup of the process which created it, and it therefore counts
against the Agent's memory limit. For comparison, the three conntrack maps of an implementation which also
did NAT would be preallocated and would add about ten megabytes at startup.

Addresses are stored as the four bytes they have on the wire. The programs read them out of the packet and
never swap them, so the Go side writes them in the same order. This is not cosmetic for the LPM trie: it
compares a prefix byte by byte from the front, so storing an address the other way round matches nothing and
reports no error.

## Testing

Unit tests in `pkg/agent/hostdp/objects_linux_test.go` cover what the loader assumes about the generated
objects, the relocation, the key encodings and the inert behaviour before `Load`.

`/home/ubuntu/hostdp-validate/fwdtest.sh` builds a two Node topology in network namespaces:

```text
pod-ns            nodeA-ns                          nodeB-ns              rpod-ns
pod0 ------------ gwA            ethA --------- ethB           gwB ------ rpod0
10.10.0.5/24      10.10.0.1/24   192.168.50.1   192.168.50.2   10.10.1.1  10.10.1.5/24
```

The first Node deliberately has no route to the remote Pod CIDR, so a packet reaching the remote Pod proves
the programs forwarded it. It checks that the Pod is unreachable before the datapath loads, that ICMP and TCP
both complete afterwards, that the reply arrives with its TTL decremented by both Nodes, and that an oversized
packet is left to the stack. The neighbor is preresolved in that topology because the fallback which resolves
it in a real cluster cannot work without the route.

Two notes for anyone extending it. The Node must be its own network namespace and not the root one, because
the development host's own forwarding rules silently drop traffic between veth pairs in the root namespace.
And BPF maps are not scoped to a network namespace, so two instances produce two maps with the same name and
`bpftool map dump name stats` picks one of them arbitrarily.

## Known gaps

These are known and not implemented. None of them causes a packet to be lost, because of the fallback, but
several of them fail silently, which is why they are listed rather than left to be discovered.

1. **No reattachment when an interface changes.** The programs are attached once. If the gateway or the
   transport interface is deleted and recreated, the index changes, the link disappears and the programs stop
   running. Traffic falls back to the host network stack and nothing reports it. This needs either a
   subscription to interface events or a periodic check that the attachment is still there.
2. **The MTUs are read once.** They are written into `node_config` at load time. Changing an interface MTU
   afterwards leaves the map holding the old value. The size check then uses the wrong number, although
   `bpf_fib_lookup` performs its own check and catches the case, which was observed in testing.
3. **No neighbor refresh.** Covered above. An entry which goes stale is only refreshed by a packet which
   falls back. A deliberate periodic fallback, or a probe from the Go side, would make this a property rather
   than a side effect.
4. **IPv6 is not supported.** The programs handle IPv4 only, and the loader refuses anything else.
5. **IP options are not parsed.** A packet with `ihl != 5` goes to the stack.
6. **No metrics.** The counters are readable through the `Stats` method but are not exported to Prometheus,
   which is where an operator would look for them.
7. **Enabling the gate on only one side of the cluster is fine, but enabling it in the wrong mode is only
   caught at startup.** The packets on the wire are unchanged, so a Node running this and a Node not running
   it interoperate, and the feature can be rolled out one Node at a time. The traffic encapsulation mode is
   validated when the datapath loads, and a mode which does not route between Nodes is refused there.

## Open questions

These are the points worth deciding before this goes any further, in the order they matter.

**Is the performance worth it?** The datapath saves a routing lookup and a traversal of netfilter per packet
in each direction. Nobody has measured what that is worth on a real Node. In noEncap the expensive work is in
OVS, and the host stack segment is short. This should be measured in shadow mode before anything else is
built on top, and the answer decides whether the rest of this list is worth answering. If the gain does not
justify the maintenance, the programs can be removed and nothing else has to be undone, because nothing was
taken away from the host stack.

**Should there be an observation only mode?** A mode where the programs compute the forwarding decision,
record it, and always return `TC_ACT_OK` would validate the map contents and the controller mirroring against
real traffic at no risk. It is a small change and it is the cheapest way to gain confidence in the parts most
likely to be wrong, which are the control plane ones rather than the packet handling.

**How far should this go?** Extending it to the traffic leaving the cluster means implementing conntrack, and
the list at the top of this document is what that costs. The alternative is to stop here and treat the host
stack as the owner of everything stateful. That is a product decision, not a technical one.

**Is the loader the right trade?** It is about 800 lines including the generator, against a dependency on a
library which does the same and more. The loss is the verifier line mapping, which can be recovered at build
time. The gain is no eBPF library in the Agent binary.
