// Copyright 2026 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package hostdp

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"k8s.io/klog/v2"
)

//go:embed bpf/hostdp_bpfel.o
var bpfObject []byte

// node_config map indices, mirroring hostdp.bpf.c.
const (
	nodeConfigTransportIP    = 0
	nodeConfigSubnetPrefix   = 1
	nodeConfigLocalPodNet    = 2
	nodeConfigLocalPodPrefix = 3
)

// stats map indices, mirroring the constants in hostdp.bpf.c.
var statNames = map[uint32]string{
	0: "snat",
	1: "unsnat",
	2: "passthrough",
	3: "fwd",
	4: "fwd_miss",
	5: "egress_snat",
	6: "nodeport_dnat",
	7: "nodeport_snat",
}

// podCIDRKey mirrors struct pod_cidr_key in hostdp.bpf.c. Addr holds the network-order IPv4 bytes; the LPM
// trie matches them left-to-right, so a byte array (not a uint32) keeps the layout unambiguous.
type podCIDRKey struct {
	PrefixLen uint32
	Addr      [4]byte
}

// npKey mirrors struct np_key in hostdp.bpf.c: {NodePort, proto}, port in network order.
type npKey struct {
	Port  [2]byte
	Proto uint8
	_     uint8
}

// npBackend mirrors struct np_backend in hostdp.bpf.c: backend address + port, both network order.
type npBackend struct {
	Addr [4]byte
	Port [2]byte
	_    [2]byte
}

type loader struct {
	coll        *ebpf.Collection
	links       []link.Link
	podCIDRs    *ebpf.Map
	podRoutes   *ebpf.Map
	nodeConfig  *ebpf.Map
	egressSteer *ebpf.Map
	egressSNAT  *ebpf.Map
	nodePort    *ebpf.Map
	stats       *ebpf.Map
}

// NewLoader returns an eBPF host-datapath control surface.
func NewLoader() Interface {
	return &loader{}
}

func (l *loader) Load(transportIfIndex, gatewayIfIndex int) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock rlimit: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		return fmt.Errorf("failed to load eBPF collection spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to load eBPF collection: %w", err)
	}
	l.coll = coll
	l.podCIDRs = coll.Maps["pod_cidrs"]
	l.podRoutes = coll.Maps["pod_routes"]
	l.nodeConfig = coll.Maps["node_config"]
	l.egressSteer = coll.Maps["egress_steer"]
	l.egressSNAT = coll.Maps["egress_snat"]
	l.nodePort = coll.Maps["nodeport"]
	l.stats = coll.Maps["stats"]
	if l.podCIDRs == nil || l.podRoutes == nil || l.nodeConfig == nil ||
		l.egressSteer == nil || l.egressSNAT == nil || l.nodePort == nil || l.stats == nil {
		l.Close()
		return fmt.Errorf("eBPF object is missing an expected map")
	}

	// Attach with tcx (kernel >= 6.6). tcx links are ordered and don't clobber other tc programs on the
	// interface, unlike the legacy clsact/netlink attach. The masquerade programs live on the transport
	// interface; the Pod-to-remote-Pod forwarding program lives on the gateway (Pod-facing) interface
	// ingress, where Pod traffic enters the host from OVS before the routing decision.
	for _, a := range []struct {
		prog    string
		attach  ebpf.AttachType
		ifIndex int
	}{
		{"hostdp_egress", ebpf.AttachTCXEgress, transportIfIndex},
		{"hostdp_ingress", ebpf.AttachTCXIngress, transportIfIndex},
		{"hostdp_fwd", ebpf.AttachTCXIngress, gatewayIfIndex},
	} {
		prog := coll.Programs[a.prog]
		if prog == nil {
			l.Close()
			return fmt.Errorf("eBPF object is missing program %s", a.prog)
		}
		lnk, err := link.AttachTCX(link.TCXOptions{
			Interface: a.ifIndex,
			Program:   prog,
			Attach:    a.attach,
		})
		if err != nil {
			l.Close()
			return fmt.Errorf("failed to attach %s with tcx: %w", a.prog, err)
		}
		l.links = append(l.links, lnk)
	}
	klog.InfoS("Loaded eBPF host datapath", "transportIfIndex", transportIfIndex, "gatewayIfIndex", gatewayIfIndex)
	return nil
}

func (l *loader) Close() error {
	for _, lnk := range l.links {
		lnk.Close()
	}
	l.links = nil
	if l.coll != nil {
		l.coll.Close()
		l.coll = nil
	}
	return nil
}

func (l *loader) SetNodeConfig(transportIP net.IP, subnetPrefixLen int) error {
	v4 := transportIP.To4()
	if v4 == nil {
		return fmt.Errorf("transport IP %s is not IPv4 (only IPv4 is supported for now)", transportIP)
	}
	// Store the address as a native uint32 of the network-order bytes so the datapath (which reads
	// skb ip->saddr, already network order) compares equal.
	addr := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	if err := l.nodeConfig.Put(uint32(nodeConfigTransportIP), hostToNetU32(addr)); err != nil {
		return err
	}
	return l.nodeConfig.Put(uint32(nodeConfigSubnetPrefix), uint32(subnetPrefixLen))
}

func (l *loader) SetLocalPodCIDR(podCIDR *net.IPNet) error {
	v4 := podCIDR.IP.To4()
	if v4 == nil {
		return fmt.Errorf("local Pod CIDR %s is not IPv4 (only IPv4 is supported for now)", podCIDR)
	}
	ones, _ := podCIDR.Mask.Size()
	addr := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	if err := l.nodeConfig.Put(uint32(nodeConfigLocalPodNet), hostToNetU32(addr)); err != nil {
		return err
	}
	return l.nodeConfig.Put(uint32(nodeConfigLocalPodPrefix), uint32(ones))
}

func (l *loader) AddPodCIDR(podCIDR *net.IPNet) error {
	key, err := podCIDRKeyOf(podCIDR)
	if err != nil {
		return err
	}
	return l.podCIDRs.Put(key, uint8(1))
}

func (l *loader) DeletePodCIDR(podCIDR *net.IPNet) error {
	key, err := podCIDRKeyOf(podCIDR)
	if err != nil {
		return err
	}
	if err := l.podCIDRs.Delete(key); err != nil && !isKeyNotExist(err) {
		return err
	}
	return nil
}

func (l *loader) SetPodRoute(podCIDR *net.IPNet, nextHop net.IP) error {
	key, err := podCIDRKeyOf(podCIDR)
	if err != nil {
		return err
	}
	v4 := nextHop.To4()
	if v4 == nil {
		return fmt.Errorf("next hop %s is not IPv4 (only IPv4 is supported for now)", nextHop)
	}
	addr := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	return l.podRoutes.Put(key, hostToNetU32(addr))
}

func (l *loader) DeletePodRoute(podCIDR *net.IPNet) error {
	key, err := podCIDRKeyOf(podCIDR)
	if err != nil {
		return err
	}
	if err := l.podRoutes.Delete(key); err != nil && !isKeyNotExist(err) {
		return err
	}
	return nil
}

func (l *loader) AddEgressSteer(podIP, egressNodeIP net.IP) error {
	pod, err := ipv4Bytes(podIP)
	if err != nil {
		return err
	}
	nh, err := ipv4Bytes(egressNodeIP)
	if err != nil {
		return err
	}
	return l.egressSteer.Put(pod, nh)
}

func (l *loader) DeleteEgressSteer(podIP net.IP) error {
	pod, err := ipv4Bytes(podIP)
	if err != nil {
		return err
	}
	if err := l.egressSteer.Delete(pod); err != nil && !isKeyNotExist(err) {
		return err
	}
	return nil
}

func (l *loader) AddEgressSNAT(podIP, egressIP net.IP) error {
	pod, err := ipv4Bytes(podIP)
	if err != nil {
		return err
	}
	eip, err := ipv4Bytes(egressIP)
	if err != nil {
		return err
	}
	return l.egressSNAT.Put(pod, eip)
}

func (l *loader) DeleteEgressSNAT(podIP net.IP) error {
	pod, err := ipv4Bytes(podIP)
	if err != nil {
		return err
	}
	if err := l.egressSNAT.Delete(pod); err != nil && !isKeyNotExist(err) {
		return err
	}
	return nil
}

func (l *loader) AddNodePort(protocol uint8, port uint16, backendIP net.IP, backendPort uint16) error {
	baddr, err := ipv4Bytes(backendIP)
	if err != nil {
		return err
	}
	key := npKey{Proto: protocol}
	binary.BigEndian.PutUint16(key.Port[:], port)
	val := npBackend{Addr: baddr}
	binary.BigEndian.PutUint16(val.Port[:], backendPort)
	return l.nodePort.Put(key, val)
}

func (l *loader) DeleteNodePort(protocol uint8, port uint16) error {
	key := npKey{Proto: protocol}
	binary.BigEndian.PutUint16(key.Port[:], port)
	if err := l.nodePort.Delete(key); err != nil && !isKeyNotExist(err) {
		return err
	}
	return nil
}

func (l *loader) Stats() (map[string]uint64, error) {
	out := make(map[string]uint64, len(statNames))
	for idx, name := range statNames {
		var v uint64
		if err := l.stats.Lookup(idx, &v); err != nil {
			return nil, err
		}
		out[name] = v
	}
	return out, nil
}

// ipv4Bytes returns the network-order bytes of an IPv4 address, matching the datapath's __u32 map keys/values
// (which are raw addresses read from packet headers).
func ipv4Bytes(ip net.IP) ([4]byte, error) {
	var out [4]byte
	v4 := ip.To4()
	if v4 == nil {
		return out, fmt.Errorf("address %s is not IPv4 (only IPv4 is supported for now)", ip)
	}
	copy(out[:], v4)
	return out, nil
}

func podCIDRKeyOf(podCIDR *net.IPNet) (podCIDRKey, error) {
	v4 := podCIDR.IP.To4()
	if v4 == nil {
		return podCIDRKey{}, fmt.Errorf("Pod CIDR %s is not IPv4 (only IPv4 is supported for now)", podCIDR)
	}
	ones, _ := podCIDR.Mask.Size()
	key := podCIDRKey{PrefixLen: uint32(ones)}
	copy(key.Addr[:], v4)
	return key, nil
}

// hostToNetU32 returns v with its bytes in the same order the datapath sees a network-order __be32: cilium/ebpf
// serializes a uint32 in host (little-endian) order, so we byte-swap to store the network-order bytes.
func hostToNetU32(v uint32) uint32 {
	return v>>24 | (v>>8)&0xff00 | (v<<8)&0xff0000 | v<<24
}

func isKeyNotExist(err error) bool {
	return err != nil && (err == ebpf.ErrKeyNotExist)
}
