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
}

// podCIDRKey mirrors struct pod_cidr_key in hostdp.bpf.c. Addr holds the network-order IPv4 bytes; the LPM
// trie matches them left-to-right, so a byte array (not a uint32) keeps the layout unambiguous.
type podCIDRKey struct {
	PrefixLen uint32
	Addr      [4]byte
}

type loader struct {
	coll       *ebpf.Collection
	links      []link.Link
	podCIDRs   *ebpf.Map
	nodeConfig *ebpf.Map
	stats      *ebpf.Map
}

// NewLoader returns an eBPF host-datapath control surface.
func NewLoader() Interface {
	return &loader{}
}

func (l *loader) Load(transportIfIndex int) error {
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
	l.nodeConfig = coll.Maps["node_config"]
	l.stats = coll.Maps["stats"]
	if l.podCIDRs == nil || l.nodeConfig == nil || l.stats == nil {
		l.Close()
		return fmt.Errorf("eBPF object is missing an expected map")
	}

	// Attach both directions with tcx (kernel >= 6.6). tcx links are ordered and don't clobber other tc
	// programs on the interface, unlike the legacy clsact/netlink attach.
	for _, a := range []struct {
		prog   string
		attach ebpf.AttachType
	}{
		{"hostdp_egress", ebpf.AttachTCXEgress},
		{"hostdp_ingress", ebpf.AttachTCXIngress},
	} {
		prog := coll.Programs[a.prog]
		if prog == nil {
			l.Close()
			return fmt.Errorf("eBPF object is missing program %s", a.prog)
		}
		lnk, err := link.AttachTCX(link.TCXOptions{
			Interface: transportIfIndex,
			Program:   prog,
			Attach:    a.attach,
		})
		if err != nil {
			l.Close()
			return fmt.Errorf("failed to attach %s with tcx: %w", a.prog, err)
		}
		l.links = append(l.links, lnk)
	}
	klog.InfoS("Loaded eBPF host datapath", "transportIfIndex", transportIfIndex)
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
