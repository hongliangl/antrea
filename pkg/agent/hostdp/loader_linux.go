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
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

// instructionSize is the size of an eBPF instruction. A wide one, which is what holds a map reference, takes
// two of those, and its immediate is the first four bytes after the opcode and the registers.
const instructionSize = 8

// opcodeLoadImm64 is the opcode of the wide instruction loading a 64 bit immediate, which is the only one a
// map relocation applies to. pseudoMapFD in its source register is what tells the kernel that the immediate
// is the descriptor of a map rather than a value.
const (
	opcodeLoadImm64 = 0x18
	pseudoMapFD     = 1
)

// The slots of the node_config and stats maps, which must match the ones bpf/hostdp.bpf.c defines.
const (
	cfgLocalPodNet uint32 = iota
	cfgLocalPodPrefix
	cfgTransportMTU
	cfgGatewayMTU
	cfgGatewayIfIndex
	cfgGatewayIP
)

const (
	statFwd uint32 = iota
	statFwdMiss
	statReturn
	statReturnMiss
	statPass
	statTTLExpired
	statTooBig
	statCount
)

// The names the programs are attached under, which must match the ones bpf/hostdp.bpf.c defines.
const (
	programFwd    = "hostdp_fwd"
	programReturn = "hostdp_return"
)

const (
	mapPodRoutes  = "pod_routes"
	mapNodeConfig = "node_config"
	mapStats      = "stats"
)

// podRouteKey is the key of the pod_routes map, which must match struct pod_route_key. The address is kept
// as bytes in network order, which is the order an LPM trie compares a prefix in.
type podRouteKey struct {
	prefixLen uint32
	addr      [4]byte
}

type loader struct {
	// mutex serializes the map writes, which come from the Node route controller, with Load and Close.
	mutex sync.Mutex
	// mapFDs and programFDs are indexed by name, and are empty until Load succeeds.
	mapFDs      map[string]int
	programFDs  map[string]int
	attachments []*attachment
	loaded      bool
}

// NewLoader returns an eBPF host datapath which does nothing until Load is called.
func NewLoader() Interface {
	return &loader{
		mapFDs:     make(map[string]int),
		programFDs: make(map[string]int),
	}
}

func (l *loader) Load(config Config) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.loaded {
		return fmt.Errorf("the eBPF host datapath is already loaded")
	}
	if err := validate(config); err != nil {
		return err
	}
	// A kernel older than 5.11 accounts the memory of the maps against the locked memory limit rather
	// than against the cgroup of the process, and the default limit is far below what they need.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}); err != nil {
		klog.V(2).InfoS("Could not raise the locked memory limit, which a kernel 5.11 or later ignores anyway", "err", err)
	}

	if err := l.loadLocked(config); err != nil {
		// Leave nothing half attached behind: what was done so far is undone, and the Node keeps
		// forwarding through the host stack.
		l.closeLocked()
		return err
	}
	l.loaded = true
	klog.InfoS("Loaded the eBPF host datapath", "transportIfIndex", config.TransportIfIndex,
		"gatewayIfIndex", config.GatewayIfIndex, "localPodCIDR", config.LocalPodCIDR)
	return nil
}

func validate(config Config) error {
	switch {
	case config.TransportIfIndex <= 0:
		return fmt.Errorf("the transport interface index is %d", config.TransportIfIndex)
	case config.GatewayIfIndex <= 0:
		return fmt.Errorf("the gateway interface index is %d", config.GatewayIfIndex)
	case config.TransportMTU <= 0:
		return fmt.Errorf("the transport MTU is %d", config.TransportMTU)
	case config.GatewayMTU <= 0:
		return fmt.Errorf("the gateway MTU is %d", config.GatewayMTU)
	case config.LocalPodCIDR == nil:
		return fmt.Errorf("the local Pod CIDR is not set")
	case config.GatewayIPv4 == nil:
		return fmt.Errorf("the gateway address is not set")
	case config.NodeIPv4 == nil:
		return fmt.Errorf("the Node transport address is not set")
	}
	for _, ip := range []struct {
		name  string
		value net.IP
	}{{"gateway address", config.GatewayIPv4}, {"Node transport address", config.NodeIPv4}} {
		if ip.value.To4() == nil {
			return fmt.Errorf("the %s %s is not IPv4, which is all this datapath supports for now",
				ip.name, ip.value)
		}
	}
	if config.LocalPodCIDR.IP.To4() == nil {
		return fmt.Errorf("the local Pod CIDR %s is not IPv4, which is all this datapath supports for now",
			config.LocalPodCIDR)
	}
	// The programs tell a Pod from anything else by the Pod CIDR alone, so a Node whose transport address
	// is inside it would have its own traffic forwarded as a Pod's, and the traffic of a host network Pod
	// with it. That configuration is refused rather than handled, as nothing else in the datapath could
	// tell the two apart.
	if config.LocalPodCIDR.Contains(config.NodeIPv4) {
		return fmt.Errorf("the Node transport address %s is inside the local Pod CIDR %s, which this "+
			"datapath cannot tell apart from a Pod", config.NodeIPv4, config.LocalPodCIDR)
	}
	if !config.LocalPodCIDR.Contains(config.GatewayIPv4) {
		return fmt.Errorf("the gateway address %s is outside the local Pod CIDR %s, which the datapath "+
			"assumes it is in", config.GatewayIPv4, config.LocalPodCIDR)
	}
	return nil
}

func (l *loader) loadLocked(config Config) error {
	for _, def := range bpfMaps {
		fd, err := createMap(def)
		if err != nil {
			return err
		}
		l.mapFDs[def.name] = fd
	}
	// The configuration is written before the programs are attached, so that the first packet they see
	// is matched against the real Pod CIDR rather than against an empty one.
	if err := l.writeConfig(config); err != nil {
		return err
	}
	for _, def := range bpfPrograms {
		instructions, err := l.relocate(def)
		if err != nil {
			return err
		}
		fd, err := loadProgram(def.name, instructions)
		if err != nil {
			return err
		}
		l.programFDs[def.name] = fd
	}

	// hostdp_fwd goes on the gateway ingress, where a local Pod's packet enters the host from OVS before
	// the stack routes it; hostdp_return goes on the transport ingress, where the packets coming back
	// from remote Pods arrive.
	for _, a := range []struct {
		program string
		ifIndex int
	}{
		{programFwd, config.GatewayIfIndex},
		{programReturn, config.TransportIfIndex},
	} {
		attached, err := attach(l.programFDs[a.program], a.ifIndex, true, a.program)
		if err != nil {
			return err
		}
		l.attachments = append(l.attachments, attached)
	}
	return nil
}

// relocate copies the instructions of a program and replaces the immediate of each instruction referring to a
// map with the descriptor of that map.
func (l *loader) relocate(def programDef) ([]byte, error) {
	instructions := []byte(def.instructions)
	patched := make([]byte, len(instructions))
	copy(patched, instructions)
	for _, reloc := range def.relocs {
		offset := int(reloc.instruction) * instructionSize
		// A wide instruction takes two slots, so its second half has to be there as well.
		if offset < 0 || offset+2*instructionSize > len(patched) {
			return nil, fmt.Errorf("program %s has a relocation at instruction %d, which is outside "+
				"its %d instructions", def.name, reloc.instruction, len(patched)/instructionSize)
		}
		if patched[offset] != opcodeLoadImm64 {
			return nil, fmt.Errorf("program %s has a relocation at instruction %d, whose opcode is "+
				"%#02x rather than a wide load", def.name, reloc.instruction, patched[offset])
		}
		if int(reloc.mapIndex) >= len(bpfMaps) {
			return nil, fmt.Errorf("program %s refers to map %d, and there are %d",
				def.name, reloc.mapIndex, len(bpfMaps))
		}
		name := bpfMaps[reloc.mapIndex].name
		fd, ok := l.mapFDs[name]
		if !ok {
			return nil, fmt.Errorf("program %s refers to map %s, which was not created", def.name, name)
		}
		// The high nibble of the second byte is the source register, which says what the immediate is.
		patched[offset+1] = patched[offset+1]&0x0f | pseudoMapFD<<4
		binary.LittleEndian.PutUint32(patched[offset+4:], uint32(fd))
	}
	return patched, nil
}

func (l *loader) writeConfig(config Config) error {
	ones, _ := config.LocalPodCIDR.Mask.Size()
	for slot, value := range map[uint32]uint32{
		cfgLocalPodNet:    networkOrder(config.LocalPodCIDR.IP),
		cfgLocalPodPrefix: uint32(ones),
		cfgTransportMTU:   uint32(config.TransportMTU),
		cfgGatewayMTU:     uint32(config.GatewayMTU),
		cfgGatewayIfIndex: uint32(config.GatewayIfIndex),
		cfgGatewayIP:      networkOrder(config.GatewayIPv4),
	} {
		key := slot
		if err := mapUpdate(l.mapFDs[mapNodeConfig], unsafe.Pointer(&key), unsafe.Pointer(&value), 0); err != nil {
			return fmt.Errorf("writing slot %d of the configuration: %w", slot, err)
		}
	}
	return nil
}

// networkOrder returns an IPv4 address as the four bytes it has on the wire, read as a native integer, which
// is the form the programs compare it in: they read it out of the packet and never swap it.
func networkOrder(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.NativeEndian.Uint32(v4)
}

func routeKeyOf(podCIDR *net.IPNet) (podRouteKey, error) {
	v4 := podCIDR.IP.To4()
	if v4 == nil {
		return podRouteKey{}, fmt.Errorf("Pod CIDR %s is not IPv4, which is all this datapath supports for now", podCIDR)
	}
	ones, bits := podCIDR.Mask.Size()
	if bits != 32 {
		return podRouteKey{}, fmt.Errorf("Pod CIDR %s does not have an IPv4 mask", podCIDR)
	}
	key := podRouteKey{prefixLen: uint32(ones)}
	copy(key.addr[:], v4)
	return key, nil
}

func (l *loader) AddPodRoute(podCIDR *net.IPNet, nextHop net.IP) error {
	if podCIDR == nil || nextHop == nil {
		return fmt.Errorf("the Pod CIDR and the next hop are both required")
	}
	if nextHop.To4() == nil {
		return fmt.Errorf("next hop %s is not IPv4, which is all this datapath supports for now", nextHop)
	}
	key, err := routeKeyOf(podCIDR)
	if err != nil {
		return err
	}
	value := networkOrder(nextHop)

	l.mutex.Lock()
	defer l.mutex.Unlock()
	if !l.loaded {
		return nil
	}
	if err := mapUpdate(l.mapFDs[mapPodRoutes], unsafe.Pointer(&key), unsafe.Pointer(&value), 0); err != nil {
		return fmt.Errorf("adding the route to %s via %s: %w", podCIDR, nextHop, err)
	}
	return nil
}

func (l *loader) DeletePodRoute(podCIDR *net.IPNet) error {
	if podCIDR == nil {
		return fmt.Errorf("the Pod CIDR is required")
	}
	key, err := routeKeyOf(podCIDR)
	if err != nil {
		return err
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()
	if !l.loaded {
		return nil
	}
	if err := mapDelete(l.mapFDs[mapPodRoutes], unsafe.Pointer(&key)); err != nil {
		// Deleting a route which is not there is what happens when it was never added, and leaves the
		// map in the wanted state either way.
		if err == unix.ENOENT {
			return nil
		}
		return fmt.Errorf("deleting the route to %s: %w", podCIDR, err)
	}
	return nil
}

func (l *loader) Stats() (Stats, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	var stats Stats
	if !l.loaded {
		return stats, nil
	}
	values := make([]uint64, statCount)
	for slot := range values {
		key := uint32(slot)
		if err := mapLookup(l.mapFDs[mapStats], unsafe.Pointer(&key), unsafe.Pointer(&values[slot])); err != nil {
			return Stats{}, fmt.Errorf("reading counter %d: %w", slot, err)
		}
	}
	return Stats{
		Forwarded:     values[statFwd],
		ForwardMisses: values[statFwdMiss],
		Returned:      values[statReturn],
		ReturnMisses:  values[statReturnMiss],
		Passed:        values[statPass],
		TTLExpired:    values[statTTLExpired],
		TooBig:        values[statTooBig],
	}, nil
}

func (l *loader) Close() error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.closeLocked()
}

// closeLocked undoes what Load did, in the reverse order, and reports the first thing which went wrong after
// having tried all of them: leaving a program attached because an unrelated descriptor would not close is
// worse than the error itself.
func (l *loader) closeLocked() error {
	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, a := range l.attachments {
		record(a.detach())
	}
	l.attachments = nil
	for name, fd := range l.programFDs {
		record(unix.Close(fd))
		delete(l.programFDs, name)
	}
	for name, fd := range l.mapFDs {
		record(unix.Close(fd))
		delete(l.mapFDs, name)
	}
	l.loaded = false
	return firstErr
}
