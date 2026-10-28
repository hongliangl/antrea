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

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"

	agentconfig "antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/ebpf/internal/bpf"
	"antrea.io/antrea/v2/pkg/agent/ebpf/internal/objects"
	"antrea.io/antrea/v2/pkg/util/channel"
)

// instructionSize is the size of an eBPF instruction. A wide one, which is what holds a map reference, takes
// two of those, and its immediate is the first four bytes after the opcode and the registers.
const instructionSize = bpf.InstructionSize

// opcodeLoadImm64 is the opcode of the wide instruction loading a 64 bit immediate, which is the only one a
// map relocation applies to. pseudoMapFD in its source register is what tells the kernel that the immediate
// is the descriptor of a map rather than a value.
const (
	opcodeLoadImm64 = 0x18
	pseudoMapFD     = 1
)

// The stats indices must match bpf/host_datapath.bpf.c.
const (
	statForward uint32 = iota
	statForwardMiss
	statReturn
	statReturnMiss
	statPass
	statTTLExpired
	statTooBig
	statCount
)

// The names the programs are attached under, which must match the ones bpf/host_datapath.bpf.c defines.
const (
	programForward = "hostdp_fwd"
	programReturn  = "hostdp_return"
)

const (
	mapPodRoutes  = "pod_routes"
	mapPodRoutes6 = "pod_routes6"
	mapNodeConfig = "node_config"
	mapStats      = "stats"
)

// syncInterval controls program attachment checks and neighbor reconciliation retries.
const syncInterval = 30 * time.Second

// ipConfig4 matches struct ip_config4.
type ipConfig4 struct {
	prefixLen   uint32
	localPodNet uint32
	gatewayIP   uint32
}

// ipConfig6 matches struct ip_config6.
type ipConfig6 struct {
	prefixLen   uint32
	localPodNet [16]byte
	gatewayIP   [16]byte
}

// nodeConfig matches struct node_config.
type nodeConfig struct {
	transportMTU      uint32
	gatewayMTU        uint32
	gatewayIfIndex    uint32
	forwardingEnabled uint32
	ipv4              ipConfig4
	ipv6              ipConfig6
}

// storedInterfaceState records the initial attachment target and its availability.
type storedInterfaceState struct {
	// program is the program attached to the interface, and name the name the interface is looked up by.
	program string
	name    string
	ifIndex int
	// missing prevents neighbor registration on an absent or replaced interface.
	missing bool
}

// client owns the maps, programs, attachments and interface reconciliation state.
type client struct {
	// networkConfig supplies the traffic mode checked during initialization.
	networkConfig *agentconfig.NetworkConfig
	// interfaceStore supplies local Pod IPs for neighbor registration.
	interfaceStore interfaceStore
	// podUpdateSubscriber delivers CNI Pod lifecycle notifications.
	podUpdateSubscriber channel.Subscriber
	// podUpdateCh coalesces CNI Pod notifications.
	podUpdateCh chan struct{}
	// mutex protects kernel resources and runtime state during reconciliation, route updates, Stats and Close.
	mutex sync.Mutex
	// mapFDs holds open BPF map descriptors by map name.
	mapFDs map[string]int
	// programFDs holds loaded BPF program descriptors by program name.
	programFDs map[string]int
	// attachments owns each program's hook attachment; an entry is nil between detach and successful reattach.
	attachments map[string]*bpf.Attachment
	// interfaceStates stores initial attachment targets and their availability by program name.
	interfaceStates map[string]*storedInterfaceState
	// neighborManager registers Pod and peer Node neighbors for kernel refresh.
	neighborManager *neighborManager
	// nextHops maps remote Pod CIDRs to peer Node IPs used for neighbor registration.
	nextHops map[string]net.IP
	// nodeConfig is the last configuration successfully written to the node_config map.
	nodeConfig nodeConfig
	// initialized is true while maps and programs are ready for use.
	initialized bool
}

var _ Interface = (*client)(nil)

// NewClient prepares the eBPF client. Initialize creates its kernel resources.
func NewClient(
	networkConfig *agentconfig.NetworkConfig,
	interfaceStore interfaceStore,
	podUpdateSubscriber channel.Subscriber,
) Interface {
	return &client{
		networkConfig:       networkConfig,
		interfaceStore:      interfaceStore,
		podUpdateSubscriber: podUpdateSubscriber,
		podUpdateCh:         make(chan struct{}, 1),
		mapFDs:              make(map[string]int),
		programFDs:          make(map[string]int),
		attachments:         make(map[string]*bpf.Attachment),
		interfaceStates:     make(map[string]*storedInterfaceState),
	}
}

func (c *client) Initialize(agentNodeConfig *agentconfig.NodeConfig) error {
	if c.networkConfig.TrafficEncapMode != agentconfig.TrafficEncapModeNoEncap &&
		c.networkConfig.TrafficEncapMode != agentconfig.TrafficEncapModeHybrid {
		return fmt.Errorf("the eBPF host datapath supports noEncap and hybrid modes, got %s",
			c.networkConfig.TrafficEncapMode)
	}
	// The BPF programs classify a transport IP inside the Pod CIDR as a local Pod.
	if agentNodeConfig.PodIPv4CIDR != nil &&
		agentNodeConfig.NodeTransportIPv4Addr != nil &&
		agentNodeConfig.PodIPv4CIDR.Contains(agentNodeConfig.NodeTransportIPv4Addr.IP) {
		return fmt.Errorf("the Node transport address %s is inside the local Pod CIDR %s",
			agentNodeConfig.NodeTransportIPv4Addr.IP,
			agentNodeConfig.PodIPv4CIDR)
	}
	if agentNodeConfig.PodIPv6CIDR != nil &&
		agentNodeConfig.NodeTransportIPv6Addr != nil &&
		agentNodeConfig.PodIPv6CIDR.Contains(agentNodeConfig.NodeTransportIPv6Addr.IP) {
		return fmt.Errorf("the Node transport address %s is inside the local Pod CIDR %s",
			agentNodeConfig.NodeTransportIPv6Addr.IP,
			agentNodeConfig.PodIPv6CIDR)
	}
	transport, err := net.InterfaceByName(agentNodeConfig.NodeTransportInterfaceName)
	if err != nil {
		return fmt.Errorf("error getting the transport interface %s: %w", agentNodeConfig.NodeTransportInterfaceName, err)
	}
	gateway, err := net.InterfaceByName(agentNodeConfig.GatewayConfig.Name)
	if err != nil {
		return fmt.Errorf("error getting the gateway interface %s: %w", agentNodeConfig.GatewayConfig.Name, err)
	}

	var podCIDRs []*net.IPNet
	var gatewayIPs []net.IP
	var families []int
	if agentNodeConfig.PodIPv4CIDR != nil {
		podCIDRs = append(podCIDRs, agentNodeConfig.PodIPv4CIDR)
		gatewayIPs = append(gatewayIPs, agentNodeConfig.GatewayConfig.IPv4)
		families = append(families, unix.AF_INET)
	}
	if agentNodeConfig.PodIPv6CIDR != nil {
		podCIDRs = append(podCIDRs, agentNodeConfig.PodIPv6CIDR)
		gatewayIPs = append(gatewayIPs, agentNodeConfig.GatewayConfig.IPv6)
		families = append(families, unix.AF_INET6)
	}
	neighbors := &neighborManager{
		podCIDRs:   podCIDRs,
		gatewayIPs: gatewayIPs,
		families:   families,
		owned:      make(map[neighborKey]neighborFlags),
		paused:     true,
	}
	if err = neighbors.probe(); err != nil {
		return fmt.Errorf("managed neighbors are required for eBPF forwarding: %w", err)
	}
	c.neighborManager = neighbors
	c.nextHops = make(map[string]net.IP)
	// A kernel older than 5.11 accounts the memory of the maps against the locked memory limit rather
	// than against the cgroup of the process, and the default limit is far below what they need.
	if err = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}); err != nil {
		klog.V(2).InfoS("Could not raise the locked memory limit, which a kernel 5.11 or later ignores anyway", "err", err)
	}

	config := nodeConfig{
		transportMTU:   uint32(transport.MTU),
		gatewayMTU:     uint32(gateway.MTU),
		gatewayIfIndex: uint32(gateway.Index),
	}
	if agentNodeConfig.PodIPv4CIDR != nil {
		ones, _ := agentNodeConfig.PodIPv4CIDR.Mask.Size()
		config.ipv4.prefixLen = uint32(ones)
		config.ipv4.localPodNet = binary.NativeEndian.Uint32(networkOrder(agentNodeConfig.PodIPv4CIDR.IP))
		config.ipv4.gatewayIP = binary.NativeEndian.Uint32(networkOrder(agentNodeConfig.GatewayConfig.IPv4))
	}
	if agentNodeConfig.PodIPv6CIDR != nil {
		ones, _ := agentNodeConfig.PodIPv6CIDR.Mask.Size()
		config.ipv6.prefixLen = uint32(ones)
		copy(config.ipv6.localPodNet[:], networkOrder(agentNodeConfig.PodIPv6CIDR.IP))
		copy(config.ipv6.gatewayIP[:], networkOrder(agentNodeConfig.GatewayConfig.IPv6))
	}

	if err = c.load(config, transport, gateway); err != nil {
		// Leave nothing half attached behind: what was done so far is undone, and the Node keeps
		// forwarding through the host stack.
		c.cleanup()
		return err
	}
	c.initialized = true
	c.syncNeighbors()
	klog.InfoS("Loaded the eBPF host datapath",
		"transportIfIndex", transport.Index,
		"gatewayIfIndex", gateway.Index,
		"localPodCIDR", agentNodeConfig.PodIPv4CIDR,
		"localPodIPv6CIDR", agentNodeConfig.PodIPv6CIDR)

	return nil
}

func (c *client) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting the eBPF client", "interval", syncInterval)
	defer klog.InfoS("Shutting down the eBPF client")

	subscriberID := c.podUpdateSubscriber.Subscribe(c.processPodUpdate)
	defer c.podUpdateSubscriber.Unsubscribe(subscriberID)

	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()
	c.sync()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			c.sync()
		case <-c.podUpdateCh:
			c.mutex.Lock()
			if c.initialized {
				c.syncNeighbors()
			}
			c.mutex.Unlock()
		}
	}
}

func (c *client) sync() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if !c.initialized {
		return
	}
	for _, stored := range c.interfaceStates {
		if err := c.syncProgram(stored); err != nil {
			klog.ErrorS(err, "Failed to reconcile eBPF program",
				"interface", stored.name,
				"program", stored.program)
		}
	}
	c.syncNeighbors()
}

// syncProgram restores a missing program attachment on its original interface.
func (c *client) syncProgram(stored *storedInterfaceState) error {
	link, err := netlink.LinkByName(stored.name)
	if err != nil {
		stored.missing = true
		return fmt.Errorf("getting interface %s: %w", stored.name, err)
	}
	if link.Attrs().Index != stored.ifIndex {
		stored.missing = true
		return fmt.Errorf("interface %s index changed from %d to %d", stored.name, stored.ifIndex, link.Attrs().Index)
	}
	stored.missing = false

	if old := c.attachments[stored.program]; old != nil {
		attached, err := old.Attached()
		if err != nil {
			return err
		}
		if attached {
			return nil
		}
		if err := old.Detach(); err != nil {
			return err
		}
		c.attachments[stored.program] = nil
	}

	attached, err := bpf.Attach(c.programFDs[stored.program], stored.ifIndex, true, stored.program)
	if err != nil {
		return err
	}
	c.attachments[stored.program] = attached
	klog.InfoS("Restored eBPF program", "interface", stored.name, "program", stored.program)

	return nil
}

func (c *client) load(config nodeConfig, transport, gateway *net.Interface) error {
	for _, def := range objects.Maps {
		fd, err := bpf.CreateMap(bpf.MapSpec{
			Name:       def.Name,
			Type:       def.Type,
			KeySize:    def.KeySize,
			ValueSize:  def.ValueSize,
			MaxEntries: def.MaxEntries,
			Flags:      def.Flags,
		})
		if err != nil {
			return err
		}
		c.mapFDs[def.Name] = fd
	}
	// The configuration is written before the programs are attached, so that the first packet they see
	// is matched against the real Pod CIDR rather than against an empty one.
	if err := c.writeNodeConfig(config); err != nil {
		return err
	}

	for _, def := range objects.Programs {
		instructions, err := c.relocate(def)
		if err != nil {
			return err
		}
		fd, err := bpf.LoadProgram(def.Name, instructions)
		if err != nil {
			return err
		}
		c.programFDs[def.Name] = fd
	}

	// hostdp_fwd goes on the gateway ingress, where a local Pod's packet enters the host from OVS before
	// the stack routes it; hostdp_return goes on the transport ingress, where the packets coming back
	// from remote Pods arrive.
	for _, stored := range []*storedInterfaceState{
		{
			program: programForward,
			name:    gateway.Name,
			ifIndex: gateway.Index,
		},
		{
			program: programReturn,
			name:    transport.Name,
			ifIndex: transport.Index,
		},
	} {
		attached, err := bpf.Attach(c.programFDs[stored.program], stored.ifIndex, true, stored.program)
		if err != nil {
			return err
		}
		c.attachments[stored.program] = attached
		c.interfaceStates[stored.program] = stored
	}

	return nil
}

// relocate copies the instructions of a program and replaces the immediate of each instruction referring to a
// map with the descriptor of that map.
func (c *client) relocate(def objects.Program) ([]byte, error) {
	instructions := []byte(def.Instructions)
	patched := make([]byte, len(instructions))
	copy(patched, instructions)

	for _, reloc := range def.Relocations {
		offset := int(reloc.Instruction) * instructionSize
		// A wide instruction takes two slots, so its second half has to be there as well.
		if offset < 0 || offset+2*instructionSize > len(patched) {
			return nil, fmt.Errorf("program %s has a relocation at instruction %d, which is outside "+
				"its %d instructions", def.Name, reloc.Instruction, len(patched)/instructionSize)
		}
		if patched[offset] != opcodeLoadImm64 {
			return nil, fmt.Errorf("program %s has a relocation at instruction %d, whose opcode is "+
				"%#02x rather than a wide load", def.Name, reloc.Instruction, patched[offset])
		}
		if int(reloc.MapIndex) >= len(objects.Maps) {
			return nil, fmt.Errorf("program %s refers to map %d, and there are %d",
				def.Name, reloc.MapIndex, len(objects.Maps))
		}
		name := objects.Maps[reloc.MapIndex].Name
		fd, ok := c.mapFDs[name]
		if !ok {
			return nil, fmt.Errorf("program %s refers to map %s, which was not created", def.Name, name)
		}
		// The high nibble of the second byte is the source register, which says what the immediate is.
		patched[offset+1] = patched[offset+1]&0x0f | pseudoMapFD<<4
		binary.LittleEndian.PutUint32(patched[offset+4:], uint32(fd))
	}
	return patched, nil
}

// writeNodeConfig updates the map and retains the last successfully written configuration.
// Call during initialization or with the client mutex held.
func (c *client) writeNodeConfig(config nodeConfig) error {
	key := uint32(0)
	if err := bpf.UpdateMapElement(c.mapFDs[mapNodeConfig], unsafe.Pointer(&key), unsafe.Pointer(&config), 0); err != nil {
		return fmt.Errorf("writing the Node configuration: %w", err)
	}
	c.nodeConfig = config

	return nil
}

func (c *client) AddPodRoute(podCIDR *net.IPNet, nextHop net.IP) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if !c.initialized {
		return nil
	}

	mapName := getMapPodRouteName(podCIDR)
	key := routeKeyOf(podCIDR)
	value := networkOrder(nextHop)
	err := bpf.UpdateMapElement(c.mapFDs[mapName],
		unsafe.Pointer(&key[0]),
		unsafe.Pointer(&value[0]),
		0)
	if err != nil {
		return fmt.Errorf("adding the route to %s via %s: %w", podCIDR, nextHop, err)
	}

	c.nextHops[podCIDR.String()] = append(net.IP(nil), nextHop...)
	c.syncNeighbors()

	return nil
}

func (c *client) DeletePodRoute(podCIDR *net.IPNet) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if !c.initialized {
		return nil
	}

	mapName := getMapPodRouteName(podCIDR)
	key := routeKeyOf(podCIDR)
	err := bpf.DeleteMapElement(c.mapFDs[mapName], unsafe.Pointer(&key[0]))
	// A route which was never installed is already in the wanted state.
	if err != nil && err != unix.ENOENT {
		return fmt.Errorf("deleting the route to %s: %w", podCIDR, err)
	}
	delete(c.nextHops, podCIDR.String())
	c.syncNeighbors()

	return nil
}

func (c *client) Stats() (Stats, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var stats Stats
	if !c.initialized {
		return stats, nil
	}
	values := make([]uint64, statCount)
	for slot := range values {
		key := uint32(slot)
		if err := bpf.LookupMapElement(c.mapFDs[mapStats], unsafe.Pointer(&key), unsafe.Pointer(&values[slot])); err != nil {
			return Stats{}, fmt.Errorf("reading counter %d: %w", slot, err)
		}
	}
	return Stats{
		Forwarded:     values[statForward],
		ForwardMisses: values[statForwardMiss],
		Returned:      values[statReturn],
		ReturnMisses:  values[statReturnMiss],
		Passed:        values[statPass],
		TTLExpired:    values[statTTLExpired],
		TooBig:        values[statTooBig],
	}, nil
}

func (c *client) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.cleanup()
}

// cleanup releases resources in reverse order and returns the first error after trying all of them.
// Call during initialization or with the client mutex held.
func (c *client) cleanup() error {
	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for name, a := range c.attachments {
		if a != nil {
			record(a.Detach())
		}
		delete(c.attachments, name)
	}
	if c.neighborManager != nil {
		record(c.neighborManager.sync(nil))
		c.neighborManager = nil
	}
	clear(c.nextHops)
	clear(c.interfaceStates)
	for name, fd := range c.programFDs {
		record(unix.Close(fd))
		delete(c.programFDs, name)
	}
	for name, fd := range c.mapFDs {
		record(unix.Close(fd))
		delete(c.mapFDs, name)
	}
	c.initialized = false
	return firstErr
}

// networkOrder returns the address bytes in network order: 4 bytes for IPv4 or 16 for IPv6.
func networkOrder(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

// routeKeyOf encodes struct pod_route_key or pod_route_key6: a native-order prefix length followed by address bytes.
func routeKeyOf(podCIDR *net.IPNet) []byte {
	addr := networkOrder(podCIDR.IP)
	ones, _ := podCIDR.Mask.Size()
	key := make([]byte, 4+len(addr))
	binary.NativeEndian.PutUint32(key, uint32(ones))
	copy(key[4:], addr)
	return key
}

func getMapPodRouteName(podCIDR *net.IPNet) string {
	if podCIDR.IP.To4() != nil {
		return mapPodRoutes
	}
	return mapPodRoutes6
}
