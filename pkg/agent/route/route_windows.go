//go:build windows
// +build windows

// Copyright 2020 Antrea Authors
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

package route

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/util/winfirewall"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	iputil "antrea.io/antrea/pkg/util/ip"
)

const (
	inboundFirewallRuleName  = "Antrea: accept packets from local Pods"
	outboundFirewallRuleName = "Antrea: accept packets to local Pods"

	antreaNatNodePort = "antrea-nat-nodeport"
)

var (
	antreaNat                  = util.AntreaNatName
	virtualServiceIPv4Net      = util.NewIPNet(config.VirtualServiceIPv4)
	virtualNodePortDNATIPv4Net = util.NewIPNet(config.VirtualNodePortDNATIPv4)
	PodCIDRIPv4                *net.IPNet
)

type Client struct {
	nodeConfig      *config.NodeConfig
	networkConfig   *config.NetworkConfig
	serviceRoutes   *sync.Map
	fwClient        *winfirewall.Client
	bridgeInfIndex  int
	noSNAT          bool
	proxyAll        bool
	clusterIPv4CIDR *net.IPNet
}

// NewClient returns a route client.
func NewClient(networkConfig *config.NetworkConfig, noSNAT, proxyAll, connectUplinkToBridge, multicastEnabled bool) (*Client, error) {
	return &Client{
		networkConfig: networkConfig,
		serviceRoutes: &sync.Map{},
		fwClient:      winfirewall.NewClient(),
		noSNAT:        noSNAT,
		proxyAll:      proxyAll,
	}, nil
}

// Initialize sets nodeConfig on Window.
// Service LoadBalancing is provided by OpenFlow.
func (c *Client) Initialize(nodeConfig *config.NodeConfig, done func()) error {
	c.nodeConfig = nodeConfig
	PodCIDRIPv4 = nodeConfig.PodIPv4CIDR
	bridgeInf, err := net.InterfaceByName(nodeConfig.OVSBridge)
	if err != nil {
		return fmt.Errorf("failed to find the interface %s: %v", nodeConfig.OVSBridge, err)
	}
	c.bridgeInfIndex = bridgeInf.Index
	if err := c.initFwRules(); err != nil {
		return err
	}
	// Enable IP-Forwarding on the host gateway interface, thus the host networking stack can be used to forward the
	// SNAT packet from local Pods. The SNAT packet is leaving the OVS pipeline with the Node's IP as the source IP,
	// the external address as the destination IP, and the antrea-gw0's MAC as the dst MAC. Then it will be forwarded
	// to the host network stack from the host gateway interface, and its dst MAC could be resolved to the right one.
	// At last, the packet is sent back to OVS from the bridge Interface, and the OpenFlow entries will output it to
	// the uplink interface directly.
	if err := util.EnableIPForwarding(nodeConfig.GatewayConfig.Name); err != nil {
		return err
	}
	if !c.noSNAT {
		err := util.NewNetNat(antreaNat, nodeConfig.PodIPv4CIDR)
		if err != nil {
			return err
		}
	}

	if c.proxyAll {
		if err := c.initServiceIPRoutes(); err != nil {
			return fmt.Errorf("failed to initialize Service IP routes: %v", err)
		}
	}
	done()

	return nil
}

func (c *Client) initServiceIPRoutes() error {
	if c.networkConfig.IPv4Enabled {
		if err := c.addVirtualServiceIPRoute(false); err != nil {
			return err
		}
		if err := c.addVirtualNodePortDNATIPRoute(false); err != nil {
			return err
		}
	}
	if c.networkConfig.IPv6Enabled {
		return fmt.Errorf("IPv6 is not supported on Windows")
	}
	return nil
}

// Reconcile removes the orphaned routes and related configuration based on the desired podCIDRs and Service IPs. Only
// the route entries on the host gateway interface are stored in the cache.
func (c *Client) Reconcile(podCIDRs []string, svcIPs map[string]bool) error {
	desiredPodCIDRs := sets.NewString(podCIDRs...)
	routes, err := c.listIPRoutesOnGW()
	if err != nil {
		return err
	}
	for dst, rt := range routes {
		if desiredPodCIDRs.Has(dst) {
			c.serviceRoutes.Store(dst, rt)
			continue
		}
		// Don't delete the routes which are added by AntreaProxy when proxyAll is enabled.
		if c.proxyAll && c.isServiceRoute(rt) {
			continue
		}
		err := util.RemoveNetRoute(rt)
		if err != nil {
			return err
		}
	}
	return nil
}

// AddRoutes adds routes to the provided podCIDR.
// It overrides the routes if they already exist, without error.
func (c *Client) AddRoutes(podCIDR *net.IPNet, nodeName string, peerNodeIP, peerGwIP net.IP) error {
	obj, found := c.serviceRoutes.Load(podCIDR.String())
	route := &util.Route{
		DestinationSubnet: podCIDR,
		RouteMetric:       util.MetricDefault,
	}
	if c.networkConfig.NeedsTunnelToPeer(peerNodeIP, c.nodeConfig.NodeTransportIPv4Addr) {
		route.LinkIndex = c.nodeConfig.GatewayConfig.LinkIndex
		route.GatewayAddress = peerGwIP
	} else if c.networkConfig.NeedsDirectRoutingToPeer(peerNodeIP, c.nodeConfig.NodeTransportIPv4Addr) {
		// NoEncap traffic to Node on the same subnet.
		// Set the peerNodeIP as next hop.
		route.LinkIndex = c.bridgeInfIndex
		route.GatewayAddress = peerNodeIP
	}
	// NoEncap traffic to Node on the different subnet needs underlying routing support.
	// Use host default route inside the Node.

	if found {
		existingRoute := obj.(*util.Route)
		if existingRoute.GatewayAddress.Equal(route.GatewayAddress) {
			klog.V(4).Infof("Route with destination %s already exists on %s (%s)", podCIDR.String(), nodeName, peerNodeIP)
			return nil
		}
		// Remove the existing route entry if the gateway address is not as expected.
		if err := util.RemoveNetRoute(existingRoute); err != nil {
			klog.Errorf("Failed to delete existing route entry with destination %s gateway %s on %s (%s)", podCIDR.String(), peerGwIP.String(), nodeName, peerNodeIP)
			return err
		}
	}

	if route.GatewayAddress == nil {
		return nil
	}

	if err := util.ReplaceNetRoute(route); err != nil {
		return err
	}

	c.serviceRoutes.Store(podCIDR.String(), route)
	klog.V(2).Infof("Added route with destination %s via %s on host gateway on %s (%s)", podCIDR.String(), peerGwIP.String(), nodeName, peerNodeIP)
	return nil
}

// DeleteRoutes deletes routes to the provided podCIDR.
// It does nothing if the routes don't exist, without error.
func (c *Client) DeleteRoutes(podCIDR *net.IPNet) error {
	obj, found := c.serviceRoutes.Load(podCIDR.String())
	if !found {
		klog.V(2).Infof("Route with destination %s not exists", podCIDR.String())
		return nil
	}

	rt := obj.(*util.Route)
	if err := util.RemoveNetRoute(rt); err != nil {
		return err
	}
	c.serviceRoutes.Delete(podCIDR.String())
	klog.V(2).Infof("Deleted route with destination %s from host gateway", podCIDR.String())
	return nil
}

// addVirtualServiceIPRoute adds routes on a Windows Node for redirecting ClusterIP and NodePort
// Service traffic from host network to OVS via antrea-gw0.
func (c *Client) addVirtualServiceIPRoute(isIPv6 bool) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	svcIP := config.VirtualServiceIPv4

	neigh := generateNeigh(svcIP, linkIndex)
	if err := util.ReplaceNetNeighbor(neigh); err != nil {
		return fmt.Errorf("failed to add new IP neighbour for %s: %w", svcIP, err)
	}
	klog.InfoS("Added virtual Service IP neighbor", "neighbor", neigh)

	route := generateRoute(virtualServiceIPv4Net, net.IPv4zero, linkIndex, util.MetricHigh)
	if err := util.ReplaceNetRoute(route); err != nil {
		return fmt.Errorf("failed to install route for virtual Service IP %s: %w", svcIP.String(), err)
	}
	c.serviceRoutes.Store(svcIP.String(), route)
	klog.InfoS("Added virtual Service IP route", "route", route)

	return nil
}

func (c *Client) AddClusterIPRoute(svcIP net.IP) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	gw := config.VirtualServiceIPv4
	metric := util.MetricHigh
	curClusterIPCIDR := c.clusterIPv4CIDR

	// If the route exists and its destination CIDR contains the ClusterIP, there is no need to update the route.
	if curClusterIPCIDR != nil && curClusterIPCIDR.Contains(svcIP) {
		klog.V(4).InfoS("Route with current ClusterIP CIDR can route the ClusterIP to Antrea gateway", "ClusterIP CIDR", curClusterIPCIDR, "ClusterIP", svcIP)
		return nil
	}

	var newClusterIPCIDR *net.IPNet
	var err error
	if curClusterIPCIDR != nil {
		// If the route exists and its destination CIDR doesn't contain the ClusterIP, generate a new destination CIDR by
		// enlarging the current destination CIDR with the ClusterIP.
		if newClusterIPCIDR, err = util.ExtendCIDRWithIP(curClusterIPCIDR, svcIP); err != nil {
			return fmt.Errorf("enlarge the destination CIDR with an error: %w", err)
		}
	} else {
		// If the route doesn't exist, generate a new destination CIDR with the ClusterIP. Note that, this is the first
		// ClusterIP since the route doesn't exist.
		newClusterIPCIDR = util.NewIPNet(svcIP)
	}

	// Generate a route with the new destination CIDR and install it.
	route := generateRoute(newClusterIPCIDR, gw, linkIndex, metric)
	if err = util.ReplaceNetRoute(route); err != nil {
		return fmt.Errorf("failed to install new ClusterIP route: %w", err)
	}
	// Store the new destination CIDR.
	c.clusterIPv4CIDR = route.DestinationSubnet
	klog.V(4).InfoS("Created a route to route the ClusterIP to Antrea gateway", "route", route, "ClusterIP", svcIP)

	// Collect stale routes.
	var staleRoutes []*util.Route
	if curClusterIPCIDR != nil {
		// If current destination CIDR is not nil, the route with current destination CIDR should be uninstalled since
		// a new route with a newly calculated destination CIDR has been installed.
		route.DestinationSubnet = curClusterIPCIDR
		staleRoutes = []*util.Route{route}
	} else {
		// If current destination CIDR is nil, which means that Antrea Agent has just started, then all existing routes
		// whose destination CIDR contains the first ClusterIP should be uninstalled, except the newly installed route.
		// Note that, there may be multiple stale routes prior to this commit. When upgrading, all stale routes will be
		// collected. After this commit, there will be only one stale route after Antrea Agent started.
		routes, err := c.listIPRoutesOnGW()
		if err != nil {
			return fmt.Errorf("error listing ip routes: %w", err)
		}
		for _, rt := range routes {
			if rt.GatewayAddress.Equal(gw) && !rt.DestinationSubnet.IP.Equal(svcIP) && rt.DestinationSubnet.Contains(svcIP) {
				staleRoutes = append(staleRoutes, rt)
			}
		}
	}

	// Remove stale routes.
	for _, rt := range staleRoutes {
		if err = util.RemoveNetRoute(rt); err != nil {
			if strings.Contains(err.Error(), "No matching MSFT_NetRoute objects") {
				klog.InfoS("Failed to delete stale ClusterIP route since the route doesn't exist", "route", route)
			} else {
				return fmt.Errorf("failed to delete routing entry for ClusterIP %s: %w", svcIP.String(), err)
			}
		}
		klog.V(4).InfoS("Uninstalled stale ClusterIP route successfully", "stale route", rt)
	}

	return nil
}

func (c *Client) addVirtualNodePortDNATIPRoute(isIPv6 bool) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	vIPNet := virtualNodePortDNATIPv4Net
	vIP := config.VirtualNodePortDNATIPv4
	gw := config.VirtualServiceIPv4

	route := generateRoute(vIPNet, gw, linkIndex, util.MetricHigh)
	if err := util.ReplaceNetRoute(route); err != nil {
		return fmt.Errorf("failed to install route for virtual Service IP %s: %w", vIP.String(), err)
	}
	c.serviceRoutes.Store(vIP.String(), route)
	klog.InfoS("Added virtual Service IP route", "route", route)

	// For NodePort Service, a new NetNat for NetNatStaticMapping is needed.
	if err := util.NewNetNat(antreaNatNodePort, vIPNet); err != nil {
		return err
	}

	return nil
}

// MigrateRoutesToGw is not supported on Windows.
func (c *Client) MigrateRoutesToGw(linkName string) error {
	return errors.New("MigrateRoutesToGw is unsupported on Windows")
}

// UnMigrateRoutesFromGw is not supported on Windows.
func (c *Client) UnMigrateRoutesFromGw(route *net.IPNet, linkName string) error {
	return errors.New("UnMigrateRoutesFromGw is unsupported on Windows")
}

// Run is not supported on Windows and returns immediately.
func (c *Client) Run(stopCh <-chan struct{}) {
}

func (c *Client) isServiceRoute(route *util.Route) bool {
	// If the destination IP or gateway IP is virtual Service IP , then it is a route which is added by AntreaProxy.
	if route.DestinationSubnet.IP.Equal(config.VirtualServiceIPv4) || route.GatewayAddress.Equal(config.VirtualServiceIPv4) {
		return true
	}
	return false
}

func (c *Client) listIPRoutesOnGW() (map[string]*util.Route, error) {
	routes, err := util.GetNetRoutesAll()
	if err != nil {
		return nil, err
	}
	rtMap := make(map[string]*util.Route)
	for idx := range routes {
		rt := routes[idx]
		if rt.LinkIndex != c.nodeConfig.GatewayConfig.LinkIndex {
			continue
		}
		// Only process IPv4 route entries in the loop.
		if rt.DestinationSubnet.IP.To4() == nil {
			continue
		}
		// Retrieve the route entries that use global unicast IP address as the destination. "GetNetRoutesAll" also
		// returns the entries of loopback, broadcast, and multicast, which are added by the system when adding a new IP
		// on the interface. Since removing those route entries might introduce the host networking issues, ignore them
		// from the list.
		if !rt.DestinationSubnet.IP.IsGlobalUnicast() {
			continue
		}
		// Windows adds an active route entry for the local broadcast address automatically when a new IP address
		// is configured on the interface. This route entry should be ignored in the list.
		if !rt.GatewayAddress.Equal(config.VirtualServiceIPv4) && rt.DestinationSubnet.IP.Equal(iputil.GetLocalBroadcastIP(rt.DestinationSubnet)) {
			continue
		}
		rtMap[rt.DestinationSubnet.String()] = &rt
	}
	return rtMap, nil
}

// initFwRules adds Windows Firewall rules to accept the traffic that is sent to or from local Pods.
func (c *Client) initFwRules() error {
	err := c.fwClient.AddRuleAllowIP(inboundFirewallRuleName, winfirewall.FWRuleIn, c.nodeConfig.PodIPv4CIDR)
	if err != nil {
		return err
	}
	err = c.fwClient.AddRuleAllowIP(outboundFirewallRuleName, winfirewall.FWRuleOut, c.nodeConfig.PodIPv4CIDR)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) AddSNATRule(snatIP net.IP, mark uint32) error {
	return nil
}

func (c *Client) DeleteSNATRule(mark uint32) error {
	return nil
}

// TODO: nodePortAddresses is not supported currently.
func (c *Client) AddNodePort(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error {
	return util.ReplaceNetNatStaticMapping(antreaNatNodePort, "0.0.0.0", port, config.VirtualServiceIPv4.String(), port, string(protocol))
}

func (c *Client) DeleteNodePort(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error {
	return util.RemoveNetNatStaticMapping(antreaNatNodePort, "0.0.0.0", port, string(protocol))
}

// addLoadBalancerIngressIPRoute is used to add routing entry which is used to route LoadBalancer ingress IP to Antrea
// gateway on host.
func (c *Client) addLoadBalancerIngressIPRoute(svcIPStr string) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	gw := config.VirtualServiceIPv4
	metric := util.MetricHigh
	_, svcIPNet, _ := net.ParseCIDR(svcIPStr)

	route := generateRoute(svcIPNet, gw, linkIndex, metric)
	if err := util.ReplaceNetRoute(route); err != nil {
		return fmt.Errorf("failed to install routing entry for LoadBalancer ingress IP %s: %w", svcIPStr, err)
	}
	klog.V(4).InfoS("Added LoadBalancer ingress IP route", "route", route)
	c.serviceRoutes.Store(svcIPStr, route)

	return nil
}

// deleteLoadBalancerIngressIPRoute is used to delete routing entry which is used to route LoadBalancer ingress IP to Antrea
// gateway on host.
func (c *Client) deleteLoadBalancerIngressIPRoute(svcIPStr string) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	gw := config.VirtualServiceIPv4
	metric := util.MetricHigh
	_, svcIPNet, _ := net.ParseCIDR(svcIPStr)

	route := generateRoute(svcIPNet, gw, linkIndex, metric)
	if err := util.RemoveNetRoute(route); err != nil {
		if strings.Contains(err.Error(), "No matching MSFT_NetRoute objects") {
			klog.InfoS("Failed to delete LoadBalancer ingress IP route since the route doesn't exist", "route", route)
		} else {
			return fmt.Errorf("failed to delete routing entry for LoadBalancer ingress IP %s: %w", svcIPStr, err)
		}
	}
	klog.V(4).InfoS("Uninstalled stale ClusterIP route successfully", "stale route", route)
	c.serviceRoutes.Delete(svcIPStr)

	return nil
}

func (c *Client) AddLoadBalancer(externalIPs []string) error {
	for _, svcIPStr := range externalIPs {
		if err := c.addLoadBalancerIngressIPRoute(svcIPStr); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) DeleteLoadBalancer(externalIPs []string) error {
	for _, svcIPStr := range externalIPs {
		if err := c.deleteLoadBalancerIngressIPRoute(svcIPStr); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) AddLocalAntreaFlexibleIPAMPodRule(podAddresses []net.IP) error {
	return nil
}

func (c *Client) DeleteLocalAntreaFlexibleIPAMPodRule(podAddresses []net.IP) error {
	return nil
}

func generateRoute(ipNet *net.IPNet, gw net.IP, linkIndex int, metric int) *util.Route {
	return &util.Route{
		DestinationSubnet: ipNet,
		GatewayAddress:    gw,
		RouteMetric:       metric,
		LinkIndex:         linkIndex,
	}
}

func generateNeigh(ip net.IP, linkIndex int) *util.Neighbor {
	return &util.Neighbor{
		LinkIndex:        linkIndex,
		IPAddress:        ip,
		LinkLayerAddress: openflow.GlobalVirtualMAC,
		State:            "Permanent",
	}
}
