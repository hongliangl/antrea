//go:build linux
// +build linux

// Copyright 2023 Antrea Authors
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

package networkpolicy

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/route"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util/iptables"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	secv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/util/ip"
)

const (
	prefix = "ANTREA-POL"
)

/*
NodeNetworkPolicy datapath implementation using iptables/ip6tables involves four components:
1. Core iptables rule:
   - Added to ANTREA-POL-INGRESS-RULES (ingress) or ANTREA-POL-EGRESS-RULES (egress).
   - Matches an ipset created for the NodeNetworkPolicy rule as source (ingress) or destination (egress).
   - Targets an action (the rule with single service) or a service chain created for the NodeNetworkPolicy rule (the rule
     with multiple services).
2. Service iptables chain:
   - Created for the NodeNetworkPolicy rule to integrate service iptables rules if a rule has multiple services.
3. Service iptables rules:
   - Added to the service chain created for the NodeNetworkPolicy rule.
   - Constructed from the services of the NodeNetworkPolicy rule.
4. From/To ipset:
   - Created for the NodeNetworkPolicy rule, containing all source IP addresses (ingress) or destination IP addresses (egress).

Assuming three ingress NodeNetworkPolicy rules with IDs 1111, 2222, and 3333, prioritized in descending order.
Core iptables rules organized by priorities in ANTREA-POL-INGRESS-RULES like the following. Every ipset name consists of
prefix "ANTREA-POL", rule ID and IP protocol version. The name the target chain consists of prefix "ANTREA-POL" and rule ID.

```
:ANTREA-POL-INGRESS-RULES
-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-1111-4 src -j ANTREA-POL-1111 -m comment --comment "Antrea: for rule 1111, policy AntreaClusterNetworkPolicy:name1"
-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-2222-4 src -p tcp --dport 8080 -j ACCEPT -m comment --comment "Antrea: for rule 2222, policy AntreaClusterNetworkPolicy:name2"
-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-3333-4 src -p tcp --dport 22 -j ACCEPT -m comment --comment "Antrea: for rule 3333, policy AntreaClusterNetworkPolicy:name3"
```

There is a service iptables chain and service iptables rules for the NodeNetworkPolicy rule with ID 1111.

```
:ANTREA-POL-1111
-A ANTREA-POL-1111 -j ACCEPT -p tcp --dport 80
-A ANTREA-POL-1111 -j ACCEPT -p tcp --dport 443
```
*/

type iptRule struct {
	ruleID   string
	priority *types.Priority
	ruleStr  string
}

// iptChainCache caches the sorted iptables rules and for a chain.
type iptChainCache struct {
	rules []*iptRule
	sync.Mutex
}

func newIPTChainCache() *iptChainCache {
	return &iptChainCache{}
}

// nodePolicyLastRealized is the struct cached by nodeReconciler. It's used to track the actual state of iptables rules
// and chains we have enforced, so that we can know how to reconcile a rule when it's updated/removed.
type nodePolicyLastRealized struct {
	// ipsets tracks the last realized ipsets names for the policy rule.
	ipsets map[iptables.Protocol]string

	// serviceIPTChain tracks the last realized service iptables chain if multipleServices is true.
	serviceIPTChain  string
	multipleServices bool

	// coreIPTChain tracks the last realized iptables chain where the core iptables rule is installed.
	coreIPTChain string
	priority     *types.Priority
}

func newNodePolicyLastRealized() *nodePolicyLastRealized {
	return &nodePolicyLastRealized{
		ipsets: make(map[iptables.Protocol]string),
	}
}

type nodeReconciler struct {
	ipProtocols         []iptables.Protocol
	routeClient         route.Interface
	cachedCoreIPTChains map[string]*iptChainCache
	// lastRealizeds caches the last realized rules. It's a mapping from ruleID to *nodePolicyLastRealized.
	lastRealizeds sync.Map
}

func newNodeReconciler(routeClient route.Interface, ipv4Enabled, ipv6Enabled bool) *nodeReconciler {
	var ipProtocols []iptables.Protocol
	cachedCoreIPTChains := make(map[string]*iptChainCache)
	if ipv4Enabled {
		ipProtocols = append(ipProtocols, iptables.ProtocolIPv4)
		cachedCoreIPTChains[genCacheCategory(config.NodeNetworkPolicyIngressRulesChain, false)] = newIPTChainCache()
		cachedCoreIPTChains[genCacheCategory(config.NodeNetworkPolicyEgressRulesChain, false)] = newIPTChainCache()
	}
	if ipv6Enabled {
		ipProtocols = append(ipProtocols, iptables.ProtocolIPv6)
		cachedCoreIPTChains[genCacheCategory(config.NodeNetworkPolicyIngressRulesChain, true)] = newIPTChainCache()
		cachedCoreIPTChains[genCacheCategory(config.NodeNetworkPolicyEgressRulesChain, true)] = newIPTChainCache()
	}
	return &nodeReconciler{
		ipProtocols:         ipProtocols,
		routeClient:         routeClient,
		cachedCoreIPTChains: cachedCoreIPTChains,
	}
}

// Reconcile checks whether the provided rule have been enforced or not, and invoke the add or update method accordingly.
func (r *nodeReconciler) Reconcile(rule *CompletedRule) error {
	klog.InfoS("Reconciling Node NetworkPolicy rule", "rule", rule.ID, "policy", rule.SourceRef.ToString())

	value, exists := r.lastRealizeds.Load(rule.ID)
	var err error
	if !exists {
		err = r.add(rule)
	} else {
		err = r.update(value.(*nodePolicyLastRealized), rule)
	}
	return err
}

func (r *nodeReconciler) RunIDAllocatorWorker(stopCh <-chan struct{}) {

}

func (r *nodeReconciler) BatchReconcile(rules []*CompletedRule) error {
	if len(rules) == 0 {
		return nil
	}

	var ingressRulesToInstall, egressRulesToInstall, rulesToInstall []*CompletedRule
	for _, rule := range rules {
		if _, exists := r.lastRealizeds.Load(rule.ID); exists {
			klog.ErrorS(nil, "Rule should not have been realized yet: initialization phase", "rule", rule.ID)
			continue
		}
		rulesToInstall = append(rulesToInstall, rule)
		if rule.Direction == v1beta2.DirectionIn {
			ingressRulesToInstall = append(ingressRulesToInstall, rule)
		} else {
			egressRulesToInstall = append(egressRulesToInstall, rule)
		}
	}

	lastRealizeds := make(map[string]*nodePolicyLastRealized) // ruleID -> *nodePolicyLastRealized
	priorities := make(map[string]*types.Priority)            // ruleID -> *types.Priority
	serviceIPTChains := make(map[string]string)               // ruleID -> service iptables chain name
	serviceIPTRuleTargets := make(map[string]string)          // ruleID -> service iptables rule target
	coreIPTRuleTargets := make(map[string]string)             // ruleID -> core iptables rule target
	singleServices := make(map[string]*v1beta2.Service)       // ruleID -> single service

	for _, rule := range rulesToInstall {
		ruleID := rule.ID
		lastRealizeds[ruleID] = newNodePolicyLastRealized()
		priorities[ruleID] = genPriority(rule)

		serviceIPTChain, serviceIPTRuleTarget, coreIPTRuleTarget, singleService := genIPTInfoFromRule(rule)
		if serviceIPTChain != "" {
			serviceIPTChains[ruleID] = serviceIPTChain
			serviceIPTRuleTargets[ruleID] = serviceIPTRuleTarget
		}
		coreIPTRuleTargets[ruleID] = coreIPTRuleTarget
		if singleService != nil {
			singleServices[ruleID] = singleService
		}
	}

	for _, ipProtocol := range r.ipProtocols {
		isIPv6 := iptables.IsIPv6Protocol(ipProtocol)
		ipsets := make(map[string]string) // ruleID -> ipset name

		// Create ipsets for all rules and cache the ipset names.
		for _, rule := range rulesToInstall {
			ruleID := rule.ID

			ipsetName := genIPSetName(ruleID, isIPv6)
			ipsetEntries := getIPSetEntries(rule, isIPv6)
			if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPSet(ipsetName, ipsetEntries, isIPv6); err != nil {
				return err
			}

			// Update the lastRealized after adding ipset for the rule.
			lastRealizeds[ruleID].ipsets[ipProtocol] = ipsetName
			ipsets[ruleID] = ipsetName
		}

		var allIPTChainsToAdd []string  // allIPTChainsToAdd is used to store all iptables chains to add.
		var allIPTRulesToAdd [][]string // allIPTRulesToAdd is used to store all iptables rules to add.

		if len(serviceIPTChains) > 0 {
			// Get all iptables chains and iptables rules for services of all rules.
			serviceIPTChainsToAdd, serviceIPTRulesToAdd := buildAllServiceIPTRules(rulesToInstall,
				serviceIPTChains,
				serviceIPTRuleTargets,
				ipProtocol)
			// Add the iptables chains and rules to `allIPTChainsToAdd` and `allIPTRulesToAdd` respectively.
			allIPTChainsToAdd = append(allIPTChainsToAdd, serviceIPTChainsToAdd...)
			allIPTRulesToAdd = append(allIPTRulesToAdd, serviceIPTRulesToAdd...)
		}

		if len(ingressRulesToInstall) > 0 {
			coreIPTRulesToCache, coreIPTRulesToAdd := buildCoreIPTRules(ipProtocol,
				ingressRulesToInstall,
				priorities,
				ipsets,
				coreIPTRuleTargets,
				singleServices,
				config.NodeNetworkPolicyIngressRulesChain,
				true)
			// Append the chain name `ANTREA-POL-INGRESS-RULES` to `allIPTChainsToAdd` since the rules will be installed
			// in this chain and append the core iptables rules for the ingress rules to `allIPTRulesToAdd`.
			allIPTChainsToAdd = append(allIPTChainsToAdd, config.NodeNetworkPolicyIngressRulesChain)
			allIPTRulesToAdd = append(allIPTRulesToAdd, coreIPTRulesToAdd)

			// Cache the core iptables rules for ingress rules.
			cachedCoreIPTChain := r.cachedCoreIPTChains[genCacheCategory(config.NodeNetworkPolicyIngressRulesChain, isIPv6)]
			cachedCoreIPTChain.rules = coreIPTRulesToCache
		}

		if len(egressRulesToInstall) > 0 {
			coreIPTRulesToCache, coreIPTRulesToAdd := buildCoreIPTRules(ipProtocol,
				egressRulesToInstall,
				priorities,
				ipsets,
				coreIPTRuleTargets,
				singleServices,
				config.NodeNetworkPolicyEgressRulesChain,
				false)
			// Append the chain name `ANTREA-POL-EGRESS-RULES` to `allIPTChainsToAdd` since the rules will be installed
			// in this chain and append the core iptables rules for the egress rules to `allIPTRulesToAdd`.
			allIPTChainsToAdd = append(allIPTChainsToAdd, config.NodeNetworkPolicyEgressRulesChain)
			allIPTRulesToAdd = append(allIPTRulesToAdd, coreIPTRulesToAdd)

			// Cache the core iptables rules for egress rules.
			cachedCoreIPTChain := r.cachedCoreIPTChains[genCacheCategory(config.NodeNetworkPolicyEgressRulesChain, isIPv6)]
			cachedCoreIPTChain.rules = coreIPTRulesToCache
		}

		// Add all iptables chains and rules.
		if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPTables(allIPTChainsToAdd, allIPTRulesToAdd, isIPv6); err != nil {
			return err
		}
	}

	// Update all lastRealizeds.
	for _, rule := range rulesToInstall {
		ruleID := rule.ID
		lastRealized := lastRealizeds[ruleID]
		lastRealized.priority = priorities[ruleID]
		lastRealized.coreIPTChain = getCoreIPTRuleChain(rule)
		if serviceIPTChain, exists := serviceIPTChains[ruleID]; exists {
			lastRealized.multipleServices = true
			lastRealized.serviceIPTChain = serviceIPTChain
		}
		r.lastRealizeds.Store(ruleID, lastRealized)
	}
	return nil
}

func (r *nodeReconciler) Forget(ruleID string) error {
	klog.InfoS("Forgetting rule", "rule", ruleID)

	value, exists := r.lastRealizeds.Load(ruleID)
	if !exists {
		return nil
	}

	lastRealized := value.(*nodePolicyLastRealized)
	coreIPTChain := lastRealized.coreIPTChain

	for _, ipProtocol := range r.ipProtocols {
		isIPv6 := iptables.IsIPv6Protocol(ipProtocol)
		if err := r.deleteCoreIPRule(ruleID, coreIPTChain, isIPv6); err != nil {
			return err
		}
		if err := r.routeClient.DeleteNodeNetworkPolicyIPSet(lastRealized.ipsets[ipProtocol], isIPv6); err != nil {
			return err
		}
		if lastRealized.multipleServices {
			if err := r.routeClient.DeleteNodeNetworkPolicyIPTables([]string{lastRealized.serviceIPTChain}, isIPv6); err != nil {
				return err
			}
		}
	}

	r.lastRealizeds.Delete(ruleID)
	return nil
}

func (r *nodeReconciler) GetRuleByFlowID(ruleFlowID uint32) (*types.PolicyRule, bool, error) {
	return nil, false, nil
}

func (r *nodeReconciler) update(lastRealized *nodePolicyLastRealized, rule *CompletedRule) error {
	for _, ipProtocol := range r.ipProtocols {
		isIPv6 := iptables.IsIPv6Protocol(ipProtocol)

		ipsetName := lastRealized.ipsets[ipProtocol]
		ipsetEntries := getIPSetEntries(rule, isIPv6)
		if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPSet(ipsetName, ipsetEntries, isIPv6); err != nil {
			return err
		}
	}

	r.lastRealizeds.Store(rule.ID, lastRealized)
	return nil
}

func genIPTInfoFromRule(rule *CompletedRule) (string, string, string, *v1beta2.Service) {
	var serviceIPTRuleChain, serviceIPTRuleTarget, coreIPTRuleTarget string
	var singService *v1beta2.Service
	ruleID := rule.ID

	if len(rule.Services) > 1 {
		// If a rule has multiple services, create a chain to install iptables rules for these services, with the target
		// of the services determined by the rule's action. The core iptables rule should target the chain.
		serviceIPTRuleChain = genServiceIPTRuleChain(ruleID)
		serviceIPTRuleTarget = ruleActionToIPTTarget(rule.Action)
		coreIPTRuleTarget = serviceIPTRuleChain
	} else {
		// If a rule has no or single service, the target is determined by the rule's action, as there is no need to create
		// a chain for a single-service iptables rule.
		coreIPTRuleTarget = ruleActionToIPTTarget(rule.Action)
		// If a rule has single service, the core iptables rule directly incorporates the service.
		if len(rule.Services) == 1 {
			singService = &rule.Services[0]
		}
	}
	return serviceIPTRuleChain, serviceIPTRuleTarget, coreIPTRuleTarget, singService
}

func (r *nodeReconciler) add(rule *CompletedRule) error {
	ruleID := rule.ID
	lastRealized := newNodePolicyLastRealized()
	priority := genPriority(rule)

	serviceIPTChain, serviceIPTRuleTarget, coreIPTRuleTarget, singleService := genIPTInfoFromRule(rule)
	coreIPTChain := getCoreIPTRuleChain(rule)
	coreIPTRuleComment := genCoreIPTRuleComment(ruleID, rule.SourceRef.ToString())

	for _, ipProtocol := range r.ipProtocols {
		isIPv6 := iptables.IsIPv6Protocol(ipProtocol)

		ipsetName := genIPSetName(ruleID, isIPv6)
		ipsetEntries := getIPSetEntries(rule, isIPv6)
		if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPSet(ipsetName, ipsetEntries, isIPv6); err != nil {
			return err
		}

		// Update the lastRealized after adding ipset for the rule.
		lastRealized.ipsets[ipProtocol] = ipsetName

		// Build and synchronize service iptables rules if multiple services exist in this rule. Caching is unnecessary,
		// as the modification of services in a rule results in a different rule ID, treated as a new rule for installation.
		if serviceIPTChain != "" {
			serviceIPTRules := buildServiceIPTRules(ipProtocol,
				rule.Services,
				serviceIPTChain,
				serviceIPTRuleTarget)

			if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{serviceIPTChain},
				[][]string{serviceIPTRules},
				isIPv6); err != nil {
				return err
			}
		}

		// Build the core iptables rule and synchronize it.
		coreIPTRule := buildCoreIPTRule(ipProtocol,
			coreIPTChain,
			ipsetName,
			coreIPTRuleTarget,
			coreIPTRuleComment,
			singleService,
			rule.Direction == v1beta2.DirectionIn)
		if err := r.addCoreIPTRule(rule.ID, priority, coreIPTChain, coreIPTRule, isIPv6); err != nil {
			return err
		}
	}

	lastRealized.priority = priority
	lastRealized.coreIPTChain = coreIPTChain
	if serviceIPTChain != "" {
		lastRealized.multipleServices = true
		lastRealized.serviceIPTChain = serviceIPTChain
	}
	r.lastRealizeds.Store(ruleID, lastRealized)
	return nil
}

func (r *nodeReconciler) addCoreIPTRule(ruleID string, priority *types.Priority, iptChain, iptRuleStr string, isIPv6 bool) error {
	cachedCoreIPTChain := r.getCachedCoreIPTChain(iptChain, isIPv6)
	cachedCoreIPTChain.Lock()
	defer cachedCoreIPTChain.Unlock()

	// Get all cached iptables rules, then insert the new rule and sort all iptables rules.
	cachedIPTRules := cachedCoreIPTChain.rules
	cachedIPTRules = append(cachedIPTRules, &iptRule{
		ruleID:   ruleID,
		priority: priority,
		ruleStr:  iptRuleStr,
	})
	sort.Slice(cachedIPTRules, func(i, j int) bool {
		return cachedIPTRules[i].priority.Less(*cachedIPTRules[j].priority)
	})

	// Get all the sorted iptables rules and synchronize them.
	var iptRuleStrs []string
	for _, r := range cachedIPTRules {
		iptRuleStrs = append(iptRuleStrs, r.ruleStr)
	}
	if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{iptChain}, [][]string{iptRuleStrs}, isIPv6); err != nil {
		return err
	}

	// cache the new iptables rules.
	cachedCoreIPTChain.rules = cachedIPTRules
	return nil
}

func (r *nodeReconciler) deleteCoreIPRule(ruleID string, iptChain string, isIPv6 bool) error {
	cachedCoreIPTChain := r.getCachedCoreIPTChain(iptChain, isIPv6)
	cachedCoreIPTChain.Lock()
	defer cachedCoreIPTChain.Unlock()

	// Get all cached iptables rules, then delete the rule with the given ruleID.
	cachedIPTRules := cachedCoreIPTChain.rules
	var indexToDelete int
	for i := 0; i < len(cachedIPTRules); i++ {
		if cachedIPTRules[i].ruleID == ruleID {
			indexToDelete = i
			break
		}
	}
	cachedIPTRules = append(cachedIPTRules[:indexToDelete], cachedIPTRules[indexToDelete+1:]...)

	// Get all the sorted iptables rules and synchronize them.
	var iptRuleStrs []string
	for _, r := range cachedIPTRules {
		iptRuleStrs = append(iptRuleStrs, r.ruleStr)
	}
	if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{iptChain}, [][]string{iptRuleStrs}, isIPv6); err != nil {
		return err
	}

	// cache the new iptables rules.
	cachedCoreIPTChain.rules = cachedIPTRules
	return nil
}

func (r *nodeReconciler) getCachedCoreIPTChain(iptChain string, isIPv6 bool) *iptChainCache {
	// There are 4 categories of cached core iptables rules:
	// - For IPv4, iptables rules installed in chain ANTREA-INGRESS-RULES for ingress rules.
	// - For IPv6, ip6tables rules installed in chain ANTREA-INGRESS-RULES for ingress rules.
	// - For IPv4, iptables rules installed in chain ANTREA-EGRESS-RULES for egress rules.
	// - For IPv6, ip6tables rules installed in chain ANTREA-EGRESS-RULES for egress rules.
	categoryKey := genCacheCategory(iptChain, isIPv6)
	return r.cachedCoreIPTChains[categoryKey]
}

func groupMembersToIPNets(groups v1beta2.GroupMemberSet, isIPv6 bool) sets.Set[string] {
	ipNets := sets.New[string]()
	suffix := "/32"
	if isIPv6 {
		suffix = "/128"
	}
	for _, member := range groups {
		for _, ip := range member.IPs {
			ipAddr := net.IP(ip)
			if isIPv6 == utilnet.IsIPv6(ipAddr) {
				ipNets.Insert(ipAddr.String() + suffix)
			}
		}
	}
	return ipNets
}

func ipBlocksToIPNets(ipBlocks []v1beta2.IPBlock, isIPv6 bool) sets.Set[string] {
	ipNets := sets.New[string]()
	for _, b := range ipBlocks {
		blockCIDR := ip.IPNetToNetIPNet(&b.CIDR)
		if isIPv6 != utilnet.IsIPv6CIDR(blockCIDR) {
			continue
		}
		exceptIPNets := make([]*net.IPNet, 0, len(b.Except))
		for i := range b.Except {
			c := b.Except[i]
			except := ip.IPNetToNetIPNet(&c)
			exceptIPNets = append(exceptIPNets, except)
		}
		diffCIDRs, err := ip.DiffFromCIDRs(blockCIDR, exceptIPNets)
		if err != nil {
			klog.ErrorS(err, "Error when computing effective CIDRs by removing except IPNets from IPBlock")
			continue
		}
		for _, d := range diffCIDRs {
			ipNets.Insert(d.String())
		}
	}
	return ipNets
}

func getIPSetEntries(rule *CompletedRule, isIPv6 bool) sets.Set[string] {
	if rule.Direction == v1beta2.DirectionIn {
		from1 := groupMembersToIPNets(rule.FromAddresses, isIPv6)
		from2 := ipBlocksToIPNets(rule.From.IPBlocks, isIPv6)
		return from1.Union(from2)
	} else {
		to1 := groupMembersToIPNets(rule.ToAddresses, isIPv6)
		to2 := ipBlocksToIPNets(rule.To.IPBlocks, isIPv6)
		return to1.Union(to2)
	}
}

func getCoreIPTRuleChain(rule *CompletedRule) string {
	if rule.Direction == v1beta2.DirectionIn {
		return config.NodeNetworkPolicyIngressRulesChain
	}
	return config.NodeNetworkPolicyEgressRulesChain
}

func buildCoreIPTRule(ipProtocol iptables.Protocol, iptChain, ipset, iptRuleTarget, iptRuleComment string, service *v1beta2.Service, isIngress bool) string {
	builder := iptables.NewRuleBuilder(iptChain)
	if isIngress {
		builder = builder.MatchIPSetSrc(ipset)
	} else {
		builder = builder.MatchIPSetDst(ipset)
	}
	if service != nil {
		transProtocol := genServiceTransProtocol(service.Protocol)
		switch transProtocol {
		case "tcp":
			fallthrough
		case "udp":
			fallthrough
		case "sctp":
			builder = builder.MatchTransProtocol(transProtocol).
				MatchSrcPort(service.SrcPort, service.SrcEndPort).
				MatchDstPort(service.Port, service.EndPort)
		case "icmp":
			builder = builder.MatchICMP(service.ICMPType, service.ICMPCode, ipProtocol)
		}
	}
	return builder.SetTarget(iptRuleTarget).
		SetComment(iptRuleComment).
		Done().
		GetRule()
}

func buildServiceIPTRules(ipProtocol iptables.Protocol, services []v1beta2.Service, iptChain string, iptRuleTarget string) []string {
	var rules []string
	builder := iptables.NewRuleBuilder(iptChain)
	for _, svc := range services {
		copiedBuilder := builder.CopyBuilder()
		transProtocol := genServiceTransProtocol(svc.Protocol)
		switch transProtocol {
		case "tcp":
			fallthrough
		case "udp":
			fallthrough
		case "sctp":
			copiedBuilder = copiedBuilder.MatchTransProtocol(transProtocol).
				MatchSrcPort(svc.SrcPort, svc.SrcEndPort).
				MatchDstPort(svc.Port, svc.EndPort)
		case "icmp":
			copiedBuilder = copiedBuilder.MatchICMP(svc.ICMPType, svc.ICMPCode, ipProtocol)
		}
		rules = append(rules, copiedBuilder.SetTarget(iptRuleTarget).
			Done().
			GetRule())
	}
	return rules
}

func buildAllServiceIPTRules(rules []*CompletedRule,
	serviceIPTChains map[string]string,
	serviceIPTRuleTargets map[string]string,
	ipProtocol iptables.Protocol) ([]string, [][]string) {
	var iptRules [][]string
	var iptChains []string
	for _, rule := range rules {
		if serviceIPTRuleChain, exist := serviceIPTChains[rule.ID]; exist {
			serviceIPTRuleTarget := serviceIPTRuleTargets[rule.ID]
			iptRule := buildServiceIPTRules(ipProtocol, rule.Services, serviceIPTRuleChain, serviceIPTRuleTarget)
			iptRules = append(iptRules, iptRule)
			iptChains = append(iptChains, serviceIPTRuleChain)
		}
	}
	return iptChains, iptRules
}

func buildCoreIPTRules(ipProtocol iptables.Protocol,
	rules []*CompletedRule,
	priorities map[string]*types.Priority,
	ipsetNameMap map[string]string,
	ruleTargetMap map[string]string,
	singleServiceMap map[string]*v1beta2.Service,
	iptChain string,
	isIngress bool) ([]*iptRule, []string) {
	var iptRules []*iptRule
	for _, rule := range rules {
		ruleID := rule.ID

		ipsetName := ipsetNameMap[ruleID]
		iptRuleTarget := ruleTargetMap[ruleID]
		iptRuleComment := genCoreIPTRuleComment(ruleID, rule.SourceRef.ToString())
		iptRuleStr := buildCoreIPTRule(ipProtocol, iptChain, ipsetName, iptRuleTarget, iptRuleComment, singleServiceMap[ruleID], isIngress)
		iptRules = append(iptRules, &iptRule{
			ruleID:   ruleID,
			priority: priorities[ruleID],
			ruleStr:  iptRuleStr,
		})
	}

	sort.Slice(iptRules, func(i, j int) bool {
		return iptRules[i].priority.Less(*iptRules[j].priority)
	})

	var iptRuleStrs []string
	for _, iptRule := range iptRules {
		iptRuleStrs = append(iptRuleStrs, iptRule.ruleStr)
	}

	return iptRules, iptRuleStrs
}

func genServiceIPTRuleChain(ruleID string) string {
	return fmt.Sprintf("%s-%s", prefix, strings.ToUpper(ruleID))
}

func genIPSetName(ruleID string, isIPv6 bool) string {
	suffix := "4"
	if isIPv6 {
		suffix = "6"
	}
	return fmt.Sprintf("%s-%s-%s", prefix, strings.ToUpper(ruleID), suffix)
}

func ruleActionToIPTTarget(ruleAction *secv1beta1.RuleAction) string {
	var target string
	switch *ruleAction {
	case secv1beta1.RuleActionDrop:
		target = iptables.DropTarget
	case secv1beta1.RuleActionReject:
		target = iptables.RejectTarget
	case secv1beta1.RuleActionAllow:
		target = iptables.AcceptTarget
	default:
		klog.InfoS("Unknown rule action", "action", ruleAction)
	}
	return target
}

func genServiceTransProtocol(protocol *v1beta2.Protocol) string {
	if protocol == nil {
		return "tcp"
	}
	return strings.ToLower(string(*protocol))
}

func genPriority(rule *CompletedRule) *types.Priority {
	if rule == nil {
		return nil
	}
	return &types.Priority{
		TierPriority:   *rule.TierPriority,
		PolicyPriority: *rule.PolicyPriority,
		RulePriority:   rule.Priority,
	}
}

func genCoreIPTRuleComment(ruleID, policyName string) string {
	return fmt.Sprintf("Antrea: for rule %s, policy %s", ruleID, policyName)
}

func genCacheCategory(chain string, isIPv6 bool) string {
	if isIPv6 {
		return fmt.Sprintf("%s_6", chain)
	}
	return fmt.Sprintf("%s_4", chain)
}
