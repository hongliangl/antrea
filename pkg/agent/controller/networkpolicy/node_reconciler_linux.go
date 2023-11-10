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
   - Matches an ipset created for the NodeNetworkPolicy rule as source (ingress) or destination (egress) when there are
     multiple IP addresses; if there is only one address, matches the address directly.
   - Targets an action (the rule with single service) or a service chain created for the NodeNetworkPolicy rule (the rule
     with multiple services).
2. Service iptables chain:
   - Created for the NodeNetworkPolicy rule to integrate service iptables rules if a rule has multiple services.
3. Service iptables rules:
   - Added to the service chain created for the NodeNetworkPolicy rule.
   - Constructed from the services of the NodeNetworkPolicy rule.
4. From/To ipset:
   - Created for the NodeNetworkPolicy rule, containing all source IP addresses (ingress) or destination IP addresses (egress).

Assuming four ingress NodeNetworkPolicy rules with IDs 1111, 2222, 3333 and 4444 prioritized in descending order.
Core iptables rules organized by priorities in ANTREA-POL-INGRESS-RULES like the following.

If the rule has multiple source IP addresses to match, then an ipset will be created for it. The name of the ipset consists
of prefix "ANTREA-POL", rule ID and IP protocol version.

If the rule has multiple services, an iptables chain and related rules will be created for it. The name the chain consists
of prefix "ANTREA-POL" and rule ID.

```
:ANTREA-POL-INGRESS-RULES
-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-1111-4 src -j ANTREA-POL-1111 -m comment --comment "Antrea: for rule 1111, policy AntreaClusterNetworkPolicy:name1"
-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-2222-4 src -p tcp --dport 8080 -j ACCEPT -m comment --comment "Antrea: for rule 2222, policy AntreaClusterNetworkPolicy:name2"
-A ANTREA-POL-INGRESS-RULES -s 3.3.3.3/32 src -j ANTREA-POL-3333 -m comment --comment "Antrea: for rule 3333, policy AntreaClusterNetworkPolicy:name3"
-A ANTREA-POL-INGRESS-RULES -s 4.4.4.4/32 -p tcp --dport 80 -j ACCEPT -m comment --comment "Antrea: for rule 4444, policy AntreaClusterNetworkPolicy:name4"
```

For the first rule, it has multiple services and multiple source IP addresses to match, so there will be service iptables chain
and service iptables rules and ipset created for it.

The iptables chain is like the following:

```
:ANTREA-POL-1111
-A ANTREA-POL-1111 -j ACCEPT -p tcp --dport 80
-A ANTREA-POL-1111 -j ACCEPT -p tcp --dport 443
```

The ipset is like the following:

```
Name: ANTREA-POL-1111-4
Type: hash:net
Revision: 6
Header: family inet hashsize 1024 maxelem 65536
Size in memory: 472
References: 1
Number of entries: 2
Members:
1.1.1.1
1.1.1.2
```

For the second rule, it has only one service, so there will be no service iptables chain and service iptables rules created
for it. The core rule will match the service and target the action directly. The rule has multiple source IP addresses to
match, so there will be an ipset `ANTREA-POL-2222-4` created for it.

For the third rule, it has multiple services to match, so there will be service iptables chain and service iptables rules
created for it. The rule has only one source IP address to match, so there will be no ipset created for it and just match
the source IP address directly.

For the fourth rule, it has only one service and one source IP address to match, so there will be no service iptables chain
and service iptables rules created for it. The core rule will match the service and source IP address and target the action
directly.
*/

// coreIPTRule is a struct to cache the core iptables rules to guarantee the order of iptables rules.
type coreIPTRule struct {
	ruleID   string
	priority *types.Priority
	ruleStr  string
}

// coreIPTChain caches the sorted iptables rules and for a chain.
type coreIPTChain struct {
	rules []*coreIPTRule
	sync.Mutex
}

func newIPTChain() *coreIPTChain {
	return &coreIPTChain{}
}

// nodePolicyLastRealized is the struct cached by nodeReconciler. It's used to track the actual state of iptables rules
// and chains we have enforced, so that we can know how to reconcile a rule when it's updated/removed.
type nodePolicyLastRealized struct {
	// ipsets tracks the last realized ipset names used in core iptables rules. It cannot coexist with ipNets.
	ipsets map[iptables.Protocol]string
	// ipNets tracks the last realized ipNet used in core iptables rules. It cannot coexist with ipsets.
	ipNets map[iptables.Protocol]string
	// serviceIPTChain tracks the last realized service iptables chain if multipleServices is true.
	serviceIPTChain string
	// coreIPTChain tracks the last realized iptables chain where the core iptables rule is installed.
	coreIPTChain string
}

func newNodePolicyLastRealized() *nodePolicyLastRealized {
	return &nodePolicyLastRealized{
		ipsets: make(map[iptables.Protocol]string),
		ipNets: make(map[iptables.Protocol]string),
	}
}

type nodeReconciler struct {
	ipProtocols         []iptables.Protocol
	routeClient         route.Interface
	cachedCoreIPTChains map[string]*coreIPTChain
	// lastRealizeds caches the last realized rules. It's a mapping from ruleID to *nodePolicyLastRealized.
	lastRealizeds sync.Map
}

func newNodeReconciler(routeClient route.Interface, ipv4Enabled, ipv6Enabled bool) *nodeReconciler {
	var ipProtocols []iptables.Protocol
	cachedCoreIPTChains := make(map[string]*coreIPTChain)
	if ipv4Enabled {
		ipProtocols = append(ipProtocols, iptables.ProtocolIPv4)
		cachedCoreIPTChains[genCacheCategory(config.NodeNetworkPolicyIngressRulesChain, false)] = newIPTChain()
		cachedCoreIPTChains[genCacheCategory(config.NodeNetworkPolicyEgressRulesChain, false)] = newIPTChain()
	}
	if ipv6Enabled {
		ipProtocols = append(ipProtocols, iptables.ProtocolIPv6)
		cachedCoreIPTChains[genCacheCategory(config.NodeNetworkPolicyIngressRulesChain, true)] = newIPTChain()
		cachedCoreIPTChains[genCacheCategory(config.NodeNetworkPolicyEgressRulesChain, true)] = newIPTChain()
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
	var rulesToInstall []*CompletedRule
	for _, rule := range rules {
		if _, exists := r.lastRealizeds.Load(rule.ID); exists {
			klog.ErrorS(nil, "Rule should not have been realized yet: initialization phase", "rule", rule.ID)
		} else {
			rulesToInstall = append(rulesToInstall, rule)
		}
	}
	if err := r.batchAdd(rulesToInstall); err != nil {
		return err
	}
	return nil
}

func (r *nodeReconciler) batchAdd(rules []*CompletedRule) error {
	lastRealizeds := make(map[string]*nodePolicyLastRealized)
	serviceIPTChains := make(map[iptables.Protocol][]string)
	serviceIPTRules := make(map[iptables.Protocol][][]string)
	ingressCoreIPTRules := make(map[iptables.Protocol][]*coreIPTRule)
	egressCoreIPTRules := make(map[iptables.Protocol][]*coreIPTRule)

	for _, rule := range rules {
		iptRules, lastRealized := r.computeIPTRules(rule)
		ruleID := rule.ID
		for ipProtocol, iptRule := range iptRules {
			// Sync all ipsets.
			if iptRule.IPSet != "" {
				if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPSet(iptRule.IPSet, iptRule.IPSetMembers, iptRule.IsIPv6); err != nil {
					return err
				}
			}
			// Collect all service iptables rules and chains.
			if iptRule.ServiceIPTChain != "" {
				serviceIPTChains[ipProtocol] = append(serviceIPTChains[ipProtocol], iptRule.ServiceIPTChain)
				serviceIPTRules[ipProtocol] = append(serviceIPTRules[ipProtocol], iptRule.ServiceIPTRules)
			}

			// Collect all core iptables rules.
			coreIPTRule := &coreIPTRule{ruleID, iptRule.Priority, iptRule.CoreIPTRule}
			if rule.Direction == v1beta2.DirectionIn {
				ingressCoreIPTRules[ipProtocol] = append(ingressCoreIPTRules[ipProtocol], coreIPTRule)
			} else {
				egressCoreIPTRules[ipProtocol] = append(egressCoreIPTRules[ipProtocol], coreIPTRule)
			}
		}
		lastRealizeds[ruleID] = lastRealized
	}
	for _, ipProtocol := range r.ipProtocols {
		isIPv6 := iptables.IsIPv6Protocol(ipProtocol)
		if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPTables(serviceIPTChains[ipProtocol], serviceIPTRules[ipProtocol], isIPv6); err != nil {
			return err
		}
		if err := r.addOrUpdateCoreIPTRules(ingressCoreIPTRules[ipProtocol], config.NodeNetworkPolicyIngressRulesChain, isIPv6, false); err != nil {
			return err
		}
		if err := r.addOrUpdateCoreIPTRules(egressCoreIPTRules[ipProtocol], config.NodeNetworkPolicyEgressRulesChain, isIPv6, false); err != nil {
			return err
		}
	}

	for ruleID, lastRealized := range lastRealizeds {
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
		if lastRealized.ipsets[ipProtocol] != "" {
			if err := r.routeClient.DeleteNodeNetworkPolicyIPSet(lastRealized.ipsets[ipProtocol], isIPv6); err != nil {
				return err
			}
		}
		if lastRealized.serviceIPTChain != "" {
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

func (r *nodeReconciler) computeIPTRules(rule *CompletedRule) (map[iptables.Protocol]*types.NodePolicyRule, *nodePolicyLastRealized) {
	ruleID := rule.ID
	lastRealized := newNodePolicyLastRealized()
	priority := genPriority(rule)

	var serviceIPTChain, serviceIPTRuleTarget, coreIPTRuleTarget string
	var service *v1beta2.Service
	if len(rule.Services) > 1 {
		// If a rule has multiple services, create a chain to install iptables rules for these services, with the target
		// of the services determined by the rule's action. The core iptables rule should target the chain.
		serviceIPTChain = genServiceIPTRuleChain(ruleID)
		serviceIPTRuleTarget = ruleActionToIPTTarget(rule.Action)
		coreIPTRuleTarget = serviceIPTChain
		lastRealized.serviceIPTChain = serviceIPTChain
	} else {
		// If a rule has no or single service, the target is determined by the rule's action, as there is no need to create
		// a chain for a single-service iptables rule.
		coreIPTRuleTarget = ruleActionToIPTTarget(rule.Action)
		// If a rule has single service, the core iptables rule directly incorporates the service.
		if len(rule.Services) == 1 {
			service = &rule.Services[0]
		}
	}
	coreIPTChain := getCoreIPTChain(rule)
	coreIPTRuleComment := genCoreIPTRuleComment(ruleID, rule.SourceRef.ToString())
	lastRealized.coreIPTChain = coreIPTChain

	nodePolicyRules := make(map[iptables.Protocol]*types.NodePolicyRule)
	for _, ipProtocol := range r.ipProtocols {
		isIPv6 := iptables.IsIPv6Protocol(ipProtocol)

		var serviceIPTRules []string
		if serviceIPTChain != "" {
			serviceIPTRules = buildServiceIPTRules(ipProtocol, rule.Services, serviceIPTChain, serviceIPTRuleTarget)
		}

		ipNets := getIPNetsFromRule(rule, isIPv6)
		var ipNet string
		var ipset string
		if ipNets.Len() > 1 {
			// If a rule matches multiple source or destination ipNets, create an ipset and use it in core iptables rule.
			ipset = genIPSetName(ruleID, isIPv6)
			lastRealized.ipsets[ipProtocol] = ipset
		} else if ipNets.Len() == 1 {
			// If a rule matches single source or destination, use it in core iptables rule directly.
			ipNet, _ = ipNets.PopAny()
			lastRealized.ipNets[ipProtocol] = ipNet
		}

		coreIPTRule := buildCoreIPTRule(ipProtocol,
			coreIPTChain,
			ipset,
			ipNet,
			coreIPTRuleTarget,
			coreIPTRuleComment,
			service,
			rule.Direction == v1beta2.DirectionIn)

		nodePolicyRules[ipProtocol] = &types.NodePolicyRule{
			IPSet:           ipset,
			IPSetMembers:    ipNets,
			IPNet:           ipNet,
			Priority:        priority,
			ServiceIPTChain: serviceIPTChain,
			ServiceIPTRules: serviceIPTRules,
			CoreIPTChain:    coreIPTChain,
			CoreIPTRule:     coreIPTRule,
			IsIPv6:          isIPv6,
		}
	}

	return nodePolicyRules, lastRealized
}

func (r *nodeReconciler) add(rule *CompletedRule) error {
	klog.V(2).InfoS("Adding new rule", "rule", rule)
	ruleID := rule.ID
	iptRules, lastRealized := r.computeIPTRules(rule)
	for _, iptRule := range iptRules {
		if iptRule.IPSet != "" {
			if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPSet(iptRule.IPSet, iptRule.IPSetMembers, iptRule.IsIPv6); err != nil {
				return err
			}
		}
		if iptRule.ServiceIPTChain != "" {
			if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{iptRule.ServiceIPTChain}, [][]string{iptRule.ServiceIPTRules}, iptRule.IsIPv6); err != nil {
				return err
			}
		}
		if err := r.addOrUpdateCoreIPTRules([]*coreIPTRule{{ruleID, iptRule.Priority, iptRule.CoreIPTRule}}, iptRule.CoreIPTChain, iptRule.IsIPv6, false); err != nil {
			return err
		}
	}
	r.lastRealizeds.Store(ruleID, lastRealized)
	return nil
}

func (r *nodeReconciler) update(lastRealized *nodePolicyLastRealized, newRule *CompletedRule) error {
	klog.V(2).InfoS("Updating existing rule", "rule", newRule)
	ruleID := newRule.ID
	newIPTRules, newLastRealized := r.computeIPTRules(newRule)

	for _, ipProtocol := range r.ipProtocols {
		iptRule := newIPTRules[ipProtocol]

		prevIPNet := lastRealized.ipNets[ipProtocol]
		ipNet := newLastRealized.ipNets[ipProtocol]
		prevIPSet := lastRealized.ipsets[ipProtocol]
		ipset := newLastRealized.ipsets[ipProtocol]

		if ipset != "" {
			if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPSet(iptRule.IPSet, iptRule.IPSetMembers, iptRule.IsIPv6); err != nil {
				return err
			}
		}
		if lastRealized.ipsets[ipProtocol] != "" && ipset == "" {
			if err := r.routeClient.DeleteNodeNetworkPolicyIPSet(lastRealized.ipsets[ipProtocol], iptRule.IsIPv6); err != nil {
				return err
			}
		}
		if prevIPSet != ipset || prevIPNet != ipNet {
			if err := r.addOrUpdateCoreIPTRules([]*coreIPTRule{{ruleID, iptRule.Priority, iptRule.CoreIPTRule}}, iptRule.CoreIPTChain, iptRule.IsIPv6, true); err != nil {
				return err
			}
		}
	}

	r.lastRealizeds.Store(ruleID, newLastRealized)
	return nil
}

func (r *nodeReconciler) addOrUpdateCoreIPTRules(iptRules []*coreIPTRule, iptChain string, isIPv6 bool, isUpdate bool) error {
	if len(iptRules) == 0 {
		return nil
	}

	cachedCoreIPTChain := r.getCachedCoreIPTChain(iptChain, isIPv6)
	cachedCoreIPTChain.Lock()
	defer cachedCoreIPTChain.Unlock()

	cachedIPTRules := cachedCoreIPTChain.rules
	if isUpdate {
		// Build a map to store the mapping of rule ID to rule to add.
		iptRulesToUpdate := make(map[string]*coreIPTRule)
		for _, iptRule := range iptRules {
			iptRulesToUpdate[iptRule.ruleID] = iptRule
		}
		// Iterate every existing rules. If an existing rule is in the iptRulesToUpdate map, replace it with the new rule.
		for index, iptRule := range cachedIPTRules {
			if _, exists := iptRulesToUpdate[iptRule.ruleID]; exists {
				cachedIPTRules[index] = iptRulesToUpdate[iptRule.ruleID]
			}
		}
	} else {
		// If these are new rules, append the new rules then sort all rules.
		cachedIPTRules = append(cachedIPTRules, iptRules...)
		sort.Slice(cachedIPTRules, func(i, j int) bool {
			return !cachedIPTRules[i].priority.Less(*cachedIPTRules[j].priority)
		})
	}

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

func (r *nodeReconciler) getCachedCoreIPTChain(iptChain string, isIPv6 bool) *coreIPTChain {
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

func getIPNetsFromRule(rule *CompletedRule, isIPv6 bool) sets.Set[string] {
	var set sets.Set[string]
	if rule.Direction == v1beta2.DirectionIn {
		set = groupMembersToIPNets(rule.FromAddresses, isIPv6)
		set = set.Union(ipBlocksToIPNets(rule.From.IPBlocks, isIPv6))
	} else {
		set = groupMembersToIPNets(rule.ToAddresses, isIPv6)
		set = set.Union(ipBlocksToIPNets(rule.To.IPBlocks, isIPv6))
	}
	if set.Has("0.0.0.0/0") || set.Has("::/0") {
		return nil
	}
	return set
}

func getCoreIPTChain(rule *CompletedRule) string {
	if rule.Direction == v1beta2.DirectionIn {
		return config.NodeNetworkPolicyIngressRulesChain
	}
	return config.NodeNetworkPolicyEgressRulesChain
}

func buildCoreIPTRule(ipProtocol iptables.Protocol,
	iptChain string,
	ipset string,
	ipNet string,
	iptRuleTarget string,
	iptRuleComment string,
	service *v1beta2.Service,
	isIngress bool) string {
	builder := iptables.NewRuleBuilder(iptChain)
	if isIngress {
		if ipset != "" {
			builder = builder.MatchIPSetSrc(ipset)
		} else if ipNet != "" {
			builder = builder.MatchCIDRSrc(ipNet)
		}
	} else {
		if ipset != "" {
			builder = builder.MatchIPSetDst(ipset)
		} else if ipNet != "" {
			builder = builder.MatchCIDRDst(ipNet)
		}
	}
	if service != nil {
		transProtocol := getServiceTransProtocol(service.Protocol)
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
		transProtocol := getServiceTransProtocol(svc.Protocol)
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

func getServiceTransProtocol(protocol *v1beta2.Protocol) string {
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
