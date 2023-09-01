package bmengine

import (
	"container/list"
	"fmt"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util/ipset"
	"antrea.io/antrea/pkg/agent/util/iptables"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	secv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

//TODO: FQDN support

const (
	ingressRuleChain = "ANTREA-INGRESS-RULE"
	egressRuleChain  = "ANTREA-EGRESS-RULE"
)

type positionAssigner struct {
	eleList list.List
	eleMap  map[positionKey]*list.Element
}

type positionKey struct {
	priority    types.Priority
	ruleName    string
	positionNum int
}

func (p *positionAssigner) allocateIfNotExist(priority types.Priority, ruleName string, positionNum int) int {
	key := positionKey{
		priority:    priority,
		ruleName:    ruleName,
		positionNum: positionNum,
	}

	if _, exists := p.eleMap[key]; !exists {
		ele := p.eleList.Front()
		for ele != nil {
			t := ele.Value.(positionKey).priority
			if t.Less(key.priority) {
				ele = ele.Next()
			} else {
				break
			}
		}
		if ele == nil {
			p.eleList.PushBack(key)
			p.eleMap[key] = p.eleList.Back()
		} else {
			p.eleList.InsertBefore(key, ele)
			p.eleMap[key] = ele.Prev()
		}
	}

	offset := 0
	for ele := p.eleList.Front(); ele != p.eleMap[key]; ele = ele.Next() {
		offset += ele.Value.(positionKey).positionNum
	}
	return offset + 1
}

func (p *positionAssigner) release(priority types.Priority, ruleName string, positionNum int) {
	key := positionKey{
		priority:    priority,
		ruleName:    ruleName,
		positionNum: positionNum,
	}
	if _, exists := p.eleMap[key]; !exists {
		klog.InfoS("The key does not exist", "key", key)
		return
	}

	p.eleList.Remove(p.eleMap[key])
}

type Client struct {
	iptablesClient     iptables.Interface
	ipsetClient        ipset.Interface
	ipv4Enabled        bool
	ipv6Enabled        bool
	ipProtocols        []iptables.Protocol
	positionAssigners  map[iptables.Protocol]*positionAssigner
	addressGroupCaches map[iptables.Protocol]addressGroupCacheMap
	ruleCaches         map[iptables.Protocol]ruleCacheMap
	syncLock           sync.Mutex
}

// ruleCacheMap stores ruleCacheItem for each rule.
type ruleCacheMap map[string]*ruleCacheItem

// ruleCacheItem contains sequential iptables entries for a rule.
type ruleCacheItem struct {
	priority          *types.Priority
	sequentialEntries []iptables.IPTablesEntry
}

// addressGroupCacheMap stores addressGroupItem for each address group.
type addressGroupCacheMap map[string]*addressGroupItem

// addressGroupItem contains reference count and associated ipsets.
type addressGroupItem struct {
	ref        int
	ipsetEntry *ipset.IPSetEntry
}

func NewClient(networkConfig *config.NetworkConfig,
	iptablesClient iptables.Interface,
	ipsetClient ipset.Interface) *Client {
	client := &Client{
		iptablesClient:     iptablesClient,
		ipsetClient:        ipsetClient,
		positionAssigners:  make(map[iptables.Protocol]*positionAssigner),
		addressGroupCaches: make(map[iptables.Protocol]addressGroupCacheMap),
		ruleCaches:         make(map[iptables.Protocol]ruleCacheMap),
	}
	if networkConfig.IPv4Enabled {
		client.ipProtocols = append(client.ipProtocols, iptables.ProtocolIPv4)
		client.ipv4Enabled = true
	}
	if networkConfig.IPv6Enabled {
		client.ipProtocols = append(client.ipProtocols, iptables.ProtocolIPv6)
		client.ipv6Enabled = true
	}
	return client
}

func genIPSetName(groupName string, ipProtocol iptables.Protocol) string {
	var ipProtoStr string
	if ipProtocol == iptables.ProtocolIPv4 {
		ipProtoStr = "IP"
	} else {
		ipProtoStr = "IP6"
	}
	return fmt.Sprintf("ANTREA-POLICY-%s-%s", strings.ToUpper(groupName), ipProtoStr)
}

func genIPTablesComment(ruleName string, priority *types.Priority) string {
	return fmt.Sprintf("Antrea: for NetworkPolicy rule %s, tier priority %d, policy priority %f, rule priority %d",
		ruleName, priority.TierPriority, priority.PolicyPriority, priority.RulePriority)
}

func genSequentialIPTablesEntryTargetChainName(ruleName string) string {
	return fmt.Sprintf("ANTREA-POLICY-%s", strings.ToUpper(ruleName))
}

func getNonSequentialIPTablesEntryTargetAction(ruleAction *secv1beta1.RuleAction) string {
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

func isIPv6Protocol(protocol iptables.Protocol) bool {
	return protocol == iptables.ProtocolIPv6
}

func (c *Client) InstallPolicyRule(rule *types.BMPolicyRule) error {
	var sequentialIPTablesEntryChain string
	var isIngress bool
	var addressGroupMap map[string]v1beta2.GroupMemberSet
	if rule.Direction == v1beta2.DirectionIn {
		sequentialIPTablesEntryChain = ingressRuleChain
		addressGroupMap = rule.From
		isIngress = true
	} else {
		sequentialIPTablesEntryChain = egressRuleChain
		addressGroupMap = rule.To
	}

	// Generate comment and targets for all iptables entries. Note that, the priority of rule is added to the comment, then
	// when the priority of a rule is changed only, stale iptables entries could be matched and deleted.
	iptablesComment := genIPTablesComment(rule.Name, rule.Priority)
	sequentialIPTablesEntryTarget := genSequentialIPTablesEntryTargetChainName(rule.Name)
	nonSequentialIPTablesEntryTarget := getNonSequentialIPTablesEntryTargetAction(rule.Action)

	for _, ipProtocol := range c.ipProtocols {
		// iptablesEntryBaseBuilder will be copied to build iptables entries.
		iptablesEntryBaseBuilder := iptables.NewEntryBuilder(c.iptablesClient, iptables.FilterTable, sequentialIPTablesEntryChain, ipProtocol).
			SetComment(iptablesComment)

		// Generate the sequential iptables entries builders. Note that, these iptables entries are not built completely,
		// so they are still called builders. The positions of the iptables entries are decided by the priority of the rule,
		// which will be allocated before syncing the iptables entries.
		sequentialIPTablesEntryBuilders := genSequentialIPTablesEntryBuilders(iptablesEntryBaseBuilder, ipProtocol, addressGroupMap, sequentialIPTablesEntryTarget, isIngress)
		// Generate a chain and non-sequential iptables entries. The entries will be installed in the chain.
		nonSequentialIPTablesEntryChain := iptables.NewIPTablesChain(c.iptablesClient, iptables.FilterTable, sequentialIPTablesEntryTarget, ipProtocol)
		nonSequentialIPTablesEntries := genNonSequentialIPTablesEntries(iptablesEntryBaseBuilder, ipProtocol, rule.Service, nonSequentialIPTablesEntryTarget)
		// Generate the ipsets used by the sequential iptables entries to match source or destination IP addresses.
		ipsetEntries := c.genIPSets(ipProtocol, addressGroupMap)

		err := func() error {
			c.syncLock.Lock()
			defer c.syncLock.Unlock()

			// Sync ipset entries.
			if err := c.syncIPSets(ipsetEntries, ipProtocol); err != nil {
				return err
			}
			// Sync iptables entries.
			if revertFunc, err := c.syncIPTables(ipProtocol,
				sequentialIPTablesEntryBuilders,
				nonSequentialIPTablesEntryChain,
				nonSequentialIPTablesEntries,
				rule.Priority,
				rule.Name); err != nil {
				revertFunc()
				return err
			}
			// Only update ipset cache after all iptables entries have been synced.
			c.updateIPSetCache(ipProtocol, ipsetEntries, nil, getAddressGroupNames(addressGroupMap), nil)

			return nil
		}()
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) UpdatePolicyRule(curRule, prevRule *types.BMPolicyRule) error {
	var sequentialIPTablesEntryChain string
	var isIngress bool
	var curAddressGroupMap, prevAddressGroupMap map[string]v1beta2.GroupMemberSet
	if curRule.Direction == v1beta2.DirectionIn {
		sequentialIPTablesEntryChain = ingressRuleChain
		curAddressGroupMap = curRule.From
		prevAddressGroupMap = prevRule.From
		isIngress = true
	} else {
		sequentialIPTablesEntryChain = egressRuleChain
		curAddressGroupMap = curRule.To
		prevAddressGroupMap = prevRule.To
	}

	var shouldUpdateSequentialIPTablesEntries, shouldUpdateNonSequentialIPTablesEntries bool
	curAddressGroupNames := getAddressGroupNames(curAddressGroupMap)
	prevAddressGroupNames := getAddressGroupNames(prevAddressGroupMap)
	// If the priority of the rule has been changed, the sequential iptables entries should be updated accordingly; if
	// the address groups used by the rule have been changed, the sequential iptables entries should be also updated
	// accordingly.
	if *curRule.Priority != *prevRule.Priority || !curAddressGroupNames.Equal(prevAddressGroupNames) {
		shouldUpdateSequentialIPTablesEntries = true
	}

	curServices := getServiceKeys(curRule.Service)
	prevServices := getServiceKeys(prevRule.Service)
	// If the services or action of the rule has been changed, the non-sequential iptables entries should be updated accordingly.
	if !curServices.Equal(prevServices) || curRule.Action != prevRule.Action {
		shouldUpdateNonSequentialIPTablesEntries = true
	}

	// Generate comment and targets for iptables entries. Note that, the priority of rule is added to the comment, then
	// when the priority of a rule is changed only, stale iptables entries could be matched and deleted.
	iptablesComment := genIPTablesComment(curRule.Name, curRule.Priority)
	sequentialIPTablesEntryTarget := genSequentialIPTablesEntryTargetChainName(curRule.Name)
	nonSequentialIPTablesEntryTarget := getNonSequentialIPTablesEntryTargetAction(curRule.Action)

	removedAddressGroupNames := prevAddressGroupNames.Difference(curAddressGroupNames)
	addedAddressGroupNames := curAddressGroupNames.Difference(prevAddressGroupNames)
	remainingAddressGroupNames := curAddressGroupNames.Intersection(prevAddressGroupNames)

	for _, ipProtocol := range c.ipProtocols {
		var nonSequentialIPTablesEntryChain iptables.IPTablesChain
		var sequentialIPTablesEntryBuilders []iptables.IPTablesEntryBuilder
		var nonSequentialIPTablesEntries []iptables.IPTablesEntry
		baseBuilder := iptables.NewEntryBuilder(c.iptablesClient, iptables.FilterTable, sequentialIPTablesEntryChain, ipProtocol).
			SetComment(iptablesComment)

		if shouldUpdateSequentialIPTablesEntries {
			// If sequential iptables entries should be updated, generate the sequential iptables entries builders with
			// current rule.
			sequentialIPTablesEntryBuilders = genSequentialIPTablesEntryBuilders(baseBuilder, ipProtocol, curAddressGroupMap, sequentialIPTablesEntryTarget, isIngress)
		}
		if shouldUpdateNonSequentialIPTablesEntries {
			// If non-sequential iptables entries should be updated, generate the chain and non-sequential entries with
			// current rule.
			nonSequentialIPTablesEntryChain = iptables.NewIPTablesChain(c.iptablesClient, iptables.FilterTable, sequentialIPTablesEntryTarget, ipProtocol)
			nonSequentialIPTablesEntries = genNonSequentialIPTablesEntries(baseBuilder, ipProtocol, curRule.Service, nonSequentialIPTablesEntryTarget)
		}
		// Generate the ipsets used by the sequential iptables entries to match source or destination IP addresses.
		ipsetEntries := c.genIPSets(ipProtocol, curAddressGroupMap)

		err := func() error {
			c.syncLock.Lock()
			defer c.syncLock.Unlock()

			// Sync the ipsets.
			if err := c.syncIPSets(ipsetEntries, ipProtocol); err != nil {
				return err
			}
			// Sync iptables entries.
			if revertFunc, err := c.syncIPTables(ipProtocol,
				sequentialIPTablesEntryBuilders,
				nonSequentialIPTablesEntryChain,
				nonSequentialIPTablesEntries,
				curRule.Priority,
				curRule.Name); err != nil {
				revertFunc()
				return err
			}
			// Only update ipset cache after all iptables entries have been synced.
			c.updateIPSetCache(ipProtocol, ipsetEntries, removedAddressGroupNames, addedAddressGroupNames, remainingAddressGroupNames)

			return nil
		}()
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) DeletePolicyRule(rule *types.BMPolicyRule) error {
	ruleName := rule.Name
	for _, ipProtocol := range c.ipProtocols {
		pa := c.positionAssigners[ipProtocol]
		nonSequentialIPTablesEntryChain := iptables.NewIPTablesChain(c.iptablesClient, iptables.FilterTable, genSequentialIPTablesEntryTargetChainName(ruleName), ipProtocol)

		err := func() error {
			c.syncLock.Lock()
			defer c.syncLock.Unlock()

			// Delete sequential iptables entries.
			ruleCache, exists := c.ruleCaches[ipProtocol][ruleName]
			if exists {
				for _, entry := range ruleCache.sequentialEntries {
					if err := entry.Delete(); err != nil {
						return err
					}
				}
				// release positions used by stale iptables entries.
				pa.release(*ruleCache.priority, ruleName, len(ruleCache.sequentialEntries))
			}
			// Clear the chain where installs non-sequential iptables entries then delete chain.
			if err := nonSequentialIPTablesEntryChain.Delete(); err != nil {
				return err
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func getAddressGroupNames(addressGroupMap map[string]v1beta2.GroupMemberSet) sets.Set[string] {
	s := sets.New[string]()
	for addressGroup := range addressGroupMap {
		s.Insert(addressGroup)
	}
	return s
}

func getServiceKeys(services []v1beta2.Service) sets.Set[string] {
	s := sets.New[string]()
	for _, svc := range services {
		key := svc.String()
		s.Insert(key)
	}
	return s
}

func genNonSequentialIPTablesEntries(baseBuilder iptables.IPTablesEntryBuilder,
	ipProtocol iptables.Protocol,
	services []v1beta2.Service,
	target string) []iptables.IPTablesEntry {
	entries := make([]iptables.IPTablesEntry, 0, len(services))
	for _, svc := range services {
		var iptablesEntry iptables.IPTablesEntry
		copiedBuilder := baseBuilder.CopyBuilder().SetTarget(target)
		transProtocol := *svc.Protocol
		switch transProtocol {
		case v1beta2.ProtocolTCP:
			fallthrough
		case v1beta2.ProtocolUDP:
			fallthrough
		case v1beta2.ProtocolSCTP:
			iptablesEntry = copiedBuilder.MatchTransProtocol(transProtocol).
				MatchSrcPort(svc.SrcPort, svc.SrcEndPort).
				MatchDstPort(svc.Port, svc.EndPort).
				Done()
		case v1beta2.ProtocolICMP:
			iptablesEntry = copiedBuilder.MatchICMP(svc.ICMPType, svc.ICMPCode, ipProtocol).
				Done()
		case v1beta2.ProtocolIGMP:
			iptablesEntry = copiedBuilder.MatchIGMP(svc.IGMPType, svc.GroupAddress).
				Done()
		}
		entries = append(entries, iptablesEntry)
	}
	return entries
}

func genSequentialIPTablesEntryBuilders(baseBuilder iptables.IPTablesEntryBuilder,
	ipProtocol iptables.Protocol,
	addressGroupMap map[string]v1beta2.GroupMemberSet,
	target string,
	isIngress bool) []iptables.IPTablesEntryBuilder {
	builders := make([]iptables.IPTablesEntryBuilder, 0, len(addressGroupMap))

	if len(addressGroupMap) > 0 {
		for groupName := range addressGroupMap {
			copiedBuilder := baseBuilder.CopyBuilder().SetTarget(target)
			ipsetName := genIPSetName(groupName, ipProtocol)
			if isIngress {
				copiedBuilder = copiedBuilder.MatchIPSetSrc(ipsetName)
			} else {
				copiedBuilder = copiedBuilder.MatchIPSetDst(ipsetName)
			}
			builders = append(builders, copiedBuilder)
		}
	} else {
		copiedBuilder := baseBuilder.CopyBuilder().SetTarget(target)
		builders = append(builders, copiedBuilder)
	}
	return builders
}

func (c *Client) genIPSets(ipProtocol iptables.Protocol, addressGroupMap map[string]v1beta2.GroupMemberSet) map[string]*ipset.IPSetEntry {
	isIPv6 := isIPv6Protocol(ipProtocol)
	entries := make(map[string]*ipset.IPSetEntry)

	for groupName, members := range addressGroupMap {
		ipsetName := genIPSetName(groupName, ipProtocol)
		entry := ipset.NewIPSet(c.ipsetClient, ipsetName, members, isIPv6)
		entries[groupName] = entry
	}
	return entries
}

func (c *Client) syncIPSets(ipsets map[string]*ipset.IPSetEntry, ipProtocol iptables.Protocol) error {
	for groupName, set := range ipsets {
		// If this ipset is not found in cache, which means that it is not synced, or it has been synced but its
		// members has been changed, sync the ipset.
		prevIPSetCache, exists := c.addressGroupCaches[ipProtocol][groupName]
		if exists && !prevIPSetCache.ipsetEntry.Same(set) || !exists {
			if err := set.Sync(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Client) syncOrderedIPTables(ipProtocol iptables.Protocol, entryBuilders []iptables.IPTablesEntryBuilder, rulePriority *types.Priority, ruleName string) (func(), error) {
	pa := c.positionAssigners[ipProtocol]
	entryNum := len(entryBuilders)
	syncedEntries := make([]iptables.IPTablesEntry, 0, entryNum)
	positionStart := pa.allocateIfNotExist(*rulePriority, ruleName, entryNum)
	revertFunc := func() {
		for _, entry := range syncedEntries {
			if err := entry.Delete(); err != nil {
				klog.ErrorS(err, "failed to revert the iptables entry", "entry", entry)
			}
		}
	}

	for i := 0; i < entryNum; i++ {
		// Set positions for the builders and complete iptables entry, then sync the iptables entry.
		entry := entryBuilders[i].SetPosition(positionStart + i).Done()
		if err := entry.Sync(); err != nil {
			return revertFunc, err
		}
		// Append the iptables entry to a slice which will be stored in cache.
		syncedEntries = append(syncedEntries, entry)
	}

	// If there are stale iptables entries, delete them.
	if ruleCache, exists := c.ruleCaches[ipProtocol][ruleName]; exists {
		for _, entry := range ruleCache.sequentialEntries {
			if err := entry.Delete(); err != nil {
				klog.ErrorS(err, "failed to delete the stale iptables entry", "entry", entry)
			}
		}
		// release positions used by stale iptables entries.
		pa.release(*ruleCache.priority, ruleName, len(ruleCache.sequentialEntries))
	} else {
		c.ruleCaches[ipProtocol][ruleName] = &ruleCacheItem{}
	}

	c.ruleCaches[ipProtocol][ruleName].priority = rulePriority
	c.ruleCaches[ipProtocol][ruleName].sequentialEntries = syncedEntries

	return nil, nil
}

func (c *Client) updateIPSetCache(ipProtocol iptables.Protocol, ipsetEntries map[string]*ipset.IPSetEntry, removedAddrGroups, addedAddrGroups, remainingAddrGroups sets.Set[string]) {
	// For new added entries, update references, members might be also updated if the entry has been added.
	// For remaining entries, don't update references, but members might be updated.
	// For entries to delete, update references, if references == 0, delete the ipset.

	var refToInc, refToDec []string
	var toUpdateIPSet map[string]*ipset.IPSetEntry
	for groupName, set := range ipsetEntries {
		if addedAddrGroups.Has(groupName) {
			refToInc = append(refToInc, groupName)
			cachedIPSet, exists := c.addressGroupCaches[ipProtocol][groupName]
			if exists && !cachedIPSet.ipsetEntry.Same(set) || !exists {
				toUpdateIPSet[groupName] = set
			}
			if !exists {
				c.addressGroupCaches[ipProtocol][groupName] = &addressGroupItem{}
			}
		} else if remainingAddrGroups.Has(groupName) {
			if !c.addressGroupCaches[ipProtocol][groupName].ipsetEntry.Same(set) {
				toUpdateIPSet[groupName] = set
			}
		} else if removedAddrGroups.Has(groupName) {
			refToDec = append(refToDec, groupName)
		}
	}
	for _, groupName := range refToInc {
		c.addressGroupCaches[ipProtocol][groupName].ref++
	}
	for _, groupName := range refToDec {
		c.addressGroupCaches[ipProtocol][groupName].ref--
		if c.addressGroupCaches[ipProtocol][groupName].ref == 0 {
			if err := c.addressGroupCaches[ipProtocol][groupName].ipsetEntry.Delete(); err != nil {
				klog.ErrorS(err, "failed to delete unused ipset")
			}
		}
		delete(c.addressGroupCaches[ipProtocol], groupName)
	}
	for groupName, set := range toUpdateIPSet {
		c.addressGroupCaches[ipProtocol][groupName].ipsetEntry = set
	}
}

func (c *Client) syncIPTables(ipProtocol iptables.Protocol,
	sequentialEntryBuilders []iptables.IPTablesEntryBuilder,
	nonSequentialEntryChain iptables.IPTablesChain,
	nonSequentialEntries []iptables.IPTablesEntry,
	rulePriority *types.Priority,
	ruleName string) (func(), error) {
	if nonSequentialEntries != nil {
		// Synchronize the chain where non-sequential iptables entries are installed. This method is idempotent as it will
		// either clear the chain if it has been created or create the chain if it doesn't exist.
		if err := nonSequentialEntryChain.Sync(); err != nil {
			return nil, err
		}
		// Synchronize the non-sequential iptables entries. The non-sequential iptables entries are used to match services
		// defined in NetworkPolicy. This part is also idempotent since the chain has been cleared before Synchronizing the
		// entries.
		for _, entry := range nonSequentialEntries {
			if err := entry.Sync(); err != nil {
				return nil, err
			}
		}
	}

	if sequentialEntryBuilders == nil {
		return nil, nil
	}

	pa := c.positionAssigners[ipProtocol]
	sequentialEntryBuilderNum := len(sequentialEntryBuilders)
	syncedSequentialEntries := make([]iptables.IPTablesEntry, 0, sequentialEntryBuilderNum)
	// Use rule priority, name and the number of sequential entry builders as a key to get the range of target positions
	// which are used to build entries from the entry builders.
	positionStart := pa.allocateIfNotExist(*rulePriority, ruleName, sequentialEntryBuilderNum)
	// This function is called to uninstall the synchronized entries and release the positions when getting an error with
	// installing a sequential entry. This revert function is to ensure that the method is idempotent.
	revertFunc := func() {
		for _, entry := range syncedSequentialEntries {
			if err := entry.Delete(); err != nil {
				klog.ErrorS(err, "failed to revert the iptables entry", "entry", entry)
			}
		}
		pa.release(*rulePriority, ruleName, sequentialEntryBuilderNum)
	}

	for i := 0; i < sequentialEntryBuilderNum; i++ {
		// Set position for every entry builder to generate an entry, then synchronize entry. The entry will be installed
		// at the target position.
		entry := sequentialEntryBuilders[i].SetPosition(positionStart + i).Done()
		if err := entry.Sync(); err != nil {
			return revertFunc, err
		}
		syncedSequentialEntries = append(syncedSequentialEntries, entry)
	}

	if ruleCache, exists := c.ruleCaches[ipProtocol][ruleName]; exists {
		// If there is cache for the rule, delete the stale entries.
		for _, entry := range ruleCache.sequentialEntries {
			if err := entry.Delete(); err != nil {
				klog.ErrorS(err, "failed to delete the stale iptables entry", "entry", entry)
			}
		}
		// release positions used by stale entries.
		pa.release(*ruleCache.priority, ruleName, len(ruleCache.sequentialEntries))
		// Update the cache
		c.ruleCaches[ipProtocol][ruleName].priority = rulePriority
		c.ruleCaches[ipProtocol][ruleName].sequentialEntries = syncedSequentialEntries
	} else {
		// If there is no cache for the rule, create it.
		c.ruleCaches[ipProtocol][ruleName] = &ruleCacheItem{
			priority:          rulePriority,
			sequentialEntries: syncedSequentialEntries,
		}
	}

	return nil, nil
}
