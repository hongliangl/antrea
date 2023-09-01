package networkpolicy

import (
	"antrea.io/antrea/pkg/agent/controller/networkpolicy/bmengine"
	"antrea.io/antrea/pkg/agent/types"
	"k8s.io/klog/v2"
	"sync"
)

type bmReconciler struct {
	client bmengine.Client

	lastRealizeds sync.Map
}

func (r *bmReconciler) Reconcile(rule *CompletedRule) error {
	klog.InfoS("Reconciling NetworkPolicy rule", "rule", rule.ID, "policy", rule.SourceRef.ToString())

	value, exists := r.lastRealizeds.Load(rule.ID)

	var err error
	if !exists {
		err = r.client.InstallPolicyRule(r.computeBMRuleForAdd(rule))
	} else {
		err = r.client.UpdatePolicyRule(value.(*types.BMPolicyRule), r.computeBMRuleForAdd(rule))
	}
	return err
}

func (r *bmReconciler) RunIDAllocatorWorker(stopCh <-chan struct{}) {

}

func (r *bmReconciler) BatchReconcile(rules []*CompletedRule) error {
	for _, rule := range rules {
		if err := r.client.InstallPolicyRule(r.computeBMRuleForAdd(rule)); err != nil {
			return err
		}
	}
	return nil
}

func (r *bmReconciler) Forget(ruleID string) error {

	return nil
}

func (r *bmReconciler) GetRuleByFlowID(ruleFlowID uint32) (*types.PolicyRule, bool, error) {
	return nil, false, nil
}

func (r *bmReconciler) computeBMRuleForAdd(rule *CompletedRule) *types.BMPolicyRule {
	priority := &types.Priority{
		TierPriority:   *rule.TierPriority,
		PolicyPriority: *rule.PolicyPriority,
		RulePriority:   rule.Priority,
	}

	policyRule := &types.BMPolicyRule{
		Direction:     rule.Direction,
		To:            rule.ToAddressesMap,
		From:          rule.FromAddressesMap,
		Service:       rule.Services,
		L7Protocols:   rule.L7Protocols,
		Action:        rule.Action,
		Priority:      priority,
		Name:          rule.Name,
		PolicyRef:     rule.SourceRef,
		EnableLogging: rule.EnableLogging,
		LogLabel:      rule.LogLabel,
	}

	return policyRule
}

func (r *bmReconciler) add(rule *CompletedRule) error {
	iptRule := r.computeBMRuleForAdd(rule)
	if err := r.client.InstallPolicyRule(iptRule); err != nil {
		return err
	}
	r.lastRealizeds.Store(rule.Name, rule)
	return nil
}

func (r *bmReconciler) update(prevRule, curRule *CompletedRule) error {
	return nil
}
