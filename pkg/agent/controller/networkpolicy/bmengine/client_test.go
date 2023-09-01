package bmengine

import (
	"antrea.io/antrea/pkg/agent/config"
	ipsetmock "antrea.io/antrea/pkg/agent/util/ipset/testing"
	iptablesmock "antrea.io/antrea/pkg/agent/util/iptables/testing"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	secv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"container/list"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/intstr"
	"net"
	"testing"

	"antrea.io/antrea/pkg/agent/types"
)

func TestPositionAssigner(t *testing.T) {
	pa := &positionAssigner{
		eleList: list.List{},
		eleMap:  make(map[positionKey]*list.Element),
	}
	p1 := types.Priority{TierPriority: 1, PolicyPriority: 2, RulePriority: 2}
	p2 := types.Priority{TierPriority: 1, PolicyPriority: 2, RulePriority: 3}
	p3 := types.Priority{TierPriority: 2, PolicyPriority: 1, RulePriority: 1}
	p4 := types.Priority{TierPriority: 2, PolicyPriority: 1, RulePriority: 1}
	p5 := types.Priority{TierPriority: 2, PolicyPriority: 2, RulePriority: 2}

	start := pa.allocateIfNotExist(p1, "p1", 2)
	assert.Equal(t, 1, start)

	start = pa.allocateIfNotExist(p2, "p2", 1)
	assert.Equal(t, 1, start)

	start = pa.allocateIfNotExist(p3, "p3", 2)
	assert.Equal(t, 1, start)

	start = pa.allocateIfNotExist(p4, "p4", 1)
	assert.Equal(t, 1, start)

	start = pa.allocateIfNotExist(p5, "p5", 3)
	assert.Equal(t, 1, start)

	start = pa.allocateIfNotExist(p1, "p1", 2)
	assert.Equal(t, 8, start)

	pa.release(p2, "p2", 1)
	start = pa.allocateIfNotExist(p1, "p1", 2)
	assert.Equal(t, 7, start)
}

func newAddressGroupMember(ips ...string) *v1beta2.GroupMember {
	ipAddrs := make([]v1beta2.IPAddress, len(ips))
	for idx, ip := range ips {
		ipAddrs[idx] = v1beta2.IPAddress(net.ParseIP(ip))
	}
	return &v1beta2.GroupMember{IPs: ipAddrs}
}

var (
	actionDrop  = secv1beta1.RuleActionDrop
	protocolTCP = v1beta2.ProtocolTCP
	protocolUDP = v1beta2.ProtocolUDP
	dstPort     = intstr.FromInt(80)
	endPort     = int32(80)

	member11 = newAddressGroupMember("10.10.10.1")
	member12 = newAddressGroupMember("10.10.10.2")
	member21 = newAddressGroupMember("10.10.20.1")
	member22 = newAddressGroupMember("10.10.20.2")
	svc1     = v1beta2.Service{Protocol: &protocolTCP, Port: &dstPort}
	svc2     = v1beta2.Service{Protocol: &protocolUDP, Port: &dstPort, EndPort: &endPort}
)

func TestInstallPolicyRule(t *testing.T) {
	testCases := []struct {
		name          string
		rule          *types.BMPolicyRule
		networkConfig *config.NetworkConfig
	}{
		{
			name: "IPv4 only",
			rule: &types.BMPolicyRule{
				Direction: v1beta2.DirectionIn,
				From: map[string]v1beta2.GroupMemberSet{
					"group1": v1beta2.NewGroupMemberSet(member11, member12),
					"group2": v1beta2.NewGroupMemberSet(member21, member22),
				},
				Service:  []v1beta2.Service{svc1, svc2},
				Action:   &actionDrop,
				Priority: &types.Priority{},
				Name:     "test-rule",
			},
			networkConfig: &config.NetworkConfig{IPv4Enabled: true},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPSetClient, mockIPTablesClient := getMockClients(ctrl)
			client := NewClient(tc.networkConfig, mockIPTablesClient, mockIPSetClient)
			assert.NoError(t, client.InstallPolicyRule(tc.rule))
		})
	}
}

func getMockClients(ctrl *gomock.Controller) (*ipsetmock.MockInterface, *iptablesmock.MockInterface) {
	mockIPSetClient := ipsetmock.NewMockInterface(ctrl)
	mockIPTablesClient := iptablesmock.NewMockInterface(ctrl)
	return mockIPSetClient, mockIPTablesClient
}
