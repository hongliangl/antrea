// Copyright 2022 Antrea Authors
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

package openflow

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/agent/config"
)

func Test_featureService_initFlows(t *testing.T) {
	testCases := []struct {
		name          string
		enableIPv4    bool
		enableIPv6    bool
		clientOptions []clientOptionsFn
		expectedFlows []string
	}{
		{
			name:          "IPv4,Proxy",
			enableIPv4:    true,
			clientOptions: []clientOptionsFn{enableProxy},
			expectedFlows: []string{
				"cookie=0x1030000000000, table=UnSNAT, priority=200,ip,nw_dst=169.254.0.253 actions=ct(table=ConntrackZone,zone=65521,exec(nat))",
				"cookie=0x1030000000000, table=UnSNAT, priority=200,ip,nw_dst=10.10.0.1 actions=ct(table=ConntrackZone,zone=65521,exec(nat))",
				"cookie=0x1030000000000, table=ConntrackState, priority=200,ct_state=-new+trk,ct_mark=0x10/0x10,ip actions=set_field:0x200/0x200->reg0,goto_table:AntreaPolicyEgressRule",
				"cookie=0x1030000000000, table=PreRoutingClassifier, priority=200,ip actions=resubmit:SessionAffinity,resubmit:ServiceLB",
				"cookie=0x1030000000000, table=SessionAffinity, priority=0 actions=set_field:0x10000/0x70000->reg4",
				"cookie=0x1030000000000, table=EndpointDNAT, priority=190,reg4=0x20000/0x70000 actions=set_field:0x10000/0x70000->reg4,resubmit:ServiceLB",
				"cookie=0x1030000000000, table=L3Forwarding, priority=190,ct_mark=0x10/0x10,reg0=0x202/0x20f actions=set_field:00:00:10:10:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1030000000000, table=SNATMark, priority=200,ct_state=+new+trk,ip,reg0=0x22/0xff actions=ct(commit,table=SNAT,zone=65520,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))",
				"cookie=0x1030000000000, table=SNATMark, priority=200,ct_state=+new+trk,ip,reg0=0x12/0xff,reg4=0x200000/0x200000 actions=ct(commit,table=SNAT,zone=65520,exec(set_field:0x20/0x20->ct_mark))",
				"cookie=0x1030000000000, table=SNAT, priority=200,ct_state=+new+trk,ct_mark=0x40/0x40,ip,reg0=0x2/0xf actions=ct(commit,table=L2ForwardingCalc,zone=65521,exec(nat(src=169.254.0.253),set_field:0x10/0x10->ct_mark,set_field:0x40/0x40->ct_mark))",
				"cookie=0x1030000000000, table=SNAT, priority=200,ct_state=+new+trk,ct_mark=0x40/0x40,ip,reg0=0x3/0xf actions=ct(commit,table=L2ForwardingCalc,zone=65521,exec(nat(src=10.10.0.1),set_field:0x10/0x10->ct_mark,set_field:0x40/0x40->ct_mark))",
				"cookie=0x1030000000000, table=SNAT, priority=190,ct_state=+new+trk,ct_mark=0x20/0x20,ip,reg0=0x2/0xf actions=ct(commit,table=L2ForwardingCalc,zone=65521,exec(nat(src=10.10.0.1),set_field:0x10/0x10->ct_mark))",
				"cookie=0x1030000000000, table=SNAT, priority=200,ct_state=-new-rpl+trk,ct_mark=0x20/0x20,ip actions=ct(table=L2ForwardingCalc,zone=65521,exec(nat))",
				"cookie=0x1030000000000, table=Output, priority=210,ct_mark=0x40/0x40 actions=IN_PORT",
			},
		},
		{
			name:          "IPv6,Proxy",
			enableIPv6:    true,
			clientOptions: []clientOptionsFn{enableProxy},
			expectedFlows: []string{
				"cookie=0x1030000000000, table=UnSNAT, priority=200,ipv6,ipv6_dst=fc01::aabb:ccdd:eeff actions=ct(table=ConntrackZone,zone=65511,exec(nat))",
				"cookie=0x1030000000000, table=UnSNAT, priority=200,ipv6,ipv6_dst=fec0:10:10::1 actions=ct(table=ConntrackZone,zone=65511,exec(nat))",
				"cookie=0x1030000000000, table=ConntrackState, priority=200,ct_state=-new+trk,ct_mark=0x10/0x10,ipv6 actions=set_field:0x200/0x200->reg0,goto_table:AntreaPolicyEgressRule",
				"cookie=0x1030000000000, table=PreRoutingClassifier, priority=200,ipv6 actions=resubmit:SessionAffinity,resubmit:ServiceLB",
				"cookie=0x1030000000000, table=SessionAffinity, priority=0 actions=set_field:0x10000/0x70000->reg4",
				"cookie=0x1030000000000, table=EndpointDNAT, priority=190,reg4=0x20000/0x70000 actions=set_field:0x10000/0x70000->reg4,resubmit:ServiceLB",
				"cookie=0x1030000000000, table=L3Forwarding, priority=190,ct_mark=0x10/0x10,reg0=0x202/0x20f actions=set_field:00:00:10:10:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1030000000000, table=SNATMark, priority=200,ct_state=+new+trk,ipv6,reg0=0x22/0xff actions=ct(commit,table=SNAT,zone=65510,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))",
				"cookie=0x1030000000000, table=SNATMark, priority=200,ct_state=+new+trk,ipv6,reg0=0x12/0xff,reg4=0x200000/0x200000 actions=ct(commit,table=SNAT,zone=65510,exec(set_field:0x20/0x20->ct_mark))",
				"cookie=0x1030000000000, table=SNAT, priority=200,ct_state=+new+trk,ct_mark=0x40/0x40,ipv6,reg0=0x2/0xf actions=ct(commit,table=L2ForwardingCalc,zone=65511,exec(nat(src=fc01::aabb:ccdd:eeff),set_field:0x10/0x10->ct_mark,set_field:0x40/0x40->ct_mark))",
				"cookie=0x1030000000000, table=SNAT, priority=200,ct_state=+new+trk,ct_mark=0x40/0x40,ipv6,reg0=0x3/0xf actions=ct(commit,table=L2ForwardingCalc,zone=65511,exec(nat(src=fec0:10:10::1),set_field:0x10/0x10->ct_mark,set_field:0x40/0x40->ct_mark))",
				"cookie=0x1030000000000, table=SNAT, priority=200,ct_state=-new-rpl+trk,ct_mark=0x20/0x20,ipv6 actions=ct(table=L2ForwardingCalc,zone=65511,exec(nat))",
				"cookie=0x1030000000000, table=SNAT, priority=190,ct_state=+new+trk,ct_mark=0x20/0x20,ipv6,reg0=0x2/0xf actions=ct(commit,table=L2ForwardingCalc,zone=65511,exec(nat(src=fec0:10:10::1),set_field:0x10/0x10->ct_mark))",
				"cookie=0x1030000000000, table=Output, priority=210,ct_mark=0x40/0x40 actions=IN_PORT",
			},
		},
		{
			name:          "IPv4,ProxyAll",
			enableIPv4:    true,
			clientOptions: []clientOptionsFn{enableProxyAll},
			expectedFlows: []string{
				"cookie=0x1030000000000, table=UnSNAT, priority=200,ip,nw_dst=169.254.0.253 actions=ct(table=ConntrackZone,zone=65521,exec(nat))",
				"cookie=0x1030000000000, table=UnSNAT, priority=200,ip,nw_dst=10.10.0.1 actions=ct(table=ConntrackZone,zone=65521,exec(nat))",
				"cookie=0x1030000000000, table=ConntrackState, priority=200,ct_state=-new+trk,ct_mark=0x10/0x10,ip actions=set_field:0x200/0x200->reg0,goto_table:AntreaPolicyEgressRule",
				"cookie=0x1030000000000, table=PreRoutingClassifier, priority=200,ip actions=resubmit:NodePortMark,resubmit:SessionAffinity,resubmit:ServiceLB",
				"cookie=0x1030000000000, table=NodePortMark, priority=200,ip,nw_dst=192.168.77.100 actions=set_field:0x80000/0x80000->reg4",
				"cookie=0x1030000000000, table=NodePortMark, priority=200,ip,nw_dst=127.0.0.1 actions=set_field:0x80000/0x80000->reg4",
				"cookie=0x1030000000000, table=NodePortMark, priority=200,ip,nw_dst=169.254.0.252 actions=set_field:0x80000/0x80000->reg4",
				"cookie=0x1030000000000, table=SessionAffinity, priority=0 actions=set_field:0x10000/0x70000->reg4",
				"cookie=0x1030000000000, table=EndpointDNAT, priority=190,reg4=0x20000/0x70000 actions=set_field:0x10000/0x70000->reg4,resubmit:ServiceLB",
				"cookie=0x1030000000000, table=L3Forwarding, priority=190,ct_mark=0x10/0x10,reg0=0x202/0x20f actions=set_field:00:00:10:10:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1030000000000, table=SNATMark, priority=200,ct_state=+new+trk,ip,reg0=0x22/0xff actions=ct(commit,table=SNAT,zone=65520,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))",
				"cookie=0x1030000000000, table=SNATMark, priority=200,ct_state=+new+trk,ip,reg0=0x12/0xff,reg4=0x200000/0x200000 actions=ct(commit,table=SNAT,zone=65520,exec(set_field:0x20/0x20->ct_mark))",
				"cookie=0x1030000000000, table=SNAT, priority=200,ct_state=+new+trk,ct_mark=0x40/0x40,ip,reg0=0x2/0xf actions=ct(commit,table=L2ForwardingCalc,zone=65521,exec(nat(src=169.254.0.253),set_field:0x10/0x10->ct_mark,set_field:0x40/0x40->ct_mark))",
				"cookie=0x1030000000000, table=SNAT, priority=200,ct_state=+new+trk,ct_mark=0x40/0x40,ip,reg0=0x3/0xf actions=ct(commit,table=L2ForwardingCalc,zone=65521,exec(nat(src=10.10.0.1),set_field:0x10/0x10->ct_mark,set_field:0x40/0x40->ct_mark))",
				"cookie=0x1030000000000, table=SNAT, priority=190,ct_state=+new+trk,ct_mark=0x20/0x20,ip,reg0=0x2/0xf actions=ct(commit,table=L2ForwardingCalc,zone=65521,exec(nat(src=10.10.0.1),set_field:0x10/0x10->ct_mark))",
				"cookie=0x1030000000000, table=SNAT, priority=200,ct_state=-new-rpl+trk,ct_mark=0x20/0x20,ip actions=ct(table=L2ForwardingCalc,zone=65521,exec(nat))",
				"cookie=0x1030000000000, table=Output, priority=210,ct_mark=0x40/0x40 actions=IN_PORT",
			},
		},
		{
			name:          "IPv6,ProxyAll",
			enableIPv6:    true,
			clientOptions: []clientOptionsFn{enableProxyAll},
			expectedFlows: []string{
				"cookie=0x1030000000000, table=UnSNAT, priority=200,ipv6,ipv6_dst=fc01::aabb:ccdd:eeff actions=ct(table=ConntrackZone,zone=65511,exec(nat))",
				"cookie=0x1030000000000, table=UnSNAT, priority=200,ipv6,ipv6_dst=fec0:10:10::1 actions=ct(table=ConntrackZone,zone=65511,exec(nat))",
				"cookie=0x1030000000000, table=ConntrackState, priority=200,ct_state=-new+trk,ct_mark=0x10/0x10,ipv6 actions=set_field:0x200/0x200->reg0,goto_table:AntreaPolicyEgressRule",
				"cookie=0x1030000000000, table=PreRoutingClassifier, priority=200,ipv6 actions=resubmit:NodePortMark,resubmit:SessionAffinity,resubmit:ServiceLB",
				"cookie=0x1030000000000, table=NodePortMark, priority=200,ipv6,ipv6_dst=fec0:192:168:77::100 actions=set_field:0x80000/0x80000->reg4",
				"cookie=0x1030000000000, table=NodePortMark, priority=200,ipv6,ipv6_dst=::1 actions=set_field:0x80000/0x80000->reg4",
				"cookie=0x1030000000000, table=NodePortMark, priority=200,ipv6,ipv6_dst=fc01::aabb:ccdd:eefe actions=set_field:0x80000/0x80000->reg4",
				"cookie=0x1030000000000, table=SessionAffinity, priority=0 actions=set_field:0x10000/0x70000->reg4",
				"cookie=0x1030000000000, table=EndpointDNAT, priority=190,reg4=0x20000/0x70000 actions=set_field:0x10000/0x70000->reg4,resubmit:ServiceLB",
				"cookie=0x1030000000000, table=L3Forwarding, priority=190,ct_mark=0x10/0x10,reg0=0x202/0x20f actions=set_field:00:00:10:10:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1030000000000, table=SNATMark, priority=200,ct_state=+new+trk,ipv6,reg0=0x22/0xff actions=ct(commit,table=SNAT,zone=65510,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))",
				"cookie=0x1030000000000, table=SNATMark, priority=200,ct_state=+new+trk,ipv6,reg0=0x12/0xff,reg4=0x200000/0x200000 actions=ct(commit,table=SNAT,zone=65510,exec(set_field:0x20/0x20->ct_mark))",
				"cookie=0x1030000000000, table=SNAT, priority=200,ct_state=+new+trk,ct_mark=0x40/0x40,ipv6,reg0=0x2/0xf actions=ct(commit,table=L2ForwardingCalc,zone=65511,exec(nat(src=fc01::aabb:ccdd:eeff),set_field:0x10/0x10->ct_mark,set_field:0x40/0x40->ct_mark))",
				"cookie=0x1030000000000, table=SNAT, priority=200,ct_state=+new+trk,ct_mark=0x40/0x40,ipv6,reg0=0x3/0xf actions=ct(commit,table=L2ForwardingCalc,zone=65511,exec(nat(src=fec0:10:10::1),set_field:0x10/0x10->ct_mark,set_field:0x40/0x40->ct_mark))",
				"cookie=0x1030000000000, table=SNAT, priority=200,ct_state=-new-rpl+trk,ct_mark=0x20/0x20,ipv6 actions=ct(table=L2ForwardingCalc,zone=65511,exec(nat))",
				"cookie=0x1030000000000, table=SNAT, priority=190,ct_state=+new+trk,ct_mark=0x20/0x20,ipv6,reg0=0x2/0xf actions=ct(commit,table=L2ForwardingCalc,zone=65511,exec(nat(src=fec0:10:10::1),set_field:0x10/0x10->ct_mark))",
				"cookie=0x1030000000000, table=Output, priority=210,ct_mark=0x40/0x40 actions=IN_PORT",
			},
		},
		{
			name:          "No Proxy",
			enableIPv4:    true,
			enableIPv6:    true,
			clientOptions: []clientOptionsFn{disableProxy},
			expectedFlows: []string{
				"cookie=0x1030000000000, table=DNAT, priority=200,ip,nw_dst=10.96.0.0/16 actions=set_field:0x2->reg1,set_field:0x100/0x100->reg0,goto_table:ConntrackCommit",
				"cookie=0x1030000000000, table=DNAT, priority=200,ipv6,ipv6_dst=fec0:10:96::/64 actions=set_field:0x2->reg1,set_field:0x100/0x100->reg0,goto_table:ConntrackCommit",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fc := newFakeClient(nil, tc.enableIPv4, tc.enableIPv6, config.K8sNode, config.TrafficEncapModeEncap, tc.clientOptions...)
			defer resetPipelines()

			flows := getFlowStrings(fc.featureService.initFlows())
			assert.ElementsMatch(t, tc.expectedFlows, flows)
		})
	}
}
