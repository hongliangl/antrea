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

package suricata

import (
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"

	mock "antrea.io/antrea/pkg/agent/controller/l7networkpolicy/suricata/testing"
	v1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

func TestAddressGroupParser(t *testing.T) {
	testCases := []struct {
		name     string
		group    v1beta.GroupMemberSet
		expected string
	}{
		{
			name:     "no group",
			expected: "test_ip_src: any",
		},
		{
			name: "group",
			group: v1beta.GroupMemberSet{
				"g1": &v1beta.GroupMember{
					IPs: []v1beta.IPAddress{
						[]byte{10, 10, 0, 1},
						[]byte{10, 10, 0, 2},
					},
				},
				"g2": &v1beta.GroupMember{
					IPs: []v1beta.IPAddress{
						[]byte{10, 20, 0, 1},
						[]byte{10, 20, 0, 2},
					},
				},
			},
			expected: "test_ip_src: \"[10.10.0.1,10.10.0.2,10.20.0.1,10.20.0.2]\"",
		},
	}
	addressGroupVar := "test_ip_src"
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, addressGroupParser(addressGroupVar, tc.group))
		})
	}
}

func TestPortGroupParser(t *testing.T) {
	endPort1 := int32(90)
	endPort2 := int32(500)

	testCases := []struct {
		name      string
		protocols []v1beta.Service
		expected  string
	}{
		{
			name:     "no protocol",
			expected: "test_tp_dst: any",
		},
		{
			name:      "protocol without port",
			protocols: []v1beta.Service{{}},
			expected:  "test_tp_dst: \"[any]\"",
		},
		{
			name: "protocol with ports",
			protocols: []v1beta.Service{
				{
					Port: &intstr.IntOrString{Type: intstr.Int, IntVal: int32(80)},
				},
				{
					Port: &intstr.IntOrString{Type: intstr.Int, IntVal: int32(443)},
				},
			},
			expected: "test_tp_dst: \"[80,443]\"",
		},
		{
			name: "protocol with port ranges",
			protocols: []v1beta.Service{
				{
					Port:    &intstr.IntOrString{Type: intstr.Int, IntVal: int32(80)},
					EndPort: &endPort1,
				},
				{
					Port:    &intstr.IntOrString{Type: intstr.Int, IntVal: int32(443)},
					EndPort: &endPort2,
				},
			},
			expected: "test_tp_dst: \"[80:90,443:500]\"",
		},
		{
			name: "protocol with multiple port patterns",
			protocols: []v1beta.Service{
				{},
				{
					Port:    &intstr.IntOrString{Type: intstr.Int, IntVal: int32(80)},
					EndPort: &endPort1,
				},
				{
					Port: &intstr.IntOrString{Type: intstr.Int, IntVal: int32(443)},
				},
			},
			expected: "test_tp_dst: \"[any,80:90,443]\"",
		},
	}
	addressGroupVar := "test_tp_dst"
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, portGroupParser(addressGroupVar, tc.protocols))
		})
	}
}

func TestProtocolHTTPParser(t *testing.T) {
	testCases := []struct {
		name     string
		http     *v1beta.HTTPProtocol
		expected string
	}{
		{
			name:     "without host,method,path",
			http:     &v1beta.HTTPProtocol{},
			expected: "",
		},
		{
			name: "with host,method,path",
			http: &v1beta.HTTPProtocol{
				Host:   "www.google.com",
				Method: "GET",
				Path:   "index.html",
			},
			expected: "http.uri; content:\"index.html\"; http.method; content:\"GET\"; http.host; content:\"www.google.com\";",
		},
		{
			name: "with host",
			http: &v1beta.HTTPProtocol{
				Host: "www.google.com",
			},
			expected: "http.host; content:\"www.google.com\";",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, strings.Join(protocolHTTPParser(tc.http), " "))
		})
	}
}

var (
	ruleName = "http"
	from     = v1beta.GroupMemberSet{
		"key": &v1beta.GroupMember{
			IPs: []v1beta.IPAddress{
				[]byte{10, 10, 1, 1},
				[]byte{10, 10, 1, 2},
			},
		},
	}
	target = v1beta.GroupMemberSet{
		"key": &v1beta.GroupMember{
			IPs: []v1beta.IPAddress{
				[]byte{10, 10, 0, 1},
				[]byte{10, 10, 0, 2},
			},
		},
	}
	l4Protocol  = v1beta.ProtocolTCP
	port        = intstr.IntOrString{Type: intstr.Int, IntVal: 80}
	l4Protocols = []v1beta.Service{
		{
			Protocol: &l4Protocol,
			Port:     &port,
		},
	}
	l7Protocols = []v1beta.L7Protocol{
		{
			HTTP: &v1beta.HTTPProtocol{
				Host:   "www.google.com",
				Method: "GET",
				Path:   "index.html",
			},
		},
	}

	expectedRule = &rule{
		srcIPs:   "http_ip_src: \"[10.10.1.1,10.10.1.2]\"",
		dstIPs:   "http_ip_dst: \"[10.10.0.1,10.10.0.2]\"",
		dstPorts: "http_tp_dst: \"[80]\"",
		signatures: sets.NewString("pass http $http_ip_src any -> $http_ip_dst $http_tp_dst (msg:\"Allow by http\"; http.uri; content:\"index.html\"; http.method; content:\"GET\"; http.host; content:\"www.google.com\"; sid:1;)",
			"drop http $http_ip_src any -> $http_ip_dst $http_tp_dst (msg:\"Drop by http\"; sid:2;)"),
		sids: []uint32{1, 2},
	}
)

func TestRuleAdd(t *testing.T) {
	testCases := []struct {
		name         string
		from         v1beta.GroupMemberSet
		target       v1beta.GroupMemberSet
		l4Protocols  []v1beta.Service
		l7Protocols  []v1beta.L7Protocol
		expectedRule *rule
	}{
		{
			name:        "Address group update",
			from:        from,
			target:      nil,
			l4Protocols: l4Protocols,
			l7Protocols: l7Protocols,
			expectedRule: &rule{
				srcIPs:   "http_ip_src: \"[10.10.1.1,10.10.1.2]\"",
				dstIPs:   "http_ip_dst: any",
				dstPorts: "http_tp_dst: \"[80]\"",
				signatures: sets.NewString("pass http $http_ip_src any -> $http_ip_dst $http_tp_dst (msg:\"Allow by http\"; http.uri; content:\"index.html\"; http.method; content:\"GET\"; http.host; content:\"www.google.com\"; sid:3;)",
					"drop http $http_ip_src any -> $http_ip_dst $http_tp_dst (msg:\"Drop by http\"; sid:4;)"),
				sids: []uint32{3, 4},
			},
		},
		{
			name:        "Port group update",
			from:        from,
			target:      target,
			l4Protocols: nil,
			l7Protocols: l7Protocols,
			expectedRule: &rule{
				srcIPs:   "http_ip_src: \"[10.10.1.1,10.10.1.2]\"",
				dstIPs:   "http_ip_dst: \"[10.10.0.1,10.10.0.2]\"",
				dstPorts: "http_tp_dst: any",
				signatures: sets.NewString("pass http $http_ip_src any -> $http_ip_dst $http_tp_dst (msg:\"Allow by http\"; http.uri; content:\"index.html\"; http.method; content:\"GET\"; http.host; content:\"www.google.com\"; sid:3;)",
					"drop http $http_ip_src any -> $http_ip_dst $http_tp_dst (msg:\"Drop by http\"; sid:4;)"),
				sids: []uint32{3, 4},
			},
		},
		{
			name:        "Signature update",
			from:        from,
			target:      target,
			l4Protocols: l4Protocols,
			l7Protocols: []v1beta.L7Protocol{
				{
					HTTP: &v1beta.HTTPProtocol{
						Host:   "www.google.com",
						Method: "GET",
					},
				},
			},
			expectedRule: &rule{
				srcIPs:   "http_ip_src: \"[10.10.1.1,10.10.1.2]\"",
				dstIPs:   "http_ip_dst: \"[10.10.0.1,10.10.0.2]\"",
				dstPorts: "http_tp_dst: \"[80]\"",
				signatures: sets.NewString("pass http $http_ip_src any -> $http_ip_dst $http_tp_dst (msg:\"Allow by http\"; http.method; content:\"GET\"; http.host; content:\"www.google.com\"; sid:3;)",
					"drop http $http_ip_src any -> $http_ip_dst $http_tp_dst (msg:\"Drop by http\"; sid:4;)"),
				sids: []uint32{3, 4},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			m := mock.NewMockEnforcerOperations(ctrl)
			enforcer := NewEnforcer()
			enforcer.enforcerOperations = m

			m.EXPECT().SyncAddressGroups().AnyTimes()
			m.EXPECT().SyncPortGroups().AnyTimes()
			m.EXPECT().SyncSignatures().AnyTimes()
			m.EXPECT().ReloadSignatures().Times(2)

			assert.NoError(t, enforcer.AddRule(ruleName, from, target, l4Protocols, l7Protocols))
			assert.Equal(t, expectedRule, enforcer.cachedRules[ruleName])

			assert.NoError(t, enforcer.AddRule(ruleName, tc.from, tc.target, tc.l4Protocols, tc.l7Protocols))
			assert.Equal(t, tc.expectedRule, enforcer.cachedRules[ruleName])
		})
	}
}

func TestRuleDelete(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	m := mock.NewMockEnforcerOperations(ctrl)
	enforcer := NewEnforcer()
	enforcer.enforcerOperations = m

	m.EXPECT().SyncAddressGroups().Times(2)
	m.EXPECT().SyncPortGroups().Times(2)
	m.EXPECT().SyncSignatures().Times(2)
	m.EXPECT().ReloadSignatures().Times(2)

	assert.NoError(t, enforcer.AddRule(ruleName, from, target, l4Protocols, l7Protocols))
	assert.Equal(t, expectedRule, enforcer.cachedRules[ruleName])

	assert.NoError(t, enforcer.DeleteRule(ruleName))
	_, ok := enforcer.cachedRules[ruleName]
	assert.Equal(t, false, ok)
}
