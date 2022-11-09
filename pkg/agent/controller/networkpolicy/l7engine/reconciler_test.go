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

package l7engine

import (
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	v1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

var (
	startSuricataFnCalled bool

	suricataScFnCalledWithReloadTenant            bool
	suricataScFnCalledWithRegisterTenantHandler   bool
	suricataScFnCalledWithRegisterTenant          bool
	suricataScFnCalledWithUnregisterTenantHandler bool
	suricataScFnCalledWithUnregisterTenant        bool
)

func TestConvertProtocolHTTP(t *testing.T) {
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
			assert.Equal(t, tc.expected, convertProtocolHTTP(tc.http))
		})
	}
}

func newFakeReconciler() *Reconciler {
	defaultFS.Create(defaultSuricataConfigPath)

	fe := NewReconciler()
	fe.suricataScFn = func(scCmd string) (*scCmdRet, error) {
		if strings.HasPrefix(scCmd, "reload-tenant") {
			suricataScFnCalledWithReloadTenant = true
		} else if strings.HasPrefix(scCmd, "register-tenant-handler") {
			suricataScFnCalledWithRegisterTenantHandler = true
		} else if strings.HasPrefix(scCmd, "register-tenant") {
			suricataScFnCalledWithRegisterTenant = true
		} else if strings.HasPrefix(scCmd, "unregister-tenant-handler") {
			suricataScFnCalledWithUnregisterTenantHandler = true
		} else if strings.HasPrefix(scCmd, "unregister-tenant") {
			suricataScFnCalledWithUnregisterTenant = true
		}
		return &scCmdRet{Return: scCmdOK}, nil
	}
	fe.startSuricataFn = func() {
		startSuricataFnCalled = true
		defaultFS.Create(suricataCommandSocket)
	}
	return fe
}

func resetTest() {
	suricataScFnCalledWithReloadTenant = false
	suricataScFnCalledWithRegisterTenantHandler = false
	suricataScFnCalledWithRegisterTenant = false
	suricataScFnCalledWithUnregisterTenantHandler = false
	suricataScFnCalledWithUnregisterTenant = false
	startSuricataFnCalled = false
}
func TestStartSuricata(t *testing.T) {
	defaultFS = afero.NewMemMapFs()
	defer func() {
		defaultFS = afero.NewOsFs()
	}()

	fe := newFakeReconciler()
	fe.startSuricata()

	ok, err := afero.FileContainsBytes(defaultFS, antreaSuricataConfigPath, []byte(`---
af-packet:
  - interface: antrea-l7-tap0
    threads: auto
    cluster-id: 80
    cluster-type: cluster_flow
    defrag: no
    use-mmap: yes
    tpacket-v2: yes
    checksum-checks: no
    bpf-filter: "ip or ip6"
    copy-mode: ips
    copy-iface: antrea-l7-tap1
  - interface:  antrea-l7-tap1
    threads: auto
    cluster-id: 81
    cluster-type: cluster_flow
    defrag: no
    use-mmap: yes
    tpacket-v2: yes
    checksum-checks: no
    bpf-filter: "ip or ip6"
    copy-mode: ips
    copy-iface: antrea-l7-tap0
multi-detect:
  enabled: yes
  selector: vlan`))
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, err = afero.FileContainsBytes(defaultFS, defaultSuricataConfigPath, []byte("include: /etc/suricata/antrea.yaml"))
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestRuleLifecycle(t *testing.T) {
	ruleID := "123456"
	vlanID := uint32(1)
	policyName := "AntreaNetworkPolicy:test-l7"

	testCases := []struct {
		name                 string
		l7Protocols          []v1beta.L7Protocol
		updatedL7Protocols   []v1beta.L7Protocol
		expectedRules        string
		expectedUpdatedRules string
	}{
		{
			name: "protocol HTTP",
			l7Protocols: []v1beta.L7Protocol{
				{
					HTTP: &v1beta.HTTPProtocol{
						Host:   "www.google.com",
						Method: "GET",
						Path:   "index.html",
					},
				},
			},
			updatedL7Protocols: []v1beta.L7Protocol{
				{
					HTTP: &v1beta.HTTPProtocol{},
				},
			},
			expectedRules:        `pass http any any -> any any (msg: "Allow http by AntreaNetworkPolicy:test-l7"; http.uri; content:"index.html"; http.method; content:"GET"; http.host; content:"www.google.com"; sid: 2;)`,
			expectedUpdatedRules: `pass http any any -> any any (msg: "Allow http by AntreaNetworkPolicy:test-l7"; sid: 2;)`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defaultFS = afero.NewMemMapFs()
			defer func() {
				defaultFS = afero.NewOsFs()
			}()

			fe := newFakeReconciler()
			defer resetTest()

			// Test add a L7 Antrea NetworkPolicy.
			assert.NoError(t, fe.AddRule(ruleID, policyName, vlanID, tc.l7Protocols))

			rulesPath := generateTenantRulesPath(vlanID)
			ok, err := afero.FileContainsBytes(defaultFS, rulesPath, []byte(tc.expectedRules))
			assert.NoError(t, err)
			assert.True(t, ok)

			configPath := generateTenantConfigPath(vlanID)
			ok, err = afero.FileContainsBytes(defaultFS, configPath, []byte(rulesPath))
			assert.NoError(t, err)
			assert.True(t, ok)

			assert.True(t, startSuricataFnCalled)
			assert.True(t, suricataScFnCalledWithRegisterTenant)
			assert.True(t, suricataScFnCalledWithRegisterTenantHandler)

			// Update the added L7 Antrea NetworkPolicy.
			assert.NoError(t, fe.AddRule(ruleID, policyName, vlanID, tc.updatedL7Protocols))
			assert.True(t, suricataScFnCalledWithReloadTenant)

			// Delete the L7 Antrea NetworkPolicy.
			assert.NoError(t, fe.DeleteRule(ruleID, vlanID))
			assert.True(t, suricataScFnCalledWithUnregisterTenant)
			assert.True(t, suricataScFnCalledWithUnregisterTenantHandler)

			exists, err := afero.Exists(defaultFS, rulesPath)
			assert.NoError(t, err)
			assert.False(t, exists)

			exists, err = afero.Exists(defaultFS, configPath)
			assert.NoError(t, err)
			assert.False(t, exists)
		})
	}
}
