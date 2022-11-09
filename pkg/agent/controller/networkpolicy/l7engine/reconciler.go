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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/spf13/afero"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	v1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

const (
	defaultSuricataConfigPath = "/etc/suricata/suricata.yaml"
	antreaSuricataConfigPath  = "/etc/suricata/antrea.yaml"

	tenantConfigsDir = "/etc/suricata"
	tenantRulesDir   = "/etc/suricata/rules"

	suricataCommandSocket = "/var/run/suricata/suricata-command.socket"

	protocolHTTP = "http"

	scCmdOK = "OK"
)

type scCmdRet struct {
	Message string `json:"message"`
	Return  string `json:"return"`
}

var (
	// Declared as a variable for testing.
	defaultFS = afero.NewOsFs()
)

type genericCache struct {
	sync.RWMutex
	cached sets.Int32
}

func (g *genericCache) has(key uint32) bool {
	g.RLock()
	defer g.RUnlock()
	return g.cached.Has(int32(key))
}

func (g *genericCache) insert(key uint32) {
	g.Lock()
	defer g.Unlock()
	g.cached.Insert(int32(key))
}

func (g *genericCache) delete(key uint32) {
	g.Lock()
	defer g.Unlock()
	g.cached.Delete(int32(key))
}

type Reconciler struct {
	// Declared as member variables for testing.
	startSuricataFn func()
	suricataScFn    func(scCmd string) (*scCmdRet, error)

	suricataTenantCache        *genericCache
	suricataTenantHandlerCache *genericCache

	once sync.Once
}

func NewReconciler() *Reconciler {
	return &Reconciler{
		suricataScFn:    suricataSc,
		startSuricataFn: startSuricata,
		suricataTenantCache: &genericCache{
			cached: sets.NewInt32(),
		},
		suricataTenantHandlerCache: &genericCache{
			cached: sets.NewInt32(),
		},
	}
}

func generateTenantRulesData(policyName string, protoKeywords map[string]sets.String) *bytes.Buffer {
	rulesData := bytes.NewBuffer(nil)
	sid := 1

	// Generate default reject rule.
	allKeywords := fmt.Sprintf(`msg: "Reject by %s"; flow: to_server, established; sid: %d;`, policyName, sid)
	rule := fmt.Sprintf("reject ip any any -> any any (%s)\n", allKeywords)
	rulesData.WriteString(rule)
	sid++

	// Generate rules.
	for proto, keywordsSet := range protoKeywords {
		for keywords := range keywordsSet {
			// It is a convention that the sid is provided as the last keyword (or second-to-last if there is a rev)
			// of a rule.
			if keywords != "" {
				allKeywords = fmt.Sprintf(`msg: "Allow %s by %s"; %s sid: %d;`, proto, policyName, keywords, sid)
			} else {
				allKeywords = fmt.Sprintf(`msg: "Allow %s by %s"; sid: %d;`, proto, policyName, sid)
			}
			rule = fmt.Sprintf("pass %s any any -> any any (%s)\n", proto, allKeywords)
			rulesData.WriteString(rule)
			sid++
		}
	}

	return rulesData
}

func generateTenantRulesPath(vlanID uint32) string {
	return fmt.Sprintf("%s/antrea-l7-networkpolicy-%d.rules", tenantRulesDir, vlanID)
}

func generateTenantConfigPath(vlanID uint32) string {
	return fmt.Sprintf("%s/antrea-tenant-%d.yaml", tenantConfigsDir, vlanID)
}

func writeConfigFile(path string, data *bytes.Buffer) error {
	f, err := defaultFS.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(data.Bytes()); err != nil {
		return err
	}
	return nil
}

func convertProtocolHTTP(http *v1beta.HTTPProtocol) string {
	var keywords []string
	if http.Path != "" {
		keywords = append(keywords, fmt.Sprintf(`http.uri; content:"%s";`, http.Path))
	}
	if http.Method != "" {
		keywords = append(keywords, fmt.Sprintf(`http.method; content:"%s";`, http.Method))
	}
	if http.Host != "" {
		keywords = append(keywords, fmt.Sprintf(`http.host; content:"%s";`, http.Host))
	}
	return strings.Join(keywords, " ")
}

func (r *Reconciler) AddRule(ruleID, policyName string, vlanID uint32, l7Protocols []v1beta.L7Protocol) error {
	r.once.Do(func() {
		r.startSuricata()
	})

	// Generate the keyword part used in Suricata rules.
	protoKeywords := make(map[string]sets.String)
	for _, protocol := range l7Protocols {
		if protocol.HTTP != nil {
			httpKeywords := convertProtocolHTTP(protocol.HTTP)
			if _, ok := protoKeywords[protocolHTTP]; !ok {
				protoKeywords[protocolHTTP] = sets.NewString()
			}
			protoKeywords[protocolHTTP].Insert(httpKeywords)
		}
	}

	klog.InfoS("Reconciling L7 rule", "RuleID", ruleID, "PolicyName", policyName)
	// Write the Suricata rules to file.
	rulesPath := generateTenantRulesPath(vlanID)
	rulesData := generateTenantRulesData(policyName, protoKeywords)
	if err := writeConfigFile(rulesPath, rulesData); err != nil {
		return fmt.Errorf("failed to write Suricata rules data to file %s for L7 rule %s of %s", rulesPath, ruleID, policyName)
	}

	// Add a Suricata tenant.
	if err := r.addBindingSuricataTenant(vlanID, rulesPath); err != nil {
		return fmt.Errorf("failed to add Suricata tenant for L7 rule %s of %s", ruleID, policyName)
	}

	return nil
}

func (r *Reconciler) DeleteRule(ruleID string, vlanID uint32) error {
	// Delete the Suricata tenant.
	if err := r.deleteBindingSuricataTenant(vlanID); err != nil {
		return fmt.Errorf("failed to delete Suricata tenant %d for L7 rule %s: %v", vlanID, ruleID, err)
	}

	// Delete the Suricata rules file.
	rulesPath := generateTenantRulesPath(vlanID)
	if err := defaultFS.Remove(rulesPath); err != nil {
		klog.ErrorS(err, "failed to delete rules file", "FilePath", rulesPath, "RuleID", ruleID)
	}

	return nil
}

func (r *Reconciler) addBindingSuricataTenant(vlanID uint32, rulesPath string) error {
	tenantConfigPath := generateTenantConfigPath(vlanID)
	exists, err := afero.Exists(defaultFS, tenantConfigPath)
	if err != nil {
		return fmt.Errorf("failed to stat config file %s", tenantConfigPath)
	}

	// If the tenant config file exists, it means that this tenant has been added, just reload the tenant to load the
	// updated rules.
	if exists {
		resp, err := r.reloadSuricataTenant(vlanID, tenantConfigPath)
		if err != nil {
			return err
		}
		if resp.Return != scCmdOK {
			return fmt.Errorf("failed to reload Suricata tenant %d with config file %s: %v", vlanID, tenantConfigPath, resp.Message)
		}
		klog.V(4).InfoS("reloaded Suricata tenant successfully", "TenantID", vlanID, "TenantConfigPath", tenantConfigPath, "ResponseMsg", resp.Message)
		return nil
	}

	success := false
	// If the tenant config file doesn't exist, create a config file for the tenant.
	tenantConfigData := bytes.NewBuffer([]byte(fmt.Sprintf(`%%YAML 1.1

---
default-rule-path: /etc/suricata/rules
rule-files:
  - %s
`, rulesPath)))
	if err = writeConfigFile(tenantConfigPath, tenantConfigData); err != nil {
		return fmt.Errorf("failed to write config file %s for Suricata tenant %d: %v", tenantConfigPath, vlanID, err)
	}
	defer func() {
		if !success {
			// Delete the config file regardless if it is created.
			defaultFS.Remove(tenantConfigPath)
		}
	}()

	// Register the tenant with the config file. Note that, to be simple, use the VLAN id as the tenant ID.
	if !r.suricataTenantCache.has(vlanID) {
		resp, err := r.registerSuricataTenant(vlanID, tenantConfigPath)
		if err != nil {
			return err
		}
		if resp.Return != scCmdOK {
			return fmt.Errorf("failed to register Suricata tenant %d with config file %s: %v", vlanID, tenantConfigPath, resp.Message)
		}
		klog.V(4).InfoS("registered Suricata tenant successfully", "TenantID", vlanID, "TenantConfigPath", tenantConfigPath, "ResponseMsg", resp.Message)
		r.suricataTenantCache.insert(vlanID)
	}

	// Register the tenant handler by mapping the tenant to the allocated VLAN ID.
	if !r.suricataTenantHandlerCache.has(vlanID) {
		resp, err := r.registerSuricataTenantHandler(vlanID, vlanID)
		if err != nil {
			return err
		}
		if resp.Return != scCmdOK {
			return fmt.Errorf("failed to register Suricata tenant %d handler to VLAN %d: %v", vlanID, vlanID, resp.Message)
		}
		klog.V(4).InfoS("registered Suricata tenant handler successfully", "TenantID", vlanID, "VLANID", vlanID, "ResponseMsg", resp.Message)
		r.suricataTenantHandlerCache.insert(vlanID)
	}

	success = true

	return nil
}

func (r *Reconciler) deleteBindingSuricataTenant(vlanID uint32) error {
	// Unregister the tenant handler.
	if r.suricataTenantHandlerCache.has(vlanID) {
		resp, err := r.unregisterSuricataTenantHandler(vlanID, vlanID)
		if err != nil {
			return err
		}
		if resp.Return != scCmdOK {
			return fmt.Errorf("failed to unregister Suricata tenant %d handler: %v", vlanID, resp.Message)
		}
		klog.V(4).InfoS("unregistered Suricata tenant handler successfully", "TenantID", vlanID, "VLANID", vlanID, "ResponseMsg", resp.Message)
		r.suricataTenantHandlerCache.delete(vlanID)
	}

	// Unregister the tenant.
	if r.suricataTenantCache.has(vlanID) {
		resp, err := r.unregisterSuricataTenant(vlanID)
		if err != nil {
			return err
		}
		if resp.Return != scCmdOK {
			return fmt.Errorf("failed to unregister Suricata tenant %d: %v", vlanID, resp.Message)
		}
		klog.V(4).InfoS("unregistered Suricata tenant successfully", "TenantID", vlanID, "ResponseMsg", resp.Message)
		r.suricataTenantCache.delete(vlanID)
	}

	// Delete the tenant config file.
	configPath := generateTenantConfigPath(vlanID)
	if err := defaultFS.Remove(configPath); err != nil {
		if err != afero.ErrFileNotFound {
			return fmt.Errorf("failed to delete config file %s", configPath)
		}
	}
	return nil
}

func (r *Reconciler) reloadSuricataTenant(tenantID uint32, tenantConfigPath string) (*scCmdRet, error) {
	scCmd := fmt.Sprintf("reload-tenant %d %s", tenantID, tenantConfigPath)
	return r.suricataScFn(scCmd)
}

func (r *Reconciler) registerSuricataTenant(tenantID uint32, tenantConfigPath string) (*scCmdRet, error) {
	scCmd := fmt.Sprintf("register-tenant %d %s", tenantID, tenantConfigPath)
	return r.suricataScFn(scCmd)
}

func (r *Reconciler) unregisterSuricataTenant(tenantID uint32) (*scCmdRet, error) {
	scCmd := fmt.Sprintf("unregister-tenant %d", tenantID)
	return r.suricataScFn(scCmd)
}

func (r *Reconciler) registerSuricataTenantHandler(tenantID, vlanID uint32) (*scCmdRet, error) {
	scCmd := fmt.Sprintf("register-tenant-handler %d vlan %d", tenantID, vlanID)
	return r.suricataScFn(scCmd)
}

func (r *Reconciler) unregisterSuricataTenantHandler(tenantID, vlanID uint32) (*scCmdRet, error) {
	scCmd := fmt.Sprintf("unregister-tenant-handler %d vlan %d", tenantID, vlanID)
	return r.suricataScFn(scCmd)
}

func (r *Reconciler) startSuricata() {
	// Create the config file /etc/suricata/antrea.yaml for Antrea which will be included in the default Suricata config file
	// /etc/suricata/suricata.yaml.
	suricataAntreaConfigData := fmt.Sprintf(`%%YAML 1.1
---
af-packet:
  - interface: %[1]s
    threads: auto
    cluster-id: 80
    cluster-type: cluster_flow
    defrag: no
    use-mmap: yes
    tpacket-v2: yes
    checksum-checks: no
    bpf-filter: "ip or ip6"
    copy-mode: ips
    copy-iface: %[2]s
  - interface:  %[2]s
    threads: auto
    cluster-id: 81
    cluster-type: cluster_flow
    defrag: no
    use-mmap: yes
    tpacket-v2: yes
    checksum-checks: no
    bpf-filter: "ip or ip6"
    copy-mode: ips
    copy-iface: %[1]s
multi-detect:
  enabled: yes
  selector: vlan
`, config.L7NetworkPolicyTargetPortName, config.L7NetworkPolicyReturnPortName)
	f, err := defaultFS.Create(antreaSuricataConfigPath)
	if err != nil {
		klog.ErrorS(err, "Failed to create Suricata config file", "FilePath", antreaSuricataConfigPath)
		return
	}
	defer f.Close()
	if _, err = f.WriteString(suricataAntreaConfigData); err != nil {
		klog.ErrorS(err, "Failed to write Suricata config file", "FilePath", antreaSuricataConfigPath)
		return
	}

	// Open the default Suricata config file /etc/suricata/suricata.yaml.
	f, err = defaultFS.OpenFile(defaultSuricataConfigPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		klog.ErrorS(err, "Failed to open default Suricata config file", "FilePath", defaultSuricataConfigPath)
		return
	}
	defer f.Close()
	// Include the config file /etc/suricata/antrea.yaml for Antrea in the default Suricata config file /etc/suricata/suricata.yaml.
	if _, err = f.WriteString(fmt.Sprintf("include: %s\n", antreaSuricataConfigPath)); err != nil {
		klog.ErrorS(err, "Failed to update default Suricata config file", "FilePath", defaultSuricataConfigPath)
		return
	}

	r.startSuricataFn()

	// Wait Suricata command socket file to be ready.
	err = wait.PollImmediate(100*time.Millisecond, 5*time.Second, func() (bool, error) {
		if _, err = defaultFS.Stat(suricataCommandSocket); err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		klog.ErrorS(err, "Failed to find Suricata command socket file")
	} else {
		klog.InfoS("Started Suricata instance successfully")
	}
}

func startSuricata() {
	// Start Suricata with default Suricata config file /etc/suricata/suricata.yaml.
	cmd := exec.Command("suricata", "-c", defaultSuricataConfigPath, "--af-packet")
	if err := cmd.Start(); err != nil {
		klog.ErrorS(err, "Failed to start Suricata instance")
	}
}

func suricataSc(scCmd string) (*scCmdRet, error) {
	cmd := exec.Command("suricatasc", "-c", scCmd)
	retBytes, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run Suricata command '%v': %w", scCmd, err)
	}
	var ret scCmdRet
	if err = json.Unmarshal(retBytes, &ret); err != nil {
		return nil, err
	}
	return &ret, nil
}
