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
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	v1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

const (
	suricataRootConfigPath   = "/etc/suricata/suricata.yaml"
	suricataAntreaConfigPath = "/etc/suricata/antrea.yaml"

	signatureDir  = "/etc/suricata/rules"
	signatureFile = "antrea-l7-networkpolicy.rules"
	signaturePath = signatureDir + "/" + signatureFile

	addressGroupsPath = "/etc/suricata/antrea-address-groups.yaml"
	portGroupsPath    = "/etc/suricata/antrea-port-groups.yaml"

	defaultIPs   = "any"
	defaultPorts = "any"

	actionPass = "pass"
	actionDrop = "drop"

	protocolHTTP = "http"
)

type EnforcerOperations interface {
	SyncAddressGroups() error
	SyncPortGroups() error
	SyncSignatures() error
	ReloadSignatures()
}

type sidAllocator struct {
	sidCounter uint32
	recycled   []uint32
}

func (a *sidAllocator) allocate() uint32 {
	var id uint32
	if len(a.recycled) != 0 {
		id = a.recycled[len(a.recycled)-1]
		a.recycled = a.recycled[:len(a.recycled)-1]
	} else {
		a.sidCounter += 1
		id = a.sidCounter
	}
	return id
}

func (a *sidAllocator) Release(sids []uint32) {
	a.recycled = append(a.recycled, sids...)
}

func newSidAllocator() *sidAllocator {
	return &sidAllocator{}
}

type rule struct {
	srcIPs     string
	dstIPs     string
	dstPorts   string
	signatures sets.String
	sids       []uint32
}

type Enforcer struct {
	sidAllocator       *sidAllocator
	cachedRules        map[string]*rule
	enforcerOperations EnforcerOperations
}

func NewEnforcer() *Enforcer {
	ef := &Enforcer{
		cachedRules:  map[string]*rule{},
		sidAllocator: newSidAllocator(),
	}
	ef.enforcerOperations = ef
	return ef
}

func (e *Enforcer) SyncAddressGroups() error {
	groupBytes := bytes.NewBuffer(nil)
	groupBytes.WriteString("%YAML 1.1\n---\n\n")
	for _, rl := range e.cachedRules {
		groupBytes.WriteString(rl.srcIPs + "\n")
		groupBytes.WriteString(rl.dstIPs + "\n")
	}
	f, err := os.OpenFile(addressGroupsPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(groupBytes.Bytes()); err != nil {
		return err
	}
	return nil
}

func (e *Enforcer) SyncPortGroups() error {
	groupBytes := bytes.NewBuffer(nil)
	groupBytes.WriteString("%YAML 1.1\n---\n\n")
	for _, rl := range e.cachedRules {
		groupBytes.WriteString(rl.dstPorts + "\n")
	}
	f, err := os.OpenFile(portGroupsPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(groupBytes.Bytes()); err != nil {
		return err
	}
	return nil
}

func (e *Enforcer) SyncSignatures() error {
	signatureBytes := bytes.NewBuffer(nil)
	for _, rl := range e.cachedRules {
		for signature := range rl.signatures {
			signatureBytes.WriteString(signature + "\n")
		}
	}
	f, err := os.OpenFile(signaturePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(signatureBytes.Bytes()); err != nil {
		return err
	}
	return nil
}

func (e *Enforcer) ReloadSignatures() {
	cmd := exec.Command("suricatasc", "-c", "reload-rules")
	output, err := cmd.CombinedOutput()
	if err != nil {
		klog.ErrorS(err, "Failed to reload signatures for Suricata", "output", output)
	} else {
		klog.InfoS("Reloaded signatures for Suricata")
	}
}

func addressGroupParser(addressGroupVar string, group v1beta.GroupMemberSet) string {
	// Without any address, use 'any'.
	if len(group) == 0 {
		return fmt.Sprintf("%s: %s", addressGroupVar, defaultIPs)
	}
	// If there are addresses, merge them into a string.
	ips := make([]string, 0, len(group))
	for _, member := range group {
		for _, ip := range member.IPs {
			ips = append(ips, net.IP(ip).String())
		}
	}
	return fmt.Sprintf("%s: \"[%s]\"", addressGroupVar, strings.Join(ips, ","))
}

func portGroupParser(dstPortsVar string, l4Protocols []v1beta.Service) string {
	// Without L4 protocols, use 'any'.
	if len(l4Protocols) == 0 {
		return fmt.Sprintf("%s: %s", dstPortsVar, defaultPorts)
	}
	// If there are L4 protocols, merge all port ranges together regardless of their L4 protocols. Suricata can resolve
	// the patterns of ports:
	// - "80,90:91"
	// - "81:81,70:90"
	// - "any,80,http"
	// - "http,https"
	var portRanges []string
	for _, l4Protocol := range l4Protocols {
		var portRange string
		if l4Protocol.Port != nil {
			portRange = l4Protocol.Port.String()
			if l4Protocol.EndPort != nil {
				portRange = fmt.Sprintf("%s:%d", portRange, *l4Protocol.EndPort)
			}
		} else {
			portRange = defaultPorts
		}
		portRanges = append(portRanges, portRange)
	}
	return fmt.Sprintf("%s: \"[%s]\"", dstPortsVar, strings.Join(portRanges, ","))
}

func signatureGenerator(action, protocol, srcIPsVar, srcPorts, dstIPsVar, dstPortsVar string, msg string, protoKeywords []string, sid uint32) string {
	keywords := []string{fmt.Sprintf("msg:\"%s\";", msg)}
	keywords = append(keywords, protoKeywords...)
	keywords = append(keywords, fmt.Sprintf("sid:%d;", sid))
	signature := fmt.Sprintf("%s %s $%s %s -> $%s $%s (%s)", action, protocol, srcIPsVar, srcPorts, dstIPsVar, dstPortsVar, strings.Join(keywords, " "))
	return signature
}

func protocolHTTPParser(http *v1beta.HTTPProtocol) []string {
	var keywords []string
	if http.Path != "" {
		keywords = append(keywords, fmt.Sprintf("http.uri; content:\"%s\";", http.Path))
	}
	if http.Method != "" {
		keywords = append(keywords, fmt.Sprintf("http.method; content:\"%s\";", http.Method))
	}
	if http.Host != "" {
		keywords = append(keywords, fmt.Sprintf("http.host; content:\"%s\";", http.Host))
	}

	return keywords
}

func (e *Enforcer) Run(stopCh <-chan struct{}) {
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
    copy-mode: ips
    copy-iface: %[2]s
  - interface:  %[2]s
    threads: auto
    cluster-id: 81
    cluster-type: cluster_flow
    defrag: no
    use-mmap: yes
    tpacket-v2: yes
    copy-mode: ips
    copy-iface: %[1]s
vars:
  address-groups:
    include: %[3]s
  port-groups:
    include: %[4]s
default-rule-path: %[5]s
rule-files:
  - %[6]s
`, config.L7NPTrafficControlTargetPort, config.L7NPTrafficControlReturnPort, addressGroupsPath, portGroupsPath, signatureDir, signatureFile)

	if err := os.WriteFile(suricataAntreaConfigPath, []byte(suricataAntreaConfigData), 0600); err != nil {
		klog.ErrorS(err, "Failed to write config file", "FilePath", suricataAntreaConfigPath)
		return
	}

	f, err := os.OpenFile(suricataRootConfigPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		klog.ErrorS(err, "Failed to Suricata config file", "FilePath", suricataRootConfigPath)
		return
	}
	defer f.Close()

	if _, err = f.WriteString(fmt.Sprintf("include: %s\n", suricataAntreaConfigPath)); err != nil {
		klog.ErrorS(err, "Failed to update Suricata config file", "FilePath", suricataRootConfigPath)
		return
	}
	cmd := exec.Command("suricata", "-c", suricataRootConfigPath, "--af-packet")
	if err = cmd.Start(); err != nil {
		klog.ErrorS(err, "Failed to start Suricata")
	}

	klog.InfoS("Started Suricata instance")
	return
}

func (e *Enforcer) AddRule(ruleName string, from v1beta.GroupMemberSet, target v1beta.GroupMemberSet, l4Protocols []v1beta.Service, l7Protocols []v1beta.L7Protocol) error {
	ruleName = strings.Replace(ruleName, " ", "_", -1)

	// Generate name of source address group environment variable used in signatures.
	srcIPsVar := fmt.Sprintf("%s_ip_src", ruleName)
	// Generate value of source address group environment variable.
	srcIPs := addressGroupParser(srcIPsVar, from)

	// Generate name of destination IP group environment variable used in signatures.
	dstIPsVar := fmt.Sprintf("%s_ip_dst", ruleName)
	// Generate value of destination address group environment variable.
	dstIPs := addressGroupParser(dstIPsVar, target)

	// Generate source port part used in signatures.
	srcPorts := defaultPorts

	// Generate name of destination port group environment variable used in signatures.
	dstPortsVar := fmt.Sprintf("%s_tp_dst", ruleName)
	// Generate value of destination port group environment variable.
	dstPorts := portGroupParser(dstPortsVar, l4Protocols)

	// Generate signatures and sids used by these signatures. Note that, every signature needs a unique sid.
	signatures := sets.NewString()
	var sids []uint32
	for _, protocol := range l7Protocols {
		if protocol.HTTP != nil {
			sid := e.sidAllocator.allocate()
			signatureMsg := fmt.Sprintf("Allow by %s", ruleName)
			protoKeywords := protocolHTTPParser(protocol.HTTP)
			signature := signatureGenerator(actionPass, protocolHTTP, srcIPsVar, srcPorts, dstIPsVar, dstPortsVar, signatureMsg, protoKeywords, sid)
			sids = append(sids, sid)
			signatures.Insert(signature)

			sid = e.sidAllocator.allocate()
			signatureMsg = fmt.Sprintf("Drop by %s", ruleName)
			defaultDropSignature := signatureGenerator(actionDrop, protocolHTTP, srcIPsVar, srcPorts, dstIPsVar, dstPortsVar, signatureMsg, nil, sid)
			sids = append(sids, sid)
			signatures.Insert(defaultDropSignature)

			klog.V(4).InfoS("Syncing signatures",
				"RuleName", ruleName,
				"SrcIPs", srcIPs,
				"DstIPs", dstIPs,
				"DstPorts", dstPorts,
				"Signatures", []string{signature, defaultDropSignature})
		}
	}

	newRule := &rule{
		srcIPs:     srcIPs,
		dstIPs:     dstIPs,
		dstPorts:   dstPorts,
		signatures: signatures,
		sids:       sids,
	}
	var needUpdateAddressGroups, needUpdatePortGroups, needUpdateSignatures bool
	curRule, exist := e.cachedRules[ruleName]
	if exist {
		// If source or destination address group of the new rule is different from the cached rule, config file storing
		// address groups should be updated.
		if curRule.srcIPs != newRule.srcIPs || curRule.dstIPs != newRule.dstIPs {
			needUpdateAddressGroups = true
		}
		// If destination port group of the new rule is different from the cached rule, config file storing port groups
		// should be updated.
		if curRule.dstPorts != newRule.dstPorts {
			needUpdatePortGroups = true
		}
		// If signatures of the new rule are different from the cached rule, config file storing signatures should be
		// updated.
		if !curRule.signatures.Equal(newRule.signatures) {
			needUpdateSignatures = true
		}
	} else {
		needUpdateAddressGroups = true
		needUpdatePortGroups = true
		needUpdateSignatures = true
	}

	// Release the sids used by stale signatures.
	if curRule != nil {
		e.sidAllocator.Release(curRule.sids)
	}
	// Update cached rules.
	e.cachedRules[ruleName] = newRule

	// Sync address groups to corresponding config file from cached rules.
	if needUpdateAddressGroups {
		if err := e.enforcerOperations.SyncAddressGroups(); err != nil {
			return err
		}
	}
	// Sync port groups to corresponding config file from cached rules.
	if needUpdatePortGroups {
		if err := e.enforcerOperations.SyncPortGroups(); err != nil {
			return err
		}
	}
	// Sync signatures to corresponding config file from cached rules.
	if needUpdateSignatures {
		if err := e.enforcerOperations.SyncSignatures(); err != nil {
			return err
		}
	}

	// Reload updated signatures from config files.
	e.enforcerOperations.ReloadSignatures()

	return nil
}

func (e *Enforcer) DeleteRule(name string) error {
	name = strings.Replace(name, " ", "_", -1)

	if curRule, exist := e.cachedRules[name]; exist {
		klog.V(4).InfoS("Deleting signatures", "Name", name, "Signatures", curRule.signatures, "srcIPGroup", curRule.srcIPs, "dstIPGroup", curRule.dstIPs)

		// Release the sids used by signatures to be deleted.
		e.sidAllocator.Release(curRule.sids)
		// Update cached rules.
		delete(e.cachedRules, name)

		// Sync address groups to corresponding config file from cached rules.
		if err := e.enforcerOperations.SyncAddressGroups(); err != nil {
			return err
		}
		// Sync port groups to corresponding config file from cached rules.
		if err := e.enforcerOperations.SyncPortGroups(); err != nil {
			return err
		}
		// Sync signatures to corresponding config file from cached rules.
		if err := e.enforcerOperations.SyncSignatures(); err != nil {
			return err
		}

		// Reload updated signatures from config files.
		e.enforcerOperations.ReloadSignatures()
	}
	return nil
}
