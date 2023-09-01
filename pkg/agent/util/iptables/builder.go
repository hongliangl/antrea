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

package iptables

import (
	"fmt"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/intstr"

	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

type iptablesEntry struct {
	client   Interface
	table    string
	chain    string
	position int
	protocol Protocol
	specs    strings.Builder
}

type iptablesEntryBuilder struct {
	iptablesEntry
}

func NewEntryBuilder(client Interface, table string, chain string, protocol Protocol) IPTablesEntryBuilder {
	builder := &iptablesEntryBuilder{
		iptablesEntry{
			client:   client,
			table:    table,
			chain:    chain,
			protocol: protocol,
		},
	}
	return builder
}

func (b *iptablesEntryBuilder) MatchIPSetSrc(ipset string) IPTablesEntryBuilder {
	matchStr := fmt.Sprintf("-m set --match-ipset %s src ", ipset)
	b.specs.WriteString(matchStr)
	return b
}

func (b *iptablesEntryBuilder) MatchIPSetDst(ipset string) IPTablesEntryBuilder {
	matchStr := fmt.Sprintf("-m set --match-ipset %s dst ", ipset)
	b.specs.WriteString(matchStr)
	return b
}

func (b *iptablesEntryBuilder) MatchTransProtocol(protocol v1beta2.Protocol) IPTablesEntryBuilder {
	var protoStr string
	switch protocol {
	case v1beta2.ProtocolTCP:
		protoStr = "tcp"
	case v1beta2.ProtocolUDP:
		protoStr = "udp"
	case v1beta2.ProtocolSCTP:
		protoStr = "sctp"
	}
	matchStr := fmt.Sprintf("-p %s", protoStr)
	b.specs.WriteString(matchStr)
	return b
}

func (b *iptablesEntryBuilder) MatchDstPort(port *intstr.IntOrString, endPort *int32) IPTablesEntryBuilder {
	if port == nil {
		return b
	}
	var matchStr string
	if endPort != nil {
		matchStr = fmt.Sprintf("--dport %s:%d ", port.String(), *endPort)
	} else {
		matchStr = fmt.Sprintf("--dport %s ", port.String())
	}
	b.specs.WriteString(matchStr)
	return b
}

func (b *iptablesEntryBuilder) MatchSrcPort(port, endPort *int32) IPTablesEntryBuilder {
	if port == nil {
		return b
	}
	var matchStr string
	if endPort != nil {
		matchStr = fmt.Sprintf("--sport %d:%d ", *port, *endPort)
	} else {
		matchStr = fmt.Sprintf("--sport %d ", *port)
	}
	b.specs.WriteString(matchStr)
	return b
}

func (b *iptablesEntryBuilder) MatchICMP(icmpType, icmpCode *int32, ipProtocol Protocol) IPTablesEntryBuilder {
	parts := []string{"-p"}
	icmpTypeStr := "icmp"
	if ipProtocol != ProtocolIPv4 {
		icmpTypeStr = "icmpv6"
	}
	parts = append(parts, icmpTypeStr)

	if icmpType != nil {
		icmpTypeFlag := "--icmp-type"
		if ipProtocol != ProtocolIPv4 {
			icmpTypeFlag = "--icmpv6-type"
		}

		if icmpCode != nil {
			parts = append(parts, icmpTypeFlag, fmt.Sprintf("%d/%d", *icmpType, *icmpCode))
		} else {
			parts = append(parts, icmpTypeFlag, strconv.Itoa(int(*icmpType)))
		}
	}
	b.specs.WriteString(strings.Join(parts, " "))
	b.specs.WriteByte(' ')

	return b
}

func (b *iptablesEntryBuilder) MatchIGMP(igmpType *int32, groupAddress string) IPTablesEntryBuilder {
	parts := []string{"-p", "igmp"}
	if igmpType != nil && *igmpType == crdv1beta1.IGMPQuery {
		parts = append(parts, "-d", groupAddress)
	}
	b.specs.WriteString(strings.Join(parts, " "))
	b.specs.WriteByte(' ')

	return b
}

func (b *iptablesEntryBuilder) SetTarget(target string) IPTablesEntryBuilder {
	targetStr := fmt.Sprintf("-j %s ", target)
	b.specs.WriteString(targetStr)
	return b
}

func (b *iptablesEntryBuilder) SetComment(comment string) IPTablesEntryBuilder {
	commentStr := fmt.Sprintf("-m comment --comment %s ", comment)
	b.specs.WriteString(commentStr)
	return b
}

func (b *iptablesEntryBuilder) SetPosition(position int) IPTablesEntryBuilder {
	b.position = position
	return b
}

func (b *iptablesEntryBuilder) CopyBuilder() IPTablesEntryBuilder {
	copiedSpec := strings.Builder{}
	copiedSpec.WriteString(b.specs.String())

	builder := &iptablesEntryBuilder{
		iptablesEntry{
			table:    b.table,
			chain:    b.chain,
			protocol: b.protocol,
			specs:    copiedSpec,
		},
	}
	return builder
}

func (b *iptablesEntryBuilder) Done() IPTablesEntry {
	return &b.iptablesEntry
}

func (e *iptablesEntry) Sync() error {
	var err error
	if e.position != 0 {
		err = e.client.InsertRule(e.protocol, e.table, e.chain, []string{e.specs.String()}, e.position)
	} else {
		err = e.client.AppendRule(e.protocol, e.table, e.chain, []string{e.specs.String()})
	}
	return err
}

func (e *iptablesEntry) Update() error {
	var err error
	if e.position != 0 {
		err = e.client.ReplaceRule(e.protocol, e.table, e.chain, []string{e.specs.String()}, e.position)
	} else {
		err = fmt.Errorf("error replace a iptables entry since position is not set")
	}
	return err
}

func (e *iptablesEntry) Delete() error {
	return e.client.DeleteRule(e.protocol, e.table, e.chain, []string{e.specs.String()})
}

func (e *iptablesEntry) GetString() string {
	return fmt.Sprintf("*%s -A %s %s", e.table, e.chain, e.specs.String())
}

type iptablesChain struct {
	client   Interface
	protocol Protocol
	table    string
	name     string
}

func NewIPTablesChain(client Interface, table string, name string, protocol Protocol) IPTablesChain {
	return &iptablesChain{
		client:   client,
		protocol: protocol,
		table:    table,
		name:     name,
	}
}

func (c *iptablesChain) Sync() error {
	// If the chain does not exist, this operation will create a new chain.
	return c.client.ClearChain(c.protocol, c.table, c.name)
}

func (c *iptablesChain) Delete() error {
	return c.client.DeleteChain(c.protocol, c.table, c.name)
}
