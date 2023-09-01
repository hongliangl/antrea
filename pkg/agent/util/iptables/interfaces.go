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
	"k8s.io/apimachinery/pkg/util/intstr"

	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

type IPTablesEntryBuilder interface {
	MatchIPSetSrc(ipset string) IPTablesEntryBuilder
	MatchIPSetDst(ipset string) IPTablesEntryBuilder
	MatchTransProtocol(protocol v1beta2.Protocol) IPTablesEntryBuilder
	MatchDstPort(port *intstr.IntOrString, endPort *int32) IPTablesEntryBuilder
	MatchSrcPort(port, endPort *int32) IPTablesEntryBuilder
	MatchICMP(icmpType, icmpCode *int32, ipProtocol Protocol) IPTablesEntryBuilder
	MatchIGMP(igmpType *int32, groupAddress string) IPTablesEntryBuilder
	SetTarget(target string) IPTablesEntryBuilder
	SetComment(comment string) IPTablesEntryBuilder
	SetPosition(position int) IPTablesEntryBuilder
	CopyBuilder() IPTablesEntryBuilder
	Done() IPTablesEntry
}

type IPTablesEntry interface {
	Sync() error
	Delete() error
	GetString() string
}

type IPTablesChain interface {
	Sync() error
	Delete() error
}
