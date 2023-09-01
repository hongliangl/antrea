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

package ipset

import (
	"net"

	"k8s.io/apimachinery/pkg/util/sets"

	v1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

type IPSetEntry struct {
	client Interface
	name   string
	isIPv6 bool
	ips    sets.Set[string]
}

func NewIPSet(client Interface, name string, members v1beta.GroupMemberSet, isIPv6 bool) *IPSetEntry {
	ips := sets.New[string]()
	for _, member := range members {
		for _, ip := range member.IPs {
			ipAddr := net.IP(ip)
			if isIPv6 && ipAddr.To16() != nil || !isIPv6 && ipAddr.To4() != nil {
				ips.Insert(ipAddr.String())
			}
		}
	}
	return &IPSetEntry{
		client: client,
		name:   name,
		ips:    ips,
		isIPv6: isIPv6,
	}
}

func (i *IPSetEntry) Sync() error {
	if err := i.client.CreateIPSet(i.name, HashIP, i.isIPv6); err != nil {
		return err
	}
	if err := i.client.ClearIPSet(i.name); err != nil {
		return err
	}
	for ip := range i.ips {
		if err := i.client.AddEntry(i.name, ip); err != nil {
			return err
		}
	}

	return nil
}

func (i *IPSetEntry) Delete() error {
	return i.client.DelIPSet(i.name)
}

func (i *IPSetEntry) Same(e *IPSetEntry) bool {
	if i.name != e.name {
		return false
	}
	if i.isIPv6 != e.isIPv6 {
		return false
	}
	if len(i.ips.Difference(e.ips)) > 0 {
		return false
	}
	return true
}

func (i *IPSetEntry) GetName() string {
	return i.name
}
