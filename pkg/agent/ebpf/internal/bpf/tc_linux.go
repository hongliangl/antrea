// Copyright 2026 Antrea Authors
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

//go:build linux

package bpf

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

// filterPriority and filterNamePrefix identify this datapath's TC filters across Agent restarts.
const (
	filterPriority   = 0xC000
	filterNamePrefix = "antrea_hostdp_"
)

// Attachment is a program attached to one hook, and knows how to undo it.
type Attachment struct {
	// linkFD is the descriptor of the link, or -1 when a filter was used instead.
	linkFD  int
	ifIndex int
	ingress bool
	name    string
}

// linkCreateAttr matches the BPF_LINK_CREATE fields used for a TCX attachment in Linux union bpf_attr.
// The corresponding layout in include/uapi/linux/bpf.h is:
//
//	struct { /* BPF_LINK_CREATE member of union bpf_attr */
//	    __u32 prog_fd;
//	    __u32 target_ifindex; /* union target_fd / target_ifindex */
//	    __u32 attach_type;
//	    __u32 flags;
//	    union {
//	        /* Other link types use this union for their own attributes. */
//	        struct {
//	            __u32 relative_fd;
//	            __u64 expected_revision;
//	        } tcx;
//	    };
//	};
//
// The union members overlap at offset 16. padding aligns expectedRevision to offset 24, as required by __u64.
// This structure passes only the TCX fields used here; the kernel treats omitted attributes as zero.
type linkCreateAttr struct {
	progFD           uint32
	targetIfIndex    uint32
	attachType       uint32
	flags            uint32
	relativeFD       uint32
	padding          uint32
	expectedRevision uint64
}

// Attach puts a program on the ingress or egress hook of an interface, through a link if the kernel has
// them and through a filter if it does not.
func Attach(progFD, ifIndex int, ingress bool, name string) (*Attachment, error) {
	linkFD, err := createTCXLink(progFD, ifIndex, ingress)
	if err == nil {
		return &Attachment{
			linkFD:  linkFD,
			ifIndex: ifIndex,
			ingress: ingress,
			name:    name}, nil
	}
	if !isUnsupported(err) {
		return nil, fmt.Errorf("attaching %s to interface %d with a link: %w", name, ifIndex, err)
	}
	klog.V(2).InfoS("The kernel has no support for BPF links on traffic control, using a filter instead",
		"program", name,
		"ifIndex", ifIndex,
		"err", err)

	if err = attachFilter(progFD, ifIndex, ingress, name); err != nil {
		return nil, err
	}
	return &Attachment{
		linkFD:  -1,
		ifIndex: ifIndex,
		ingress: ingress,
		name:    name}, nil
}

// Attached reports whether the attachment still exists on its interface.
// TCX links last until detached or the interface is removed; legacy filters are checked through netlink.
func (a *Attachment) Attached() (bool, error) {
	if a.linkFD >= 0 {
		return true, nil
	}
	return hasFilter(a.ifIndex, a.ingress, a.name)
}

// Detach releases the link or removes the owned TC filters.
func (a *Attachment) Detach() error {
	if a.linkFD >= 0 {
		// Closing the descriptor is what detaches the program.
		return unix.Close(a.linkFD)
	}
	return removeFilters(a.ifIndex, a.ingress)
}

// createTCXLink attaches a program through a kernel-managed link. It requires kernel 6.6 or later.
func createTCXLink(progFD, ifIndex int, ingress bool) (int, error) {
	attachType := uint32(bpfTCXEgress)
	if ingress {
		attachType = bpfTCXIngress
	}
	attr := linkCreateAttr{
		progFD:        uint32(progFD),
		targetIfIndex: uint32(ifIndex),
		attachType:    attachType,
	}
	fd, err := bpf(bpfLinkCreate, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return -1, err
	}
	return int(fd), nil
}

// attachFilter ensures the clsact qdisc exists and creates or replaces the program's filter.
func attachFilter(progFD, ifIndex int, ingress bool, name string) error {
	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
	// The qdisc is shared with whoever else uses these hooks, so it is added if missing and never removed.
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("adding the clsact qdisc to interface %d: %w", ifIndex, err)
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifIndex,
			Parent:    parentOf(ingress),
			Handle:    netlink.MakeHandle(0, 1),
			Priority:  filterPriority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:   progFD,
		Name: filterNamePrefix + name,
		// Without this the filter's verdict is a classification, and the program's own verdict, which
		// is what says whether the packet was redirected, is ignored.
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("adding the filter for %s to interface %d: %w", name, ifIndex, err)
	}
	return nil
}

// hasFilter reports whether the filter of a program is on one hook of an interface. Something else managing
// traffic control on the interface can remove it, and the interface does not have to be recreated for that.
func hasFilter(ifIndex int, ingress bool, name string) (bool, error) {
	filters, err := ownedFilters(ifIndex, ingress)
	if err != nil {
		return false, err
	}
	for _, f := range filters {
		if f.Name == filterNamePrefix+name {
			return true, nil
		}
	}
	return false, nil
}

// removeFilters removes the filters this datapath owns from one hook of an interface, whether this process
// added them or a previous one did.
func removeFilters(ifIndex int, ingress bool) error {
	filters, err := ownedFilters(ifIndex, ingress)
	if err != nil {
		return err
	}
	for _, bpfFilter := range filters {
		if err := netlink.FilterDel(bpfFilter); err != nil {
			return fmt.Errorf("removing filter %s from interface %d: %w", bpfFilter.Name, ifIndex, err)
		}
		klog.V(2).InfoS("Removed a traffic control filter of the eBPF host datapath",
			"name", bpfFilter.Name,
			"ifIndex", ifIndex)
	}
	return nil
}

// ownedFilters returns the filters this datapath owns on one hook of an interface, whether this process added
// them or a previous one did.
func ownedFilters(ifIndex int, ingress bool) ([]*netlink.BpfFilter, error) {
	filters, err := netlink.FilterList(&netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Index: ifIndex}},
		parentOf(ingress))
	if err != nil {
		// The interface having no qdisc, or being gone along with its qdisc, is not an error: there is
		// then no filter.
		if errorIs(err, unix.ENOENT) || errorIs(err, unix.ENODEV) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing the filters of interface %d: %w", ifIndex, err)
	}
	var owned []*netlink.BpfFilter
	for _, f := range filters {
		bpfFilter, ok := f.(*netlink.BpfFilter)
		if ok && strings.HasPrefix(bpfFilter.Name, filterNamePrefix) {
			owned = append(owned, bpfFilter)
		}
	}
	return owned, nil
}

func parentOf(ingress bool) uint32 {
	if ingress {
		return netlink.HANDLE_MIN_INGRESS
	}
	return netlink.HANDLE_MIN_EGRESS
}

// isUnsupported reports whether the kernel does not support this BPF command or attachment type.
func isUnsupported(err error) bool {
	return errorIs(err, unix.EINVAL) ||
		errorIs(err, unix.ENOSYS) ||
		errorIs(err, unix.EOPNOTSUPP)
}

func errorIs(err error, errno unix.Errno) bool {
	e, ok := err.(unix.Errno)
	return ok && e == errno
}
