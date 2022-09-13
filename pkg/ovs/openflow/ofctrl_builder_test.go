// Copyright 2020 Antrea Authors
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
	"fmt"
	"net"
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
)

type matchField struct {
	class   uint16
	field   uint8
	hasMask bool
	value   util.Message
	mask    util.Message
}

func checkMatchField(t *testing.T, expected *matchField, matchField openflow15.MatchField) {
	assert.Equal(t, expected.class, matchField.Class)
	assert.Equal(t, expected.field, matchField.Field)
	assert.Equal(t, expected.hasMask, matchField.HasMask)
	assert.Equal(t, expected.value, matchField.Value)
	assert.Equal(t, expected.mask, matchField.Mask)
}

func TestFlowBuilder(t *testing.T) {
	table := NewOFTable(tableID1, tableName, stageID, piplineID, missAction)
	table.SetNext(tableID2)
	table.(*ofTable).Table = new(ofctrl.Table)

	t.Run("MatchTunMetadata", func(t *testing.T) {
		testCases := []struct {
			index    int
			value    uint32
			expected *matchField
		}{
			{
				index: 1,
				value: uint32(0xfeef),
				expected: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_TUN_METADATA1,
					hasMask: true,
					value:   &openflow15.ByteArrayField{Data: []byte{0, 0, 0xfe, 0xef}, Length: 4},
					mask:    &openflow15.ByteArrayField{Data: []byte{0xff, 0xff, 0xff, 0xff}, Length: 4},
				},
			},
			{
				index: 2,
				value: uint32(0xabcdfeef),
				expected: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_TUN_METADATA2,
					hasMask: true,
					value:   &openflow15.ByteArrayField{Data: []byte{0xab, 0xcd, 0xfe, 0xef}, Length: 4},
					mask:    &openflow15.ByteArrayField{Data: []byte{0xff, 0xff, 0xff, 0xff}, Length: 4},
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).MatchTunMetadata(tc.index, tc.value).(*ofFlowBuilder)
			assert.Equal(t, []*ofctrl.NXTunMetadata{{ID: tc.index, Data: tc.value, Range: openflow15.NewNXRange(0, 31)}}, fb.ofFlow.Match.TunMetadatas)
			assert.Equal(t, []string{fmt.Sprintf("tun_metadata%d=0x%x", tc.index, tc.value)}, fb.matchers)

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expected, flowMod.Match.Fields[0])
		}

	})
	t.Run("MatchVLAN", func(t *testing.T) {
		mask := uint16(0xff)
		testCases := []struct {
			nonVLAN  bool
			vlanID   uint16
			vlanMask *uint16
			expected *matchField
		}{
			{
				nonVLAN: true,
				expected: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_VLAN_VID,
					value: &openflow15.VlanIdField{VlanId: 0},
				},
			},
			{
				nonVLAN: true,
				vlanID:  0xf1,
				expected: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_VLAN_VID,
					value: &openflow15.VlanIdField{VlanId: 0},
				},
			},
			{
				nonVLAN:  false,
				vlanID:   0xf1,
				vlanMask: &mask,
				expected: &matchField{
					class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field:   openflow15.OXM_FIELD_VLAN_VID,
					hasMask: true,
					value:   &openflow15.VlanIdField{VlanId: 0xf1 | openflow15.OFPVID_PRESENT},
					mask:    &openflow15.VlanIdField{VlanId: 0xff},
				},
			},
			{
				nonVLAN: false,
				vlanID:  0xf1,
				expected: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_VLAN_VID,
					value: &openflow15.VlanIdField{VlanId: 0xf1 | openflow15.OFPVID_PRESENT},
				},
			},
		}

		for _, tc := range testCases {
			fb := table.BuildFlow(1).MatchVLAN(tc.nonVLAN, tc.vlanID, tc.vlanMask).(*ofFlowBuilder)
			assert.Equal(t, tc.nonVLAN, fb.Match.NonVlan)
			assert.Equal(t, &tc.vlanID, fb.Match.VlanId)
			assert.Equal(t, tc.vlanMask, fb.Match.VlanMask)
			assert.Equal(t, []string{fmt.Sprintf("dl_vlan=%d", tc.vlanID)}, fb.matchers)

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expected, flowMod.Match.Fields[0])
		}
	})
	t.Run("SetHardTimeout", func(t *testing.T) {
		fb := table.BuildFlow(1).SetHardTimeout(uint16(3600)).(*ofFlowBuilder)
		assert.Equal(t, uint16(3600), fb.ofFlow.HardTimeout)

		flowMod := getFlowMod(t, fb.Done())
		assert.Equal(t, uint16(3600), flowMod.HardTimeout)
	})
	t.Run("SetIdleTimeout", func(t *testing.T) {
		fb := table.BuildFlow(1).SetIdleTimeout(uint16(3600)).(*ofFlowBuilder)
		assert.Equal(t, uint16(3600), fb.ofFlow.IdleTimeout)

		flowMod := getFlowMod(t, fb.Done())
		assert.Equal(t, uint16(3600), flowMod.IdleTimeout)
	})
	t.Run("MatchXXReg", func(t *testing.T) {
		testCases := []struct {
			regID              int
			data               []byte
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				regID:              0,
				data:               []byte{0x12, 0x34, 0x56},
				expectedMatcherStr: "xxreg0=0x123456",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_XXREG0,
					value: &openflow15.ByteArrayField{Data: []byte{0x12, 0x34, 0x56}, Length: 3},
				},
			},
			{
				regID:              1,
				data:               []byte{0x11, 0x22},
				expectedMatcherStr: "xxreg1=0x1122",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_XXREG1,
					value: &openflow15.ByteArrayField{Data: []byte{0x11, 0x22}, Length: 2},
				},
			},
			{
				regID:              2,
				data:               []byte{0xff, 0xff, 0xff, 0xff},
				expectedMatcherStr: "xxreg2=0xffffffff",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_XXREG2,
					value: &openflow15.ByteArrayField{Data: []byte{0xff, 0xff, 0xff, 0xff}, Length: 4},
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).MatchXXReg(tc.regID, tc.data).(*ofFlowBuilder)
			expectedXXRegs := []*ofctrl.XXRegister{{ID: tc.regID, Data: tc.data}}
			assert.Equal(t, expectedXXRegs, fb.Match.XxRegs)
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchRegMark/MatchRegFieldWithValue", func(t *testing.T) {
		mark1 := NewRegMark(NewRegField(1, 0, 31), 0xeeeeffff)
		mark2 := NewRegMark(NewRegField(2, 2, 5), 0xf)
		testCases := []struct {
			mark               *RegMark
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				mark:               mark1,
				expectedMatcherStr: "reg1=0xeeeeffff",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_REG1,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: mark1.value << mark1.field.rng[0]},
					mask:    &openflow15.Uint32Message{Data: mark1.field.GetRange().ToNXRange().ToUint32Mask()},
				},
			},
			{
				mark:               mark2,
				expectedMatcherStr: "reg2=0x3c/0x3c",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_REG2,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: mark2.value << mark2.field.rng[0]},
					mask:    &openflow15.Uint32Message{Data: mark2.field.GetRange().ToNXRange().ToUint32Mask()},
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).MatchRegMark(tc.mark).(*ofFlowBuilder)

			var expectedNXReg *ofctrl.NXRegister
			regID := tc.mark.field.regID
			data := tc.mark.value
			rng := tc.mark.field.rng
			if rng.Length() == 32 {
				expectedNXReg = &ofctrl.NXRegister{ID: regID, Data: data}
			} else {
				expectedNXReg = &ofctrl.NXRegister{ID: regID, Data: data, Range: rng.ToNXRange()}
			}
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])
			assert.Equal(t, 1, len(fb.Match.NxRegs))
			assert.Equal(t, expectedNXReg, fb.Match.NxRegs[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchCTState*", func(t *testing.T) {
		testCases := []struct {
			state              string
			set                bool
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				state:              "new",
				set:                true,
				expectedMatcherStr: "ct_state=+new",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 1},
					mask:    &openflow15.Uint32Message{Data: 1},
				},
			},
			{
				state:              "new",
				set:                false,
				expectedMatcherStr: "ct_state=-new",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x0},
					mask:    &openflow15.Uint32Message{Data: 0x1},
				},
			},
			{
				state:              "rel",
				set:                true,
				expectedMatcherStr: "ct_state=+rel",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x4},
					mask:    &openflow15.Uint32Message{Data: 0x4},
				},
			},
			{
				state:              "rel",
				set:                false,
				expectedMatcherStr: "ct_state=-rel",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x0},
					mask:    &openflow15.Uint32Message{Data: 0x4},
				},
			},
			{
				state:              "rpl",
				set:                true,
				expectedMatcherStr: "ct_state=+rpl",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x8},
					mask:    &openflow15.Uint32Message{Data: 0x8},
				},
			},
			{
				state:              "rpl",
				set:                false,
				expectedMatcherStr: "ct_state=-rpl",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x0},
					mask:    &openflow15.Uint32Message{Data: 0x8},
				},
			},
			{
				state:              "est",
				set:                true,
				expectedMatcherStr: "ct_state=+est",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x2},
					mask:    &openflow15.Uint32Message{Data: 0x2},
				},
			},
			{
				state:              "est",
				set:                false,
				expectedMatcherStr: "ct_state=-est",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x0},
					mask:    &openflow15.Uint32Message{Data: 0x2},
				},
			},
			{
				state:              "trk",
				set:                true,
				expectedMatcherStr: "ct_state=+trk",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x20},
					mask:    &openflow15.Uint32Message{Data: 0x20},
				},
			},
			{
				state:              "trk",
				set:                false,
				expectedMatcherStr: "ct_state=-trk",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x0},
					mask:    &openflow15.Uint32Message{Data: 0x20},
				},
			},
			{
				state:              "inv",
				set:                true,
				expectedMatcherStr: "ct_state=+inv",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x10},
					mask:    &openflow15.Uint32Message{Data: 0x10},
				},
			},
			{
				state:              "inv",
				set:                false,
				expectedMatcherStr: "ct_state=-inv",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x0},
					mask:    &openflow15.Uint32Message{Data: 0x10},
				},
			},
			{
				state:              "dnat",
				set:                true,
				expectedMatcherStr: "ct_state=+dnat",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x80},
					mask:    &openflow15.Uint32Message{Data: 0x80},
				},
			},
			{
				state:              "dnat",
				set:                false,
				expectedMatcherStr: "ct_state=-dnat",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x0},
					mask:    &openflow15.Uint32Message{Data: 0x80},
				},
			},
			{
				state:              "snat",
				set:                true,
				expectedMatcherStr: "ct_state=+snat",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x40},
					mask:    &openflow15.Uint32Message{Data: 0x40},
				},
			},
			{
				state:              "snat",
				set:                false,
				expectedMatcherStr: "ct_state=-snat",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_STATE,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x0},
					mask:    &openflow15.Uint32Message{Data: 0x40},
				},
			},
		}
		for _, tc := range testCases {
			var fb *ofFlowBuilder
			expectedCtStates := openflow15.NewCTStates()
			switch tc.state {
			case "new":
				fb = table.BuildFlow(1).MatchCTStateNew(tc.set).(*ofFlowBuilder)
				if tc.set {
					expectedCtStates.SetNew()
				} else {
					expectedCtStates.UnsetNew()
				}
			case "rel":
				fb = table.BuildFlow(1).MatchCTStateRel(tc.set).(*ofFlowBuilder)
				if tc.set {
					expectedCtStates.SetRel()
				} else {
					expectedCtStates.UnsetRel()
				}
			case "rpl":
				fb = table.BuildFlow(1).MatchCTStateRpl(tc.set).(*ofFlowBuilder)
				if tc.set {
					expectedCtStates.SetRpl()
				} else {
					expectedCtStates.UnsetRpl()
				}
			case "est":
				fb = table.BuildFlow(1).MatchCTStateEst(tc.set).(*ofFlowBuilder)
				if tc.set {
					expectedCtStates.SetEst()
				} else {
					expectedCtStates.UnsetEst()
				}
			case "trk":
				fb = table.BuildFlow(1).MatchCTStateTrk(tc.set).(*ofFlowBuilder)
				if tc.set {
					expectedCtStates.SetTrk()
				} else {
					expectedCtStates.UnsetTrk()
				}
			case "inv":
				fb = table.BuildFlow(1).MatchCTStateInv(tc.set).(*ofFlowBuilder)
				if tc.set {
					expectedCtStates.SetInv()
				} else {
					expectedCtStates.UnsetInv()
				}
			case "dnat":
				fb = table.BuildFlow(1).MatchCTStateDNAT(tc.set).(*ofFlowBuilder)
				if tc.set {
					expectedCtStates.SetDNAT()
				} else {
					expectedCtStates.UnsetDNAT()
				}
			case "snat":
				fb = table.BuildFlow(1).MatchCTStateSNAT(tc.set).(*ofFlowBuilder)
				if tc.set {
					expectedCtStates.SetSNAT()
				} else {
					expectedCtStates.UnsetSNAT()
				}
			}
			assert.Equal(t, expectedCtStates, fb.ctStates)
			assert.Equal(t, tc.expectedMatcherStr, fb.ctStateString)

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchPktMark", func(t *testing.T) {
		mask := uint32(0xf)
		testCases := []struct {
			value              uint32
			mask               *uint32
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				value:              2,
				mask:               &mask,
				expectedMatcherStr: "pkt_mark=2",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_PKT_MARK,
					hasMask: true,
					value:   &openflow15.Uint32Message{Data: 0x2},
					mask:    &openflow15.Uint32Message{Data: 0xf},
				},
			},
			{
				value:              8,
				expectedMatcherStr: "pkt_mark=8",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_PKT_MARK,
					value: &openflow15.Uint32Message{Data: 0x8},
				},
			},
		}

		for _, tc := range testCases {
			fb := table.BuildFlow(1).MatchPktMark(tc.value, tc.mask).(*ofFlowBuilder)
			assert.Equal(t, tc.value, fb.ofFlow.Match.PktMark)
			assert.Equal(t, tc.mask, fb.ofFlow.Match.PktMarkMask)
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchTunnelDst", func(t *testing.T) {
		testCases := []struct {
			ip                 net.IP
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				ip:                 net.ParseIP("1.1.1.1"),
				expectedMatcherStr: "tun_dst=1.1.1.1",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_TUN_IPV4_DST,
					value: &openflow15.TunnelIpv4DstField{TunnelIpv4Dst: net.ParseIP("1.1.1.1").To4()},
				},
			},
			{
				ip:                 net.ParseIP("255.255.255.255"),
				expectedMatcherStr: "tun_dst=255.255.255.255",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_TUN_IPV4_DST,
					value: &openflow15.TunnelIpv4DstField{TunnelIpv4Dst: net.ParseIP("255.255.255.255").To4()},
				},
			},
			{
				ip:                 net.ParseIP("fec0::1111"),
				expectedMatcherStr: "tun_ipv6_dst=fec0::1111",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_TUN_IPV6_DST,
					value: &openflow15.Ipv6DstField{Ipv6Dst: net.ParseIP("fec0::1111")},
				},
			},
			{
				ip:                 net.ParseIP("fe80::ffff"),
				expectedMatcherStr: "tun_ipv6_dst=fe80::ffff",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_TUN_IPV6_DST,
					value: &openflow15.Ipv6DstField{Ipv6Dst: net.ParseIP("fe80::ffff")},
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).MatchTunnelDst(tc.ip).(*ofFlowBuilder)
			assert.Equal(t, tc.ip, *fb.ofFlow.Match.TunnelDst)
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchCTLabelField", func(t *testing.T) {
		testCases := []struct {
			field              *CtLabel
			highLabel          uint64
			lowLabel           uint64
			expectedHighMask   uint64
			expectedLowMask    uint64
			expectedMatcherStr string
			expectedMatchField *matchField
		}{

			{
				field:              NewCTLabel(0, 0),
				lowLabel:           0x1,
				expectedLowMask:    0x1,
				expectedMatcherStr: "ct_label=0x1/0x1",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_LABEL,
					hasMask: true,
					value:   openflow15.NewCTLabelMatchField([16]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, nil).Value,
					mask:    openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}).Mask,
				},
			},
			{
				field:              NewCTLabel(1, 2),
				lowLabel:           0x7,
				expectedLowMask:    0x6,
				expectedMatcherStr: "ct_label=0x6/0x6",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_LABEL,
					hasMask: true,
					value:   openflow15.NewCTLabelMatchField([16]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6}, nil).Value,
					mask:    openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6}).Mask,
				},
			},
			{
				field:              NewCTLabel(127, 127),
				highLabel:          0x8000_0000_0000_0000,
				expectedHighMask:   0x8000_0000_0000_0000,
				expectedMatcherStr: "ct_label=0x80000000000000000000000000000000/0x80000000000000000000000000000000",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_LABEL,
					hasMask: true,
					value:   openflow15.NewCTLabelMatchField([16]byte{0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, nil).Value,
					mask:    openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0x80, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}).Mask,
				},
			},
			{
				field:              NewCTLabel(126, 127),
				highLabel:          0xa000_0000_0000_0000,
				expectedHighMask:   0xc000_0000_0000_0000,
				expectedMatcherStr: "ct_label=0x80000000000000000000000000000000/0xc0000000000000000000000000000000",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_LABEL,
					hasMask: true,
					value:   openflow15.NewCTLabelMatchField([16]byte{0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, nil).Value,
					mask:    openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0xc0, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}).Mask,
				},
			},
			{
				field:              NewCTLabel(0, 127),
				highLabel:          0x8000_0000_0000_0001,
				lowLabel:           0xa000_0000_0000_0001,
				expectedHighMask:   0xffff_ffff_ffff_ffff,
				expectedLowMask:    0xffff_ffff_ffff_ffff,
				expectedMatcherStr: "ct_label=0x8000000000000001a000000000000001/0xffffffffffffffffffffffffffffffff",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_LABEL,
					hasMask: true,
					value:   openflow15.NewCTLabelMatchField([16]byte{0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xa0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, nil).Value,
					mask:    openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}).Mask,
				},
			},
			{
				field:              NewCTLabel(32, 95),
				highLabel:          0x8000_0001,
				lowLabel:           0xa000_0001_0000_0000,
				expectedHighMask:   0xffff_ffff,
				expectedLowMask:    0xffff_ffff_0000_0000,
				expectedMatcherStr: "ct_label=0x80000001a000000100000000/0xffffffffffffffff00000000",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_LABEL,
					hasMask: true,
					value:   openflow15.NewCTLabelMatchField([16]byte{0x0, 0x0, 0x0, 0x0, 0x80, 0x0, 0x0, 0x1, 0xa0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0}, nil).Value,
					mask:    openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0}).Mask,
				},
			},
			{
				field:              NewCTLabel(0, 64),
				highLabel:          1,
				lowLabel:           0xa000_0000_0000_0001,
				expectedHighMask:   0x1,
				expectedLowMask:    0xffff_ffff_ffff_ffff,
				expectedMatcherStr: "ct_label=0x1a000000000000001/0x1ffffffffffffffff",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_LABEL,
					hasMask: true,
					value:   openflow15.NewCTLabelMatchField([16]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xa0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, nil).Value,
					mask:    openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}).Mask,
				},
			},
			{
				field:              NewCTLabel(0, 63),
				lowLabel:           0xa000_0000_0000_0001,
				expectedLowMask:    0xffff_ffff_ffff_ffff,
				expectedMatcherStr: "ct_label=0xa000000000000001/0xffffffffffffffff",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_LABEL,
					hasMask: true,
					value:   openflow15.NewCTLabelMatchField([16]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, nil).Value,
					mask:    openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}).Mask,
				},
			},
			{
				field:              NewCTLabel(64, 127),
				highLabel:          0xa000_0000_0000_0001,
				expectedHighMask:   0xffff_ffff_ffff_ffff,
				expectedMatcherStr: "ct_label=0xa0000000000000010000000000000000/0xffffffffffffffff0000000000000000",
				expectedMatchField: &matchField{
					openflow15.OXM_CLASS_NXM_1,
					openflow15.NXM_NX_CT_LABEL,
					true,
					openflow15.NewCTLabelMatchField([16]byte{0xa0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, nil).Value,
					openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}).Mask,
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).MatchCTLabelField(tc.highLabel, tc.lowLabel, tc.field).(*ofFlowBuilder)
			assert.Equal(t, tc.expectedHighMask, fb.Match.CtLabelHiMask)
			assert.Equal(t, tc.expectedLowMask, fb.Match.CtLabelLoMask)
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchInPort", func(t *testing.T) {
		testCases := []struct {
			inPort             uint32
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				inPort:             1,
				expectedMatcherStr: "in_port=1",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_IN_PORT,
					value: &openflow15.InPortField{InPort: 1},
				},
			},
			{
				inPort:             2,
				expectedMatcherStr: "in_port=2",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_IN_PORT,
					value: &openflow15.InPortField{InPort: 2},
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).MatchInPort(tc.inPort).(*ofFlowBuilder)
			assert.Equal(t, tc.inPort, fb.ofFlow.Match.InputPort)
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchSrcIP/MatchDstIP", func(t *testing.T) {
		testCases := []struct {
			isSrc              bool
			ip                 net.IP
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				isSrc:              true,
				ip:                 net.ParseIP("1.1.1.1"),
				expectedMatcherStr: "nw_src=1.1.1.1",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_IPV4_SRC,
					value: &openflow15.Ipv4SrcField{Ipv4Src: net.ParseIP("1.1.1.1")},
				},
			},
			{
				isSrc:              false,
				ip:                 net.ParseIP("1.1.1.1"),
				expectedMatcherStr: "nw_dst=1.1.1.1",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_IPV4_DST,
					value: &openflow15.Ipv4DstField{Ipv4Dst: net.ParseIP("1.1.1.1")},
				},
			},
			{
				isSrc:              true,
				ip:                 net.ParseIP("fec0::1111"),
				expectedMatcherStr: "ipv6_src=fec0::1111",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_IPV6_SRC,
					value: &openflow15.Ipv6SrcField{Ipv6Src: net.ParseIP("fec0::1111")},
				},
			},
			{
				isSrc:              false,
				ip:                 net.ParseIP("fec0::1111"),
				expectedMatcherStr: "ipv6_dst=fec0::1111",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_IPV6_DST,
					value: &openflow15.Ipv6DstField{Ipv6Dst: net.ParseIP("fec0::1111")},
				},
			},
		}
		for _, tc := range testCases {
			var fb *ofFlowBuilder
			if tc.isSrc {
				fb = table.BuildFlow(1).MatchSrcIP(tc.ip).(*ofFlowBuilder)
				assert.Equal(t, tc.ip, *fb.ofFlow.Match.IpSa)
			} else {
				fb = table.BuildFlow(1).MatchDstIP(tc.ip).(*ofFlowBuilder)
				assert.Equal(t, tc.ip, *fb.ofFlow.Match.IpDa)
			}
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchSrcIPNet/MatchDstIPNet", func(t *testing.T) {
		_, ipv4Net1, _ := net.ParseCIDR("1.1.1.0/24")
		_, ipv4Net2, _ := net.ParseCIDR("1.1.1.1/32")
		_, ipv6Net1, _ := net.ParseCIDR("fe80::1111/64")
		_, ipv6Net2, _ := net.ParseCIDR("fec0::ffff/128")
		testCases := []struct {
			isSrc              bool
			ipNet              *net.IPNet
			expectedMask       net.IP
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				isSrc:              true,
				ipNet:              ipv4Net1,
				expectedMask:       net.IP(ipv4Net1.Mask),
				expectedMatcherStr: "nw_src=1.1.1.0/24",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field:   openflow15.OXM_FIELD_IPV4_SRC,
					hasMask: true,
					value:   &openflow15.Ipv4SrcField{Ipv4Src: ipv4Net1.IP},
					mask:    &openflow15.Ipv4SrcField{Ipv4Src: net.IP(ipv4Net1.Mask)},
				},
			},
			{
				isSrc:              true,
				ipNet:              ipv4Net2,
				expectedMask:       net.IP(ipv4Net2.Mask),
				expectedMatcherStr: "nw_src=1.1.1.1/32",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field:   openflow15.OXM_FIELD_IPV4_SRC,
					hasMask: true,
					value:   &openflow15.Ipv4SrcField{Ipv4Src: ipv4Net2.IP},
					mask:    &openflow15.Ipv4SrcField{Ipv4Src: net.IP(ipv4Net2.Mask)},
				},
			},
			{
				isSrc:              true,
				ipNet:              ipv6Net1,
				expectedMask:       net.IP(ipv6Net1.Mask),
				expectedMatcherStr: "ipv6_src=fe80::/64",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field:   openflow15.OXM_FIELD_IPV6_SRC,
					hasMask: true,
					value:   &openflow15.Ipv6SrcField{Ipv6Src: ipv6Net1.IP},
					mask:    &openflow15.Ipv6SrcField{Ipv6Src: net.IP(ipv6Net1.Mask)},
				},
			},
			{
				isSrc: true,
				ipNet: ipv6Net2,
				expectedMask: net.IP(ipv6Net2.
					Mask),
				expectedMatcherStr: "ipv6_src=fec0::ffff/128",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field:   openflow15.OXM_FIELD_IPV6_SRC,
					hasMask: true,
					value:   &openflow15.Ipv6SrcField{Ipv6Src: ipv6Net2.IP},
					mask:    &openflow15.Ipv6SrcField{Ipv6Src: net.IP(ipv6Net2.Mask)},
				},
			},
			{
				isSrc:              false,
				ipNet:              ipv4Net1,
				expectedMask:       net.IP(ipv4Net1.Mask),
				expectedMatcherStr: "nw_dst=1.1.1.0/24",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field:   openflow15.OXM_FIELD_IPV4_DST,
					hasMask: true,
					value:   &openflow15.Ipv4DstField{Ipv4Dst: ipv4Net1.IP},
					mask:    &openflow15.Ipv4DstField{Ipv4Dst: net.IP(ipv4Net1.Mask)},
				},
			},
			{
				isSrc:              false,
				ipNet:              ipv4Net2,
				expectedMask:       net.IP(ipv4Net2.Mask),
				expectedMatcherStr: "nw_dst=1.1.1.1/32",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field:   openflow15.OXM_FIELD_IPV4_DST,
					hasMask: true,
					value:   &openflow15.Ipv4DstField{Ipv4Dst: ipv4Net2.IP},
					mask:    &openflow15.Ipv4DstField{Ipv4Dst: net.IP(ipv4Net2.Mask)},
				},
			},
			{
				isSrc:              false,
				ipNet:              ipv6Net1,
				expectedMask:       net.IP(ipv6Net1.Mask),
				expectedMatcherStr: "ipv6_dst=fe80::/64",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field:   openflow15.OXM_FIELD_IPV6_DST,
					hasMask: true,
					value:   &openflow15.Ipv6DstField{Ipv6Dst: ipv6Net1.IP},
					mask:    &openflow15.Ipv6DstField{Ipv6Dst: net.IP(ipv6Net1.Mask)},
				},
			},
			{
				isSrc:              false,
				ipNet:              ipv6Net2,
				expectedMask:       net.IP(ipv6Net2.Mask),
				expectedMatcherStr: "ipv6_dst=fec0::ffff/128",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field:   openflow15.OXM_FIELD_IPV6_DST,
					hasMask: true,
					value:   &openflow15.Ipv6DstField{Ipv6Dst: ipv6Net2.IP},
					mask:    &openflow15.Ipv6DstField{Ipv6Dst: net.IP(ipv6Net2.Mask)},
				},
			},
		}
		for _, tc := range testCases {
			var fb *ofFlowBuilder
			if tc.isSrc {
				fb = table.BuildFlow(1).MatchSrcIPNet(*tc.ipNet).(*ofFlowBuilder)
				assert.Equal(t, tc.ipNet.IP, *fb.ofFlow.Match.IpSa)
				assert.Equal(t, tc.expectedMask, *fb.ofFlow.Match.IpSaMask)
			} else {
				fb = table.BuildFlow(1).MatchDstIPNet(*tc.ipNet).(*ofFlowBuilder)
				assert.Equal(t, tc.ipNet.IP, *fb.ofFlow.Match.IpDa)
				assert.Equal(t, tc.expectedMask, *fb.ofFlow.Match.IpDaMask)
			}
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchICMPType/MatchICMPv6Type", func(t *testing.T) {
		testCases := []struct {
			isIPv6             bool
			icmpType           byte
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				isIPv6:             true,
				expectedMatcherStr: "icmp_type=0",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_ICMPV6_TYPE,
					value: &openflow15.IcmpTypeField{Type: 0},
				},
			},
			{
				isIPv6:             true,
				icmpType:           3,
				expectedMatcherStr: "icmp_type=3",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_ICMPV6_TYPE,
					value: &openflow15.IcmpTypeField{Type: 3},
				},
			},
			{
				expectedMatcherStr: "icmp_type=0",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_0,
					field: openflow15.NXM_OF_ICMP_TYPE,
					value: &openflow15.IcmpTypeField{Type: 0},
				},
			},
			{
				icmpType:           3,
				expectedMatcherStr: "icmp_type=3",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_0,
					field: openflow15.NXM_OF_ICMP_TYPE,
					value: &openflow15.IcmpTypeField{Type: 3},
				},
			},
		}
		for _, tc := range testCases {
			var fb *ofFlowBuilder
			if tc.isIPv6 {
				fb = table.BuildFlow(1).MatchICMPv6Type(tc.icmpType).(*ofFlowBuilder)
				assert.Equal(t, tc.icmpType, *fb.ofFlow.Match.Icmp6Type)
			} else {
				fb = table.BuildFlow(1).MatchICMPType(tc.icmpType).(*ofFlowBuilder)
				assert.Equal(t, tc.icmpType, *fb.ofFlow.Match.Icmp4Type)
			}
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchICMPCode/MatchICMPv6Code", func(t *testing.T) {
		testCases := []struct {
			isIPv6             bool
			icmpCode           byte
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				isIPv6:             true,
				icmpCode:           10,
				expectedMatcherStr: "icmp_code=10",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_ICMPV6_CODE,
					value: &openflow15.IcmpCodeField{Code: 10},
				},
			},
			{
				isIPv6:             true,
				icmpCode:           11,
				expectedMatcherStr: "icmp_code=11",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_ICMPV6_CODE,
					value: &openflow15.IcmpCodeField{Code: 11},
				},
			},
			{
				icmpCode:           10,
				expectedMatcherStr: "icmp_code=10",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_0,
					field: openflow15.NXM_OF_ICMP_CODE,
					value: &openflow15.IcmpCodeField{Code: 10},
				},
			},
			{
				icmpCode:           11,
				expectedMatcherStr: "icmp_code=11",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_0,
					field: openflow15.NXM_OF_ICMP_CODE,
					value: &openflow15.IcmpCodeField{Code: 11},
				},
			},
		}
		for _, tc := range testCases {
			var fb *ofFlowBuilder
			if tc.isIPv6 {
				fb = table.BuildFlow(1).MatchICMPv6Code(tc.icmpCode).(*ofFlowBuilder)
				assert.Equal(t, tc.icmpCode, *fb.ofFlow.Match.Icmp6Code)
			} else {
				fb = table.BuildFlow(1).MatchICMPCode(tc.icmpCode).(*ofFlowBuilder)
				assert.Equal(t, tc.icmpCode, *fb.ofFlow.Match.Icmp4Code)
			}
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchSrcMAC/MatchDstMAC", func(t *testing.T) {
		mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:fe")

		testCases := []struct {
			isSrc              bool
			mac                net.HardwareAddr
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				isSrc:              true,
				mac:                mac1,
				expectedMatcherStr: "dl_src=aa:bb:cc:dd:ee:ff",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_ETH_SRC,
					value: &openflow15.EthSrcField{EthSrc: mac1},
				},
			},
			{
				isSrc:              true,
				mac:                mac2,
				expectedMatcherStr: "dl_src=aa:bb:cc:dd:ee:fe",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_ETH_SRC,
					value: &openflow15.EthSrcField{EthSrc: mac2},
				},
			},
			{
				mac:                mac1,
				expectedMatcherStr: "dl_dst=aa:bb:cc:dd:ee:ff",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_ETH_DST,
					value: &openflow15.EthDstField{EthDst: mac1},
				},
			},
			{
				mac:                mac2,
				expectedMatcherStr: "dl_dst=aa:bb:cc:dd:ee:fe",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_ETH_DST,
					value: &openflow15.EthDstField{EthDst: mac2},
				},
			},
		}

		for _, tc := range testCases {
			var fb *ofFlowBuilder
			if tc.isSrc {
				fb = table.BuildFlow(1).MatchSrcMAC(tc.mac).(*ofFlowBuilder)
				assert.Equal(t, tc.mac, *fb.ofFlow.Match.MacSa)
			} else {
				fb = table.BuildFlow(1).MatchDstMAC(tc.mac).(*ofFlowBuilder)
				assert.Equal(t, tc.mac, *fb.ofFlow.Match.MacDa)
			}
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchARPSha/MatchARPTha", func(t *testing.T) {
		mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:fe")

		testCases := []struct {
			isSrc              bool
			mac                net.HardwareAddr
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				true,
				mac1,
				"arp_sha=aa:bb:cc:dd:ee:ff",
				&matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_ARP_SHA,
					value: &openflow15.ArpXHaField{ArpHa: mac1},
				},
			},
			{
				true,
				mac2,
				"arp_sha=aa:bb:cc:dd:ee:fe",
				&matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_ARP_SHA,
					value: &openflow15.ArpXHaField{ArpHa: mac2},
				},
			},
			{
				false,
				mac1,
				"arp_tha=aa:bb:cc:dd:ee:ff",
				&matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_ARP_THA,
					value: &openflow15.ArpXHaField{ArpHa: mac1},
				},
			},
			{
				false,
				mac2,
				"arp_tha=aa:bb:cc:dd:ee:fe",
				&matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_ARP_THA,
					value: &openflow15.ArpXHaField{ArpHa: mac2},
				},
			},
		}
		for _, tc := range testCases {
			var fb *ofFlowBuilder
			if tc.isSrc {
				fb = table.BuildFlow(1).MatchARPSha(tc.mac).(*ofFlowBuilder)
				assert.Equal(t, tc.mac, *fb.ofFlow.Match.ArpSha)
			} else {
				fb = table.BuildFlow(1).MatchARPTha(tc.mac).(*ofFlowBuilder)
				assert.Equal(t, tc.mac, *fb.ofFlow.Match.ArpTha)
			}
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchARPSpa/MatchARPTpa", func(t *testing.T) {
		testCases := []struct {
			isSrc              bool
			ip                 net.IP
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				isSrc:              true,
				ip:                 net.ParseIP("1.1.1.1"),
				expectedMatcherStr: "arp_spa=1.1.1.1",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_ARP_SPA,
					value: &openflow15.ArpXPaField{ArpPa: net.ParseIP("1.1.1.1")},
				},
			},
			{
				isSrc:              true,
				ip:                 net.ParseIP("2.2.2.2"),
				expectedMatcherStr: "arp_spa=2.2.2.2",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_ARP_SPA,
					value: &openflow15.ArpXPaField{ArpPa: net.ParseIP("2.2.2.2")},
				},
			},
			{
				ip:                 net.ParseIP("1.1.1.1"),
				expectedMatcherStr: "arp_tpa=1.1.1.1",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_ARP_TPA,
					value: &openflow15.ArpXPaField{ArpPa: net.ParseIP("1.1.1.1")},
				},
			},
			{
				ip:                 net.ParseIP("2.2.2.2"),
				expectedMatcherStr: "arp_tpa=2.2.2.2",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_ARP_TPA,
					value: &openflow15.ArpXPaField{ArpPa: net.ParseIP("2.2.2.2")},
				},
			},
		}
		for _, tc := range testCases {
			var fb *ofFlowBuilder
			if tc.isSrc {
				fb = table.BuildFlow(1).MatchARPSpa(tc.ip).(*ofFlowBuilder)
				assert.Equal(t, tc.ip, *fb.ofFlow.Match.ArpSpa)
			} else {
				fb = table.BuildFlow(1).MatchARPTpa(tc.ip).(*ofFlowBuilder)
				assert.Equal(t, tc.ip, *fb.ofFlow.Match.ArpTpa)
			}
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchARPOp", func(t *testing.T) {
		testCases := []struct {
			op                 uint16
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				op:                 1,
				expectedMatcherStr: "arp_op=1",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_ARP_OP,
					value: &openflow15.ArpOperField{ArpOper: 1},
				},
			},
			{
				op:                 2,
				expectedMatcherStr: "arp_op=2",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_ARP_OP,
					value: &openflow15.ArpOperField{ArpOper: 2},
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).MatchARPOp(tc.op).(*ofFlowBuilder)
			assert.Equal(t, tc.op, fb.ofFlow.Match.ArpOper)
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchIPDSCP", func(t *testing.T) {
		testCases := []struct {
			dscp               uint8
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				1,
				"nw_tos=4",
				&matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_IP_DSCP,
					value: &openflow15.IpDscpField{Dscp: 1},
				},
			},
			{
				2,
				"nw_tos=8",
				&matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_IP_DSCP,
					value: &openflow15.IpDscpField{Dscp: 2},
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).MatchIPDSCP(tc.dscp).(*ofFlowBuilder)
			assert.Equal(t, tc.dscp, fb.ofFlow.Match.IpDscp)
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchConjID", func(t *testing.T) {
		testCases := []struct {
			conjID             uint32
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				conjID:             1,
				expectedMatcherStr: "conj_id=1",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CONJ_ID,
					value: &openflow15.Uint32Message{Data: 1},
				},
			},
			{
				conjID:             2,
				expectedMatcherStr: "conj_id=2",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CONJ_ID,
					value: &openflow15.Uint32Message{Data: 2},
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).MatchConjID(tc.conjID).(*ofFlowBuilder)
			assert.Equal(t, tc.conjID, *fb.ofFlow.Match.ConjunctionID)
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchPriority", func(t *testing.T) {
		fb := table.BuildFlow(1).MatchPriority(uint16(100)).(*ofFlowBuilder)
		assert.Equal(t, uint16(100), fb.ofFlow.Match.Priority)

		flowMod := getFlowMod(t, fb.Done())
		assert.Equal(t, uint16(100), flowMod.Priority)
	})
	t.Run("MatchProtocol", func(t *testing.T) {
		testCases := []struct {
			protocol            Protocol
			expectedEthertype   uint16
			expectedIpProto     uint8
			expectedMatchFields []*matchField
		}{
			{
				protocol:          ProtocolIP,
				expectedEthertype: 0x0800,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x0800},
					},
				},
			},
			{
				protocol:          ProtocolIPv6,
				expectedEthertype: 0x86dd,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x86dd},
					},
				},
			},
			{
				protocol:          ProtocolARP,
				expectedEthertype: 0x0806,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x0806},
					},
				},
			},
			{
				protocol:          ProtocolTCP,
				expectedEthertype: 0x0800,
				expectedIpProto:   6,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x0800},
					},
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_IP_PROTO,
						value: &openflow15.IpProtoField{Protocol: 6},
					},
				},
			},
			{
				protocol:          ProtocolTCPv6,
				expectedEthertype: 0x86dd,
				expectedIpProto:   6,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x86dd},
					},
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_IP_PROTO,
						value: &openflow15.IpProtoField{Protocol: 6},
					},
				},
			},
			{
				protocol:          ProtocolUDP,
				expectedEthertype: 0x0800,
				expectedIpProto:   17,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x0800},
					},
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_IP_PROTO,
						value: &openflow15.IpProtoField{Protocol: 17},
					},
				},
			},
			{
				protocol:          ProtocolUDPv6,
				expectedEthertype: 0x86dd,
				expectedIpProto:   17,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x86dd},
					},
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_IP_PROTO,
						value: &openflow15.IpProtoField{Protocol: 17},
					},
				},
			},
			{
				protocol:          ProtocolSCTP,
				expectedEthertype: 0x800,
				expectedIpProto:   132,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x800},
					},
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_IP_PROTO,
						value: &openflow15.IpProtoField{Protocol: 132},
					},
				},
			},
			{
				protocol:          ProtocolSCTPv6,
				expectedEthertype: 0x86dd,
				expectedIpProto:   132,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x86dd},
					},
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_IP_PROTO,
						value: &openflow15.IpProtoField{Protocol: 132},
					},
				},
			},
			{
				protocol:          ProtocolICMP,
				expectedEthertype: 0x0800,
				expectedIpProto:   1,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x0800},
					},
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_IP_PROTO,
						value: &openflow15.IpProtoField{Protocol: 1},
					},
				},
			},
			{
				protocol:          ProtocolICMPv6,
				expectedEthertype: 0x86dd,
				expectedIpProto:   58,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x86dd},
					},
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_IP_PROTO,
						value: &openflow15.IpProtoField{Protocol: 58},
					},
				},
			},
			{
				protocol:          ProtocolIGMP,
				expectedEthertype: 0x0800,
				expectedIpProto:   2,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x0800},
					},
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_IP_PROTO,
						value: &openflow15.IpProtoField{Protocol: 2},
					},
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).MatchProtocol(tc.protocol).(*ofFlowBuilder)
			assert.Equal(t, tc.expectedEthertype, fb.ofFlow.Match.Ethertype)
			assert.Equal(t, tc.expectedIpProto, fb.ofFlow.Match.IpProto)
			assert.Equal(t, tc.protocol, fb.protocol)

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, len(tc.expectedMatchFields), len(flowMod.Match.Fields))
			for idx, expectedMatchField := range tc.expectedMatchFields {
				checkMatchField(t, expectedMatchField, flowMod.Match.Fields[idx])
			}
		}
	})
	t.Run("MatchIPProtocolValue", func(t *testing.T) {
		testCases := []struct {
			isIPv6              bool
			protoValue          uint8
			expectedEtherType   uint16
			expectedMatchFields []*matchField
		}{
			{
				protoValue:        protocol.Type_TCP,
				expectedEtherType: 0x0800,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x0800},
					},
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_IP_PROTO,
						value: &openflow15.IpProtoField{Protocol: 6},
					},
				},
			},
			{
				isIPv6:            true,
				protoValue:        protocol.Type_TCP,
				expectedEtherType: 0x086dd,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x086dd},
					},
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_IP_PROTO,
						value: &openflow15.IpProtoField{Protocol: 6},
					},
				},
			},
			{
				protoValue:        protocol.Type_UDP,
				expectedEtherType: 0x0800,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x0800},
					},
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_IP_PROTO,
						value: &openflow15.IpProtoField{Protocol: 17},
					},
				},
			},
			{
				isIPv6:            true,
				protoValue:        protocol.Type_UDP,
				expectedEtherType: 0x086dd,
				expectedMatchFields: []*matchField{
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_ETH_TYPE,
						value: &openflow15.EthTypeField{EthType: 0x086dd},
					},
					{
						class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
						field: openflow15.OXM_FIELD_IP_PROTO,
						value: &openflow15.IpProtoField{Protocol: 17},
					},
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).MatchIPProtocolValue(tc.isIPv6, tc.protoValue).(*ofFlowBuilder)
			assert.Equal(t, tc.expectedEtherType, fb.ofFlow.Match.Ethertype)
			assert.Equal(t, tc.protoValue, fb.ofFlow.Match.IpProto)

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, len(tc.expectedMatchFields), len(flowMod.Match.Fields))
			for idx, expectedMatchField := range tc.expectedMatchFields {
				checkMatchField(t, expectedMatchField, flowMod.Match.Fields[idx])
			}
		}
	})
	t.Run("MatchSrcPort/MatchDstPort", func(t *testing.T) {
		portMask := uint16(0xf000)
		testCases := []struct {
			isSrc              bool
			port               uint16
			portMask           *uint16
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				isSrc:              true,
				port:               0xf001,
				expectedMatcherStr: "tp_src=0xf001",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_TCP_SRC,
					value: &openflow15.PortField{Port: 0xf001},
				},
			},
			{
				isSrc:              true,
				port:               0xf001,
				portMask:           &portMask,
				expectedMatcherStr: "tp_src=0xf001/0xf000",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field:   openflow15.OXM_FIELD_TCP_SRC,
					hasMask: true,
					value:   &openflow15.PortField{Port: 0xf001},
					mask:    &openflow15.PortField{Port: portMask},
				},
			},
			{
				port:               0xf001,
				expectedMatcherStr: "tp_dst=0xf001",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field: openflow15.OXM_FIELD_TCP_DST,
					value: &openflow15.PortField{Port: 0xf001},
				},
			},
			{
				port:               0xf001,
				portMask:           &portMask,
				expectedMatcherStr: "tp_dst=0xf001/0xf000",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					field:   openflow15.OXM_FIELD_TCP_DST,
					hasMask: true,
					value:   &openflow15.PortField{Port: 0xf001},
					mask:    &openflow15.PortField{Port: portMask},
				},
			},
		}
		for _, tc := range testCases {
			var fb *ofFlowBuilder
			if tc.isSrc {
				fb = table.BuildFlow(1).MatchSrcPort(tc.port, tc.portMask).(*ofFlowBuilder)
				assert.Equal(t, tc.port, fb.ofFlow.Match.SrcPort)
				assert.Equal(t, tc.portMask, fb.ofFlow.Match.SrcPortMask)
			} else {
				fb = table.BuildFlow(1).MatchDstPort(tc.port, tc.portMask).(*ofFlowBuilder)
				assert.Equal(t, tc.port, fb.ofFlow.Match.DstPort)
				assert.Equal(t, tc.portMask, fb.ofFlow.Match.DstPortMask)
			}
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchCTSrcIP/MatchCTDstIP", func(t *testing.T) {
		testCases := []struct {
			isSrc              bool
			ip                 net.IP
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				isSrc:              true,
				ip:                 net.ParseIP("1.1.1.1"),
				expectedMatcherStr: "ct_nw_src=1.1.1.1",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CT_NW_SRC,
					value: &openflow15.Ipv4SrcField{Ipv4Src: net.ParseIP("1.1.1.1")},
				},
			},
			{
				isSrc:              true,
				ip:                 net.ParseIP("fec0::1111"),
				expectedMatcherStr: "ct_ipv6_src=fec0::1111",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CT_IPV6_SRC,
					value: &openflow15.Ipv6SrcField{Ipv6Src: net.ParseIP("fec0::1111")},
				},
			},
			{
				ip:                 net.ParseIP("1.1.1.1"),
				expectedMatcherStr: "ct_nw_dst=1.1.1.1",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CT_NW_DST,
					value: &openflow15.Ipv4DstField{Ipv4Dst: net.ParseIP("1.1.1.1")},
				},
			},
			{
				ip:                 net.ParseIP("fec0::1111"),
				expectedMatcherStr: "ct_ipv6_dst=fec0::1111",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CT_IPV6_DST,
					value: &openflow15.Ipv6DstField{Ipv6Dst: net.ParseIP("fec0::1111")},
				},
			},
		}
		for _, tc := range testCases {
			var fb *ofFlowBuilder
			if tc.isSrc {
				fb = table.BuildFlow(1).MatchCTSrcIP(tc.ip).(*ofFlowBuilder)
				if tc.ip.To4() != nil {
					assert.Equal(t, tc.ip, *fb.ofFlow.Match.CtIpSa)
				} else {
					assert.Equal(t, tc.ip, *fb.ofFlow.Match.CtIpv6Sa)
				}
			} else {
				fb = table.BuildFlow(1).MatchCTDstIP(tc.ip).(*ofFlowBuilder)
				if tc.ip.To4() != nil {
					assert.Equal(t, tc.ip, *fb.ofFlow.Match.CtIpDa)
				} else {
					assert.Equal(t, tc.ip, *fb.ofFlow.Match.CtIpv6Da)
				}
			}
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchCTSrcIPNet/MatchCTDstIPNet", func(t *testing.T) {
		_, ipv4Net1, _ := net.ParseCIDR("1.1.1.0/24")
		_, ipv4Net2, _ := net.ParseCIDR("1.1.1.1/32")
		_, ipv6Net1, _ := net.ParseCIDR("fe80::1111/64")
		_, ipv6Net2, _ := net.ParseCIDR("fec0::ffff/128")
		testCases := []struct {
			isSrc              bool
			ipNet              *net.IPNet
			expectedMask       net.IP
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				isSrc:              true,
				ipNet:              ipv4Net1,
				expectedMask:       net.IP(ipv4Net1.Mask),
				expectedMatcherStr: "ct_nw_src=1.1.1.0/24",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_NW_SRC,
					hasMask: true,
					value:   &openflow15.Ipv4SrcField{Ipv4Src: ipv4Net1.IP},
					mask:    &openflow15.Ipv4SrcField{Ipv4Src: net.IP(ipv4Net1.Mask)},
				},
			},
			{
				isSrc:              true,
				ipNet:              ipv4Net2,
				expectedMask:       net.IP(ipv4Net2.Mask),
				expectedMatcherStr: "ct_nw_src=1.1.1.1/32",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_NW_SRC,
					hasMask: true,
					value:   &openflow15.Ipv4SrcField{Ipv4Src: ipv4Net2.IP},
					mask:    &openflow15.Ipv4SrcField{Ipv4Src: net.IP(ipv4Net2.Mask)},
				},
			},
			{
				isSrc:              true,
				ipNet:              ipv6Net1,
				expectedMask:       net.IP(ipv6Net1.Mask),
				expectedMatcherStr: "ct_ipv6_src=fe80::/64",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_IPV6_SRC,
					hasMask: true,
					value:   &openflow15.Ipv6SrcField{Ipv6Src: ipv6Net1.IP},
					mask:    &openflow15.Ipv6SrcField{Ipv6Src: net.IP(ipv6Net1.Mask)},
				},
			},
			{
				isSrc:              true,
				ipNet:              ipv6Net2,
				expectedMask:       net.IP(ipv6Net2.Mask),
				expectedMatcherStr: "ct_ipv6_src=fec0::ffff/128",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_IPV6_SRC,
					hasMask: true,
					value:   &openflow15.Ipv6SrcField{Ipv6Src: ipv6Net2.IP},
					mask:    &openflow15.Ipv6SrcField{Ipv6Src: net.IP(ipv6Net2.Mask)},
				},
			},
			{
				ipNet:              ipv4Net1,
				expectedMask:       net.IP(ipv4Net1.Mask),
				expectedMatcherStr: "ct_nw_dst=1.1.1.0/24",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_NW_DST,
					hasMask: true,
					value:   &openflow15.Ipv4DstField{Ipv4Dst: ipv4Net1.IP},
					mask:    &openflow15.Ipv4DstField{Ipv4Dst: net.IP(ipv4Net1.Mask)},
				},
			},
			{
				ipNet:              ipv4Net2,
				expectedMask:       net.IP(ipv4Net2.Mask),
				expectedMatcherStr: "ct_nw_dst=1.1.1.1/32",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_NW_DST,
					hasMask: true,
					value:   &openflow15.Ipv4DstField{Ipv4Dst: ipv4Net2.IP},
					mask:    &openflow15.Ipv4DstField{Ipv4Dst: net.IP(ipv4Net2.Mask)},
				},
			},
			{
				ipNet:              ipv6Net1,
				expectedMask:       net.IP(ipv6Net1.Mask),
				expectedMatcherStr: "ct_ipv6_dst=fe80::/64",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_IPV6_DST,
					hasMask: true,
					value:   &openflow15.Ipv6DstField{Ipv6Dst: ipv6Net1.IP},
					mask:    &openflow15.Ipv6DstField{Ipv6Dst: net.IP(ipv6Net1.Mask)},
				},
			},
			{
				ipNet:              ipv6Net2,
				expectedMask:       net.IP(ipv6Net2.Mask),
				expectedMatcherStr: "ct_ipv6_dst=fec0::ffff/128",
				expectedMatchField: &matchField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_CT_IPV6_DST,
					hasMask: true,
					value:   &openflow15.Ipv6DstField{Ipv6Dst: ipv6Net2.IP},
					mask:    &openflow15.Ipv6DstField{Ipv6Dst: net.IP(ipv6Net2.Mask)},
				},
			},
		}
		for _, tc := range testCases {
			var fb *ofFlowBuilder
			if tc.isSrc {
				fb = table.BuildFlow(1).MatchCTSrcIPNet(*tc.ipNet).(*ofFlowBuilder)
				if tc.ipNet.IP.To4() != nil {
					assert.Equal(t, tc.ipNet.IP, *fb.ofFlow.Match.CtIpSa)
					assert.Equal(t, tc.expectedMask, *fb.ofFlow.Match.CtIpSaMask)
				} else {
					assert.Equal(t, tc.ipNet.IP, *fb.ofFlow.Match.CtIpv6Sa)
					assert.Equal(t, tc.expectedMask, *fb.ofFlow.Match.CtIpv6SaMask)
				}
			} else {
				fb = table.BuildFlow(1).MatchCTDstIPNet(*tc.ipNet).(*ofFlowBuilder)
				if tc.ipNet.IP.To4() != nil {
					assert.Equal(t, tc.ipNet.IP, *fb.ofFlow.Match.CtIpDa)
					assert.Equal(t, tc.expectedMask, *fb.ofFlow.Match.CtIpDaMask)
				} else {
					assert.Equal(t, tc.ipNet.IP, *fb.ofFlow.Match.CtIpv6Da)
					assert.Equal(t, tc.expectedMask, *fb.ofFlow.Match.CtIpv6DaMask)
				}
			}
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			checkMatchField(t, tc.expectedMatchField, flowMod.Match.Fields[0])
		}
	})
	t.Run("MatchCTSrcPort/MatchCTDstPort", func(t *testing.T) {
		testCases := []struct {
			isSrc              bool
			port               uint16
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				isSrc:              true,
				port:               10011,
				expectedMatcherStr: "ct_tp_src=10011",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CT_TP_SRC,
				},
			},
			{
				port:               10111,
				expectedMatcherStr: "ct_tp_dst=10111",
				expectedMatchField: &matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CT_TP_DST,
				},
			},
		}
		for _, tc := range testCases {
			var fb *ofFlowBuilder
			if tc.isSrc {
				fb = table.BuildFlow(1).MatchCTSrcPort(tc.port).(*ofFlowBuilder)
				assert.Equal(t, tc.port, fb.ofFlow.Match.CtTpSrcPort)
			} else {
				fb = table.BuildFlow(1).MatchCTDstPort(tc.port).(*ofFlowBuilder)
				assert.Equal(t, tc.port, fb.ofFlow.Match.CtTpDstPort)
			}
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			assert.Equal(t, tc.expectedMatchField.class, flowMod.Match.Fields[0].Class)
			assert.Equal(t, tc.expectedMatchField.field, flowMod.Match.Fields[0].Field)
		}
	})
	t.Run("MatchCTProtocol", func(t *testing.T) {
		testCases := []struct {
			protocol           Protocol
			expectedIpProto    uint8
			expectedMatcherStr string
			expectedMatchField *matchField
		}{
			{
				ProtocolTCP,
				6,
				"ct_nw_proto=6",
				&matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CT_NW_PROTO,
				},
			},
			{
				ProtocolTCPv6,
				6,
				"ct_nw_proto=6",
				&matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CT_NW_PROTO,
				},
			},
			{
				ProtocolUDP,
				17,
				"ct_nw_proto=17",
				&matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CT_NW_PROTO,
				},
			},
			{
				ProtocolUDPv6,
				17,
				"ct_nw_proto=17",
				&matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CT_NW_PROTO,
				},
			},
			{
				ProtocolSCTP,
				132,
				"ct_nw_proto=132",
				&matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CT_NW_PROTO,
				},
			},
			{
				ProtocolSCTPv6,
				132,
				"ct_nw_proto=132",
				&matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CT_NW_PROTO,
				},
			},
			{
				ProtocolICMP,
				1,
				"ct_nw_proto=1",
				&matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CT_NW_PROTO,
				},
			},
			{
				ProtocolICMPv6,
				58,
				"ct_nw_proto=58",
				&matchField{
					class: openflow15.OXM_CLASS_NXM_1,
					field: openflow15.NXM_NX_CT_NW_PROTO,
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).MatchCTProtocol(tc.protocol).(*ofFlowBuilder)
			assert.Equal(t, tc.expectedIpProto, fb.ofFlow.Match.CtIpProto)
			assert.Equal(t, 1, len(fb.matchers))
			assert.Equal(t, tc.expectedMatcherStr, fb.matchers[0])

			flowMod := getFlowMod(t, fb.Done())
			assert.Equal(t, 1, len(flowMod.Match.Fields))
			assert.Equal(t, tc.expectedMatchField.class, flowMod.Match.Fields[0].Class)
			assert.Equal(t, tc.expectedMatchField.field, flowMod.Match.Fields[0].Field)
		}
	})
	t.Run("Cookie", func(t *testing.T) {
		fb := table.BuildFlow(1).Cookie(uint64(10)).(*ofFlowBuilder)
		assert.Equal(t, uint64(10), fb.Flow.CookieID)

		flowMod := getFlowMod(t, fb.Done())
		assert.Equal(t, uint64(10), flowMod.Cookie)
	})
}
