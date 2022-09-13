// Copyright 2022 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openflow

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
)

var (
	tableID1   = uint8(1)
	tableID2   = uint8(2)
	tableName  = "testTable"
	stageID    = StageID(0)
	piplineID  = PipelineID(0)
	missAction = TableMissActionNext
)

type actionSetField struct {
	class uint16
	field uint8

	ethSrc        net.HardwareAddr
	ethDst        net.HardwareAddr
	arpXHa        net.HardwareAddr
	arpXPa        net.IP
	ipv4Src       net.IP
	ipv4Dst       net.IP
	ipv6Src       net.IP
	ipv6Dst       net.IP
	tunnelIPv4Dst net.IP
	vlanId        uint16
	arpOper       uint16

	fieldValue util.Message
	fieldMask  util.Message
}
type actionCopyField struct {
	oxmIdSrcClass uint16
	oxmIdDstClass uint16
	oxmIdSrcField uint8
	oxmIdDstField uint8
	nBits         uint16
	srcOffset     uint16
	dstOffset     uint16
}
type nxActionOutputReg struct {
	class    uint16
	field    uint8
	ofsNbits uint16
	regID    uint8
}
type nxActionConnTrack struct {
	flags        uint16
	zoneSrc      uint32
	zoneOfsNbits uint16
	recircTable  uint8
}
type nxActionCTNAT struct {
	flags         uint16
	rangeIPv4Min  net.IP
	rangeIPv4Max  net.IP
	rangeIPv6Min  net.IP
	rangeIPv6Max  net.IP
	rangeProtoMin *uint16
	rangeProtoMax *uint16
}

func newExpectedNXActionOutputReg(class uint16, field uint8, regID uint8, rng *Range) *nxActionOutputReg {
	return &nxActionOutputReg{
		class:    class,
		field:    field,
		ofsNbits: rng.ToNXRange().ToOfsBits(),
		regID:    regID,
	}
}

func checkNXActionOutputReg(t *testing.T, expected *nxActionOutputReg, action openflow15.Action) {
	assert.IsType(t, &openflow15.NXActionOutputReg{}, action)
	a := action.(*openflow15.NXActionOutputReg)
	assert.Equal(t, expected.class, a.SrcField.Class)
	assert.Equal(t, expected.field, a.SrcField.Field)
	assert.Equal(t, expected.regID, a.SrcField.Field)
	assert.Equal(t, expected.ofsNbits, a.OfsNbits)
}

func checkActionSetField(t *testing.T, expected []*actionSetField, actions []openflow15.Action) {
	assert.Equal(t, len(expected), len(actions))
	for i := 0; i < len(actions); i++ {
		assert.IsType(t, &openflow15.ActionSetField{}, actions[i])
		a := actions[i].(*openflow15.ActionSetField)
		assert.Equal(t, expected[i].class, a.Field.Class)
		assert.Equal(t, expected[i].field, a.Field.Field)

		switch a.Field.Value.(type) {
		case *openflow15.EthSrcField:
			assert.Equal(t, expected[i].ethSrc, a.Field.Value.(*openflow15.EthSrcField).EthSrc)
		case *openflow15.EthDstField:
			assert.Equal(t, expected[i].ethDst, a.Field.Value.(*openflow15.EthDstField).EthDst)
		case *openflow15.ArpXHaField:
			assert.Equal(t, expected[i].arpXHa, a.Field.Value.(*openflow15.ArpXHaField).ArpHa)
		case *openflow15.ArpXPaField:
			assert.Equal(t, expected[i].arpXPa, a.Field.Value.(*openflow15.ArpXPaField).ArpPa)
		case *openflow15.Ipv4SrcField:
			assert.Equal(t, expected[i].ipv4Src, a.Field.Value.(*openflow15.Ipv4SrcField).Ipv4Src)
		case *openflow15.Ipv4DstField:
			assert.Equal(t, expected[i].ipv4Dst, a.Field.Value.(*openflow15.Ipv4DstField).Ipv4Dst)
		case *openflow15.Ipv6SrcField:
			assert.Equal(t, expected[i].ipv6Src, a.Field.Value.(*openflow15.Ipv6SrcField).Ipv6Src)
		case *openflow15.Ipv6DstField:
			assert.Equal(t, expected[i].ipv6Dst, a.Field.Value.(*openflow15.Ipv6DstField).Ipv6Dst)
		case *openflow15.TunnelIpv4DstField:
			assert.Equal(t, expected[i].tunnelIPv4Dst, a.Field.Value.(*openflow15.TunnelIpv4DstField).TunnelIpv4Dst)
		case *openflow15.VlanIdField:
			assert.Equal(t, expected[i].vlanId, a.Field.Value.(*openflow15.VlanIdField).VlanId)
		case *openflow15.ArpOperField:
			assert.Equal(t, expected[i].arpOper, a.Field.Value.(*openflow15.ArpOperField).ArpOper)
		case *openflow15.MatchField:
			assert.Equal(t, expected[i].fieldValue, a.Field.Value.(*openflow15.MatchField).Value)
			assert.Equal(t, expected[i].fieldMask, a.Field.Value.(*openflow15.MatchField).Mask)
		case *util.Buffer:
			assert.Equal(t, expected[i].fieldValue, a.Field.Value.(*util.Buffer))
			if expected[i].fieldMask != nil {
				assert.Equal(t, expected[i].fieldMask, a.Field.Mask.(*util.Buffer))
			}
		case *openflow15.Uint32Message:
			assert.Equal(t, expected[i].fieldValue, a.Field.Value.(*openflow15.Uint32Message))
			assert.Equal(t, expected[i].fieldMask, a.Field.Mask.(*openflow15.Uint32Message))
		case *openflow15.IpDscpField:
			assert.Equal(t, expected[i].fieldValue, a.Field.Value.(*openflow15.IpDscpField))
			assert.Equal(t, expected[i].fieldMask, a.Field.Mask.(*openflow15.IpDscpField))
		case *openflow15.CTLabel:
			assert.Equal(t, expected[i].fieldValue, a.Field.Value.(*openflow15.CTLabel))
			assert.Equal(t, expected[i].fieldMask, a.Field.Mask.(*openflow15.CTLabel))
		default:
			t.Fatalf("Unknown type %v", a.Field.Value)
		}
	}
}

func checkActionCopyField(t *testing.T, expected *actionCopyField, action openflow15.Action) {
	a := action.(*openflow15.ActionCopyField)
	assert.Equal(t, expected.oxmIdSrcClass, a.OxmIdSrc.Class)
	assert.Equal(t, expected.oxmIdDstClass, a.OxmIdDst.Class)
	assert.Equal(t, expected.oxmIdSrcField, a.OxmIdSrc.Field)
	assert.Equal(t, expected.oxmIdDstField, a.OxmIdDst.Field)
	assert.Equal(t, expected.nBits, a.NBits)
	assert.Equal(t, expected.srcOffset, a.SrcOffset)
	assert.Equal(t, expected.dstOffset, a.DstOffset)
}

func newExpectedNXActionConnTrack(commit bool, tableID uint8, zone int, zoneSrcField *RegField) *nxActionConnTrack {
	flags := uint16(0)
	if commit {
		flags = uint16(1)
	}
	zoneSrc := uint32(0)
	zoneOfsNbits := uint16(zone)
	if zoneSrcField != nil {
		field, _ := openflow15.FindFieldHeaderByName(fmt.Sprintf("NXM_NX_REG%d", zoneSrcField.regID), true)
		zoneSrc = field.MarshalHeader()
		zoneOfsNbits = zoneSrcField.rng.ToNXRange().ToOfsBits()
	}
	return &nxActionConnTrack{
		flags:        flags,
		zoneSrc:      zoneSrc,
		zoneOfsNbits: zoneOfsNbits,
		recircTable:  tableID,
	}
}

func checkNXActionConnTrack(t *testing.T, expected *nxActionConnTrack, action openflow15.Action) {
	assert.IsType(t, &openflow15.NXActionConnTrack{}, action)
	a := action.(*openflow15.NXActionConnTrack)
	assert.Equal(t, expected.flags, a.Flags)
	assert.Equal(t, expected.zoneSrc, a.ZoneSrc)
	assert.Equal(t, expected.zoneOfsNbits, a.ZoneOfsNbits)
	assert.Equal(t, expected.recircTable, a.RecircTable)
}

func newExpectedNXActionCTNAT(flags uint16, rangeIPMin, rangeIPMax net.IP, rangePortMin, rangePortMax *uint16) *nxActionCTNAT {
	action := &nxActionCTNAT{
		flags:         flags,
		rangeProtoMin: rangePortMin,
		rangeProtoMax: rangePortMax,
	}
	if rangeIPMin.To4() != nil {
		action.rangeIPv4Min = rangeIPMin
	} else {
		action.rangeIPv6Min = rangeIPMin
	}
	if rangeIPMax.To4() != nil {
		action.rangeIPv4Max = rangeIPMax
	} else {
		action.rangeIPv6Max = rangeIPMax
	}

	return action
}

func checkNXActionCTNAT(t *testing.T, expected *nxActionCTNAT, action openflow15.Action) {
	assert.IsType(t, &openflow15.NXActionCTNAT{}, action)
	a := action.(*openflow15.NXActionCTNAT)
	assert.Equal(t, expected.flags, a.Flags)
	assert.Equal(t, expected.rangeIPv4Min, a.RangeIPv4Min)
	assert.Equal(t, expected.rangeIPv4Max, a.RangeIPv4Max)
	assert.Equal(t, expected.rangeIPv6Min, a.RangeIPv6Min)
	assert.Equal(t, expected.rangeIPv6Max, a.RangeIPv6Max)
	assert.Equal(t, expected.rangeProtoMin, a.RangeProtoMin)
	assert.Equal(t, expected.rangeProtoMax, a.RangeProtoMax)
}

func getFlowMod(t *testing.T, f Flow) *openflow15.FlowMod {
	msgs, err := f.GetBundleMessages(AddMessage)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(msgs))
	return msgs[0].GetMessage().(*openflow15.FlowMod)
}

func TestFlowActions(t *testing.T) {
	table := NewOFTable(tableID1, tableName, stageID, piplineID, missAction)
	table.SetNext(tableID2)
	table.(*ofTable).Table = new(ofctrl.Table)

	mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:fe")
	ipv41 := net.ParseIP("1.1.1.1")
	ipv42 := net.ParseIP("2.2.2.2")
	ipv61 := net.ParseIP("fec0::1111")
	ipv62 := net.ParseIP("fec0::2222")

	t.Run("Drop", func(t *testing.T) {
		flow := table.BuildFlow(1).Action().Drop().Done()
		flowMod := getFlowMod(t, flow)
		assert.Equal(t, 0, len(flowMod.Instructions))
	})
	t.Run("OutputFieldRange", func(t *testing.T) {
		testCases := []struct {
			regName  string
			rng      *Range
			expected *nxActionOutputReg
		}{
			{"NXM_NX_REG4", &Range{16, 31}, newExpectedNXActionOutputReg(openflow15.OXM_CLASS_NXM_1, openflow15.NXM_NX_REG4, uint8(4), &Range{16, 31})},
			{"NXM_NX_REG6", &Range{0, 31}, newExpectedNXActionOutputReg(openflow15.OXM_CLASS_NXM_1, openflow15.NXM_NX_REG6, uint8(6), &Range{0, 31})},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().OutputFieldRange(tc.regName, tc.rng).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))

			actions := flowMod.Instructions[0].(*openflow15.InstrActions).Actions
			assert.Equal(t, 1, len(actions))
			checkNXActionOutputReg(t, tc.expected, actions[0])
		}
	})
	t.Run("OutputToRegField", func(t *testing.T) {
		testCases := []struct {
			regField *RegField
			expected *nxActionOutputReg
		}{
			{NewRegField(4, 16, 31), newExpectedNXActionOutputReg(openflow15.OXM_CLASS_NXM_1, openflow15.NXM_NX_REG4, uint8(4), &Range{16, 31})},
			{NewRegField(6, 0, 31), newExpectedNXActionOutputReg(openflow15.OXM_CLASS_NXM_1, openflow15.NXM_NX_REG6, uint8(6), &Range{0, 31})},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().OutputToRegField(tc.regField).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))

			actions := flowMod.Instructions[0].(*openflow15.InstrActions).Actions
			assert.Equal(t, 1, len(actions))
			checkNXActionOutputReg(t, tc.expected, actions[0])
		}
	})
	t.Run("Output,OutputInPort,Normal", func(t *testing.T) {
		testCases := []struct {
			flow     Flow
			expected uint32
		}{
			{table.BuildFlow(1).Action().Output(3).Done(), 3},
			{table.BuildFlow(1).Action().Output(5).Done(), 5},
			{table.BuildFlow(1).Action().OutputInPort().Done(), uint32(openflow15.P_IN_PORT)},
			{table.BuildFlow(1).Action().Normal().Done(), uint32(openflow15.P_NORMAL)},
		}
		for _, tc := range testCases {
			flowMod := getFlowMod(t, tc.flow)
			assert.Equal(t, 1, len(flowMod.Instructions))

			actions := flowMod.Instructions[0].(*openflow15.InstrActions).Actions
			assert.Equal(t, 1, len(actions))
			assert.IsType(t, &openflow15.ActionOutput{}, actions[0])
			assert.Equal(t, tc.expected, actions[0].(*openflow15.ActionOutput).Port)
		}
	})
	t.Run("SetSrcMAC,SetDstMAC", func(t *testing.T) {
		testCases := []struct {
			isSrc    bool
			mac      net.HardwareAddr
			expected *actionSetField
		}{
			{true, mac1, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_ETH_SRC, ethSrc: mac1}},
			{true, mac2, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_ETH_SRC, ethSrc: mac2}},
			{false, mac1, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_ETH_DST, ethDst: mac1}},
			{false, mac2, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_ETH_DST, ethDst: mac2}},
		}
		for _, tc := range testCases {
			var flow Flow
			if tc.isSrc {
				flow = table.BuildFlow(1).Action().SetSrcMAC(tc.mac).Done()
			} else {
				flow = table.BuildFlow(1).Action().SetDstMAC(tc.mac).Done()
			}
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))
			checkActionSetField(t, []*actionSetField{tc.expected}, flowMod.Instructions[0].(*openflow15.InstrActions).Actions)
		}
	})
	t.Run("SetARPSha,SetARPTha", func(t *testing.T) {
		testCases := []struct {
			isSrc    bool
			mac      net.HardwareAddr
			expected *actionSetField
		}{
			{true, mac1, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_ARP_SHA, arpXHa: mac1}},
			{true, mac2, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_ARP_SHA, arpXHa: mac2}},
			{false, mac1, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_ARP_THA, arpXHa: mac1}},
			{false, mac2, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_ARP_THA, arpXHa: mac2}},
		}
		for _, tc := range testCases {
			var flow Flow
			if tc.isSrc {
				flow = table.BuildFlow(1).Action().SetARPSha(tc.mac).Done()
			} else {
				flow = table.BuildFlow(1).Action().SetARPTha(tc.mac).Done()
			}
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))
			checkActionSetField(t, []*actionSetField{tc.expected}, flowMod.Instructions[0].(*openflow15.InstrActions).Actions)
		}
	})
	t.Run("SetARPSpa,SetARPTpa", func(t *testing.T) {
		testCases := []struct {
			isSrc    bool
			ip       net.IP
			expected *actionSetField
		}{
			{true, ipv41, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_ARP_SPA, arpXPa: ipv41}},
			{true, ipv42, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_ARP_SPA, arpXPa: ipv42}},
			{false, ipv41, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_ARP_TPA, arpXPa: ipv41}},
			{false, ipv42, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_ARP_TPA, arpXPa: ipv42}},
		}
		for _, tc := range testCases {
			var flow Flow
			if tc.isSrc {
				flow = table.BuildFlow(1).Action().SetARPSpa(tc.ip).Done()
			} else {
				flow = table.BuildFlow(1).Action().SetARPTpa(tc.ip).Done()
			}
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))
			checkActionSetField(t, []*actionSetField{tc.expected}, flowMod.Instructions[0].(*openflow15.InstrActions).Actions)
		}
	})
	t.Run("SetSrcIP,SetDstIP", func(t *testing.T) {
		testCases := []struct {
			isSrc    bool
			ip       net.IP
			expected *actionSetField
		}{
			{true, ipv41, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_IPV4_SRC, ipv4Src: ipv41}},
			{true, ipv42, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_IPV4_SRC, ipv4Src: ipv42}},
			{true, ipv61, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_IPV6_SRC, ipv6Src: ipv61}},
			{true, ipv62, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_IPV6_SRC, ipv6Src: ipv62}},
			{false, ipv41, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_IPV4_DST, ipv4Dst: ipv41}},
			{false, ipv42, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_IPV4_DST, ipv4Dst: ipv42}},
			{false, ipv61, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_IPV6_DST, ipv6Dst: ipv61}},
			{false, ipv62, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_IPV6_DST, ipv6Dst: ipv62}},
		}
		for _, tc := range testCases {
			var flow Flow
			if tc.isSrc {
				flow = table.BuildFlow(1).Action().SetSrcIP(tc.ip).Done()
			} else {
				flow = table.BuildFlow(1).Action().SetDstIP(tc.ip).Done()
			}
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))
			checkActionSetField(t, []*actionSetField{tc.expected}, flowMod.Instructions[0].(*openflow15.InstrActions).Actions)
		}
	})
	t.Run("SetTunnelDst", func(t *testing.T) {
		testCases := []struct {
			ip       net.IP
			expected *actionSetField
		}{
			{ipv41, &actionSetField{class: openflow15.OXM_CLASS_NXM_1, field: openflow15.NXM_NX_TUN_IPV4_DST, tunnelIPv4Dst: ipv41}},
			{ipv42, &actionSetField{class: openflow15.OXM_CLASS_NXM_1, field: openflow15.NXM_NX_TUN_IPV4_DST, tunnelIPv4Dst: ipv42}},
			{ipv61, &actionSetField{class: openflow15.OXM_CLASS_NXM_1, field: openflow15.NXM_NX_TUN_IPV6_DST, ipv6Dst: ipv61}},
			{ipv62, &actionSetField{class: openflow15.OXM_CLASS_NXM_1, field: openflow15.NXM_NX_TUN_IPV6_DST, ipv6Dst: ipv62}},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().SetTunnelDst(tc.ip).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))
			checkActionSetField(t, []*actionSetField{tc.expected}, flowMod.Instructions[0].(*openflow15.InstrActions).Actions)
		}
	})
	t.Run("PopVLAN", func(t *testing.T) {
		flow := table.BuildFlow(1).Action().PopVLAN().Done()
		flowMod := getFlowMod(t, flow)
		assert.Equal(t, 1, len(flowMod.Instructions))
		actions := flowMod.Instructions[0].(*openflow15.InstrActions).Actions
		assert.Equal(t, 1, len(actions))
		assert.IsType(t, &openflow15.ActionPopVlan{}, actions[0])
	})
	t.Run("PushVLAN", func(t *testing.T) {
		testCases := []struct {
			vlanId uint16
		}{
			{0x8100},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().PushVLAN(tc.vlanId).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))
			actions := flowMod.Instructions[0].(*openflow15.InstrActions).Actions
			assert.Equal(t, 1, len(actions))
			assert.IsType(t, &openflow15.ActionPush{}, actions[0])
			assert.Equal(t, tc.vlanId, actions[0].(*openflow15.ActionPush).EtherType)
		}
	})
	t.Run("SetVLAN", func(t *testing.T) {
		testCases := []struct {
			vlanId   uint16
			expected *actionSetField
		}{
			{100, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_VLAN_VID, vlanId: 100 | openflow15.OFPVID_PRESENT}},
			{200, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_VLAN_VID, vlanId: 200 | openflow15.OFPVID_PRESENT}},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().SetVLAN(tc.vlanId).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))
			checkActionSetField(t, []*actionSetField{tc.expected}, flowMod.Instructions[0].(*openflow15.InstrActions).Actions)
		}
	})
	t.Run("LoadARPOperation", func(t *testing.T) {
		testCases := []struct {
			arpOp    uint16
			expected *actionSetField
		}{
			{1, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_ARP_OP, arpOper: 1}},
			{2, &actionSetField{class: openflow15.OXM_CLASS_OPENFLOW_BASIC, field: openflow15.OXM_FIELD_ARP_OP, arpOper: 2}},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().LoadARPOperation(tc.arpOp).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))
			checkActionSetField(t, []*actionSetField{tc.expected}, flowMod.Instructions[0].(*openflow15.InstrActions).Actions)
		}
	})
	t.Run("LoadRegMark", func(t *testing.T) {
		field1 := NewRegField(11, 1, 17)
		field2 := NewRegField(4, 0, 31)
		mark1 := NewRegMark(field1, uint32(0xfffe))
		mark2 := NewRegMark(field2, uint32(0xffffeeee))

		f := func(value uint32, class uint16, field uint8, rng *Range) *actionSetField {
			maskData := ^uint32(0) >> (32 - rng.Length()) << rng.Offset()
			valueData := value << rng.Offset()
			return &actionSetField{
				class:      class,
				field:      field,
				fieldValue: &openflow15.Uint32Message{Data: valueData},
				fieldMask:  &openflow15.Uint32Message{Data: maskData},
			}
		}
		expected1 := f(mark1.value, openflow15.OXM_CLASS_NXM_1, openflow15.NXM_NX_REG11, field1.rng)
		expected2 := f(mark2.value, openflow15.OXM_CLASS_NXM_1, openflow15.NXM_NX_REG4, field2.rng)

		testCases := []struct {
			regMarks []*RegMark
			expected []*actionSetField
		}{
			{[]*RegMark{mark1}, []*actionSetField{expected1}},
			{[]*RegMark{mark1, mark2}, []*actionSetField{expected1, expected2}},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().LoadRegMark(tc.regMarks...).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))
			checkActionSetField(t, tc.expected, flowMod.Instructions[0].(*openflow15.InstrActions).Actions)
		}
	})
	t.Run("LoadPktMarkRange", func(t *testing.T) {
		f := func(value uint32, rng *Range) *actionSetField {
			valueBytes := make([]byte, 4)
			maskBytes := make([]byte, 4)
			maskData := ^uint32(0) >> (32 - rng.Length()) << rng.Offset()
			valueData := value << rng.Offset()
			binary.BigEndian.PutUint32(maskBytes, maskData)
			binary.BigEndian.PutUint32(valueBytes, valueData)
			return &actionSetField{
				class:      openflow15.OXM_CLASS_NXM_1,
				field:      openflow15.NXM_NX_PKT_MARK,
				fieldValue: util.NewBuffer(valueBytes),
				fieldMask:  util.NewBuffer(maskBytes),
			}
		}
		mark1, mark2 := uint32(0xaeef), uint32(0xbeeffeea)
		rng1, rng2 := &Range{0, 15}, &Range{0, 31}
		expected1, expected2 := f(mark1, rng1), f(mark2, rng2)

		testCases := []struct {
			value    uint32
			rng      *Range
			expected *actionSetField
		}{
			{mark1, rng1, expected1},
			{mark2, rng2, expected2},
		}

		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().LoadPktMarkRange(tc.value, tc.rng).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))
			checkActionSetField(t, []*actionSetField{tc.expected}, flowMod.Instructions[0].(*openflow15.InstrActions).Actions)
		}
	})
	t.Run("LoadIPDSCP", func(t *testing.T) {
		testCases := []struct {
			value    uint8
			expected *actionSetField
		}{
			{
				uint8(1),
				&actionSetField{
					class:      openflow15.OXM_CLASS_NXM_0,
					field:      openflow15.NXM_OF_IP_TOS,
					fieldValue: &openflow15.IpDscpField{Dscp: uint8(1) << IPDSCPToSRange.Offset()},
					fieldMask:  &openflow15.IpDscpField{Dscp: uint8(0xff) >> (8 - IPDSCPToSRange.Length()) << IPDSCPToSRange.Offset()}},
			},
			{
				uint8(63),
				&actionSetField{
					class:      openflow15.OXM_CLASS_NXM_0,
					field:      openflow15.NXM_OF_IP_TOS,
					fieldValue: &openflow15.IpDscpField{Dscp: uint8(63) << IPDSCPToSRange.Offset()},
					fieldMask:  &openflow15.IpDscpField{Dscp: uint8(0xff) >> (8 - IPDSCPToSRange.Length()) << IPDSCPToSRange.Offset()}},
			},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().LoadIPDSCP(tc.value).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))
			checkActionSetField(t, []*actionSetField{tc.expected}, flowMod.Instructions[0].(*openflow15.InstrActions).Actions)
		}
	})
	t.Run("Move,MoveRange", func(t *testing.T) {
		testCases := []struct {
			hasRange   bool
			srcRegName string
			dstRegName string
			srcRange   Range
			dstRange   Range
			expected   *actionCopyField
		}{
			{
				hasRange:   false,
				srcRegName: "NXM_NX_REG4",
				dstRegName: "NXM_NX_REG5",
				expected: &actionCopyField{
					oxmIdSrcClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdDstClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdSrcField: openflow15.NXM_NX_REG4,
					oxmIdDstField: openflow15.NXM_NX_REG5,
					nBits:         32,
				},
			},
			{
				hasRange:   false,
				srcRegName: "NXM_NX_XXREG0",
				dstRegName: "NXM_NX_XXREG1",
				expected: &actionCopyField{
					oxmIdSrcClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdDstClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdSrcField: openflow15.NXM_NX_XXREG0,
					oxmIdDstField: openflow15.NXM_NX_XXREG1,
					nBits:         128,
				},
			},
			{
				hasRange:   false,
				srcRegName: "NXM_NX_TUN_METADATA0",
				dstRegName: "NXM_NX_TUN_METADATA1",
				expected: &actionCopyField{
					oxmIdSrcClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdDstClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdSrcField: openflow15.NXM_NX_TUN_METADATA0,
					oxmIdDstField: openflow15.NXM_NX_TUN_METADATA1,
					nBits:         1024,
				},
			},
			{
				hasRange:   false,
				srcRegName: "OXM_OF_ETH_SRC",
				dstRegName: "OXM_OF_ETH_DST",
				expected: &actionCopyField{
					oxmIdSrcClass: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					oxmIdDstClass: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					oxmIdSrcField: openflow15.OXM_FIELD_ETH_SRC,
					oxmIdDstField: openflow15.OXM_FIELD_ETH_DST,
					nBits:         48,
				},
			},
			{
				hasRange:   true,
				srcRegName: "OXM_OF_ETH_SRC",
				dstRegName: "NXM_NX_REG6",
				srcRange:   Range{16, 31},
				dstRange:   Range{1, 16},
				expected: &actionCopyField{
					oxmIdSrcClass: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					oxmIdDstClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdSrcField: openflow15.OXM_FIELD_ETH_SRC,
					oxmIdDstField: openflow15.NXM_NX_REG6,
					srcOffset:     16,
					dstOffset:     1,
					nBits:         16,
				},
			},
			{
				hasRange:   true,
				srcRegName: "NXM_NX_REG1",
				dstRegName: "OXM_OF_IPV4_SRC",
				srcRange:   Range{0, 15},
				dstRange:   Range{16, 31},
				expected: &actionCopyField{
					oxmIdSrcClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdDstClass: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					oxmIdSrcField: openflow15.NXM_NX_REG1,
					oxmIdDstField: openflow15.OXM_FIELD_IPV4_SRC,
					srcOffset:     0,
					dstOffset:     16,
					nBits:         16,
				},
			},
		}
		for _, tc := range testCases {
			var flow Flow
			if tc.hasRange {
				flow = table.BuildFlow(1).Action().MoveRange(tc.srcRegName, tc.dstRegName, tc.srcRange, tc.dstRange).Done()
			} else {
				flow = table.BuildFlow(1).Action().Move(tc.srcRegName, tc.dstRegName).Done()
			}
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))

			actions := flowMod.Instructions[0].(*openflow15.InstrActions).Actions
			assert.Equal(t, 1, len(actions))
			checkActionCopyField(t, tc.expected, actions[0])
		}
	})
	t.Run("MoveFromTunMetadata", func(t *testing.T) {
		testCases := []struct {
			srcRegID   int
			dstRegName string
			srcRange   Range
			dstRange   Range
			tlvLength  uint8
			expected   *actionCopyField
		}{
			{
				0,
				"NXM_NX_REG6",
				Range{16, 31},
				Range{1, 16},
				2,
				&actionCopyField{
					oxmIdSrcClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdDstClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdSrcField: openflow15.NXM_NX_TUN_METADATA0,
					oxmIdDstField: openflow15.NXM_NX_REG6,
					srcOffset:     16,
					dstOffset:     1,
					nBits:         16,
				},
			},
			{
				1,
				"NXM_NX_REG7",
				Range{0, 31},
				Range{0, 31},
				3,
				&actionCopyField{
					oxmIdSrcClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdDstClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdSrcField: openflow15.NXM_NX_TUN_METADATA1,
					oxmIdDstField: openflow15.NXM_NX_REG7,
					srcOffset:     0,
					dstOffset:     0,
					nBits:         32,
				},
			},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().MoveFromTunMetadata(tc.srcRegID, tc.dstRegName, tc.srcRange, tc.dstRange, tc.tlvLength).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))

			actions := flowMod.Instructions[0].(*openflow15.InstrActions).Actions
			assert.Equal(t, 1, len(actions))
			checkActionCopyField(t, tc.expected, actions[0])
		}
	})
	t.Run("ResubmitToTables", func(t *testing.T) {
		testCases := []struct {
			tableIDs []uint8
		}{
			{[]uint8{100}},
			{[]uint8{101, 102}},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().ResubmitToTables(tc.tableIDs...).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))

			actions := flowMod.Instructions[0].(*openflow15.InstrActions).Actions
			assert.Equal(t, len(tc.tableIDs), len(actions))
			for i := 0; i < len(actions); i++ {
				assert.IsType(t, &openflow15.NXActionResubmitTable{}, actions[i])
				action := actions[i].(*openflow15.NXActionResubmitTable)
				assert.Equal(t, uint16(openflow15.OFPP_IN_PORT), action.InPort)
				assert.Equal(t, tc.tableIDs[i], action.TableID)
			}
		}
	})
	t.Run("DecTTL", func(t *testing.T) {
		flow := table.BuildFlow(1).Action().DecTTL().Done()
		flowMod := getFlowMod(t, flow)
		assert.Equal(t, 1, len(flowMod.Instructions))

		actions := flowMod.Instructions[0].(*openflow15.InstrActions).Actions
		assert.Equal(t, 1, len(actions))
		assert.IsType(t, &openflow15.ActionDecNwTtl{}, actions[0])
	})
	t.Run("Conjunction", func(t *testing.T) {
		testCases := []struct {
			conjID   uint32
			clauseID uint8
			nClause  uint8
		}{
			{61, 2, 3},
			{50, 2, 2},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().Conjunction(tc.conjID, tc.clauseID, tc.nClause).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))

			actions := flowMod.Instructions[0].(*openflow15.InstrActions).Actions
			assert.Equal(t, 1, len(actions))
			assert.IsType(t, &openflow15.NXActionConjunction{}, actions[0])

			action := actions[0].(*openflow15.NXActionConjunction)
			assert.Equal(t, tc.conjID, action.ID)
			assert.Equal(t, tc.nClause, action.NClause)
			assert.Equal(t, tc.clauseID-1, action.Clause)
		}
	})
	t.Run("Group", func(t *testing.T) {
		testCases := []struct {
			groupID uint32
		}{
			{100},
			{200},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().Group(GroupIDType(tc.groupID)).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))

			actions := flowMod.Instructions[0].(*openflow15.InstrActions).Actions
			assert.Equal(t, 1, len(actions))
			assert.IsType(t, &openflow15.ActionGroup{}, actions[0])
			assert.Equal(t, tc.groupID, actions[0].(*openflow15.ActionGroup).GroupId)
		}
	})
	t.Run("Note", func(t *testing.T) {
		testCases := []struct {
			note string
		}{
			{"11223344"},
			{"aabbccdd5566"},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().Note(tc.note).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))

			actions := flowMod.Instructions[0].(*openflow15.InstrActions).Actions
			assert.Equal(t, 1, len(actions))
			assert.IsType(t, &openflow15.NXActionNote{}, actions[0])
			assert.Equal(t, []byte(tc.note), actions[0].(*openflow15.NXActionNote).Note)
		}
	})
	t.Run("Meter", func(t *testing.T) {
		testCases := []struct {
			meterId uint32
		}{
			{100},
			{200},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().Meter(tc.meterId).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))

			actions := flowMod.Instructions[0].(*openflow15.InstrActions).Actions
			assert.Equal(t, 1, len(actions))
			assert.IsType(t, &openflow15.ActionMeter{}, actions[0])
			assert.Equal(t, tc.meterId, actions[0].(*openflow15.ActionMeter).MeterId)
		}
	})
	t.Run("GotoTable", func(t *testing.T) {
		testCases := []struct {
			tableID uint8
		}{
			{100},
			{200},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().GotoTable(tc.tableID).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))
			assert.Equal(t, tc.tableID, flowMod.Instructions[0].(*openflow15.InstrGotoTable).TableId)
		}
	})
	t.Run("GotoStage", func(t *testing.T) {
		stage1 := StageID(1)
		stage2 := StageID(2)
		testCases := []struct {
			stageID         StageID
			tables          []Table
			expectedTableID uint8
		}{
			{stage1, []Table{NewOFTable(100, "table100", stage1, piplineID, missAction)}, 100},
			{stage2, []Table{NewOFTable(200, "table100", stage2, piplineID, missAction)}, 200},
		}
		for _, tc := range testCases {
			pipelineCache[piplineID] = &ofPipeline{
				pipelineID: piplineID,
				tableMap:   map[StageID][]Table{stageID: {table}},
			}

			pipelineCache[piplineID].tableMap[tc.stageID] = tc.tables
			flow := table.BuildFlow(1).Action().GotoStage(tc.stageID).Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))
			assert.Equal(t, tc.expectedTableID, flowMod.Instructions[0].(*openflow15.InstrGotoTable).TableId)
		}
	})
	t.Run("CT", func(t *testing.T) {
		regField1 := NewRegField(4, 1, 17)
		regField2 := NewRegField(5, 0, 16)
		testCases := []struct {
			commit       bool
			tableID      uint8
			zone         int
			zoneSrcField *RegField
			expected     *nxActionConnTrack
		}{
			{true, 200, 100, nil, newExpectedNXActionConnTrack(true, 200, 100, nil)},
			{false, 201, 101, nil, newExpectedNXActionConnTrack(false, 201, 101, nil)},
			{true, 203, 0, regField1, newExpectedNXActionConnTrack(true, 203, 0, regField1)},
			{false, 204, 0, regField2, newExpectedNXActionConnTrack(false, 204, 0, regField2)},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().CT(tc.commit, tc.tableID, tc.zone, tc.zoneSrcField).CTDone().Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))

			actions := flowMod.Instructions[0].(*openflow15.InstrActions).Actions
			assert.Equal(t, 1, len(actions))
			checkNXActionConnTrack(t, tc.expected, actions[0])
		}
	})
	t.Run("Learn", func(t *testing.T) {
		testCases := []struct {
			tableID     uint8
			priority    uint16
			idleTimeout uint16
			hardTimeout uint16
			cookieID    uint64
		}{
			{200, 0, 3600, 3600, uint64(0xffff)},
			{201, 1, 1800, 1800, uint64(0xfffe)},
		}
		for _, tc := range testCases {
			flow := table.BuildFlow(1).Action().Learn(tc.tableID, tc.priority, tc.idleTimeout, tc.hardTimeout, tc.cookieID).Done().Done()
			flowMod := getFlowMod(t, flow)
			assert.Equal(t, 1, len(flowMod.Instructions))

			actions := flowMod.Instructions[0].(*openflow15.InstrActions).Actions
			assert.Equal(t, 1, len(actions))
			assert.IsType(t, &openflow15.NXActionLearn{}, actions[0])

			action := actions[0].(*openflow15.NXActionLearn)
			assert.Equal(t, tc.idleTimeout, action.IdleTimeout)
			assert.Equal(t, tc.hardTimeout, action.HardTimeout)
			assert.Equal(t, tc.priority, action.Priority)
			assert.Equal(t, tc.cookieID, action.Cookie)
			assert.Equal(t, tc.tableID, action.TableID)
		}
	})
}

func TestCTActions(t *testing.T) {
	table := NewOFTable(tableID1, tableName, stageID, piplineID, missAction)
	table.(*ofTable).Table = new(ofctrl.Table)
	ipv4Min, ipv4Max := net.ParseIP("1.1.1.1"), net.ParseIP("1.1.1.2")
	ipv6Min, ipv6Max := net.ParseIP("1:1:1::1"), net.ParseIP("1:1:1::2")
	portMin, portMax := uint16(3333), uint16(4444)

	commit := true
	nextTable := uint8(100)
	zone := 100

	t.Run("LoadToCtMark", func(t *testing.T) {
		mark1 := NewCTMark(NewCTMarkField(0, 15), uint32(0xffff))
		mark2 := NewCTMark(NewCTMarkField(2, 6), uint32(0xe))
		mark3 := NewCTMark(NewCTMarkField(7, 9), uint32(0b11))
		f := func(value uint32, rng *Range) *actionSetField {
			maskData := ^uint32(0) >> (32 - rng.Length()) << rng.Offset()
			valueData := value << rng.Offset()
			return &actionSetField{
				class:      openflow15.OXM_CLASS_NXM_1,
				field:      openflow15.NXM_NX_CT_MARK,
				fieldValue: &openflow15.Uint32Message{Data: valueData},
				fieldMask:  &openflow15.Uint32Message{Data: maskData},
			}
		}
		expected1 := f(mark1.value, mark1.field.rng)
		expected2 := f(mark2.value, mark2.field.rng)
		expected3 := f(mark3.value, mark3.field.rng)

		testCases := []struct {
			marks    []*CtMark
			expected []*actionSetField
		}{
			{[]*CtMark{mark1}, []*actionSetField{expected1}},
			{[]*CtMark{mark2, mark3}, []*actionSetField{expected2, expected3}},
		}

		for _, tc := range testCases {
			actions := table.BuildFlow(1).Action().CT(commit, nextTable, zone, nil).LoadToCtMark(tc.marks...).(*ofCTAction).actions
			checkActionSetField(t, tc.expected, actions)
		}
	})
	t.Run("LoadToLabelField", func(t *testing.T) {
		value1 := uint64(0xffff_ffff_ffff_ffff)
		value2 := uint64(0xffff)
		label1 := NewCTLabel(0, 63)
		label2 := NewCTLabel(1, 16)

		f := func(value uint64, rng *Range) *actionSetField {
			var labelBytes, maskBytes [16]byte
			maskData := ^uint64(0) >> (64 - rng.Length()) << (rng.Offset() % 64)
			valueData := value << (rng.Offset() % 64)
			if rng.Offset() > 63 {
				binary.BigEndian.PutUint64(maskBytes[0:8], maskData)
				binary.BigEndian.PutUint64(labelBytes[0:8], valueData)
			} else {
				binary.BigEndian.PutUint64(maskBytes[8:], maskData)
				binary.BigEndian.PutUint64(labelBytes[8:], valueData)
			}
			match := openflow15.NewCTLabelMatchField(labelBytes, &maskBytes)
			return &actionSetField{
				class:      openflow15.OXM_CLASS_NXM_1,
				field:      openflow15.NXM_NX_CT_LABEL,
				fieldValue: match.Value.(*openflow15.CTLabel),
				fieldMask:  match.Mask.(*openflow15.CTLabel),
			}
		}
		expected1 := f(value1, label1.rng)
		expected2 := f(value2, label2.rng)

		testCases := []struct {
			value    uint64
			label    *CtLabel
			expected *actionSetField
		}{
			{value1, label1, expected1},
			{value2, label2, expected2},
		}
		for _, tc := range testCases {
			actions := table.BuildFlow(1).Action().CT(commit, nextTable, zone, nil).LoadToLabelField(tc.value, tc.label).(*ofCTAction).actions
			checkActionSetField(t, []*actionSetField{tc.expected}, actions)
		}
	})
	t.Run("MoveToLabel", func(t *testing.T) {
		testCases := []struct {
			srcRegName string
			srcRng     *Range
			dstRng     *Range
			expected   *actionCopyField
		}{
			{
				"NXM_NX_REG4",
				&Range{4, 7},
				&Range{0, 3},
				&actionCopyField{
					oxmIdSrcClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdDstClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdSrcField: openflow15.NXM_NX_REG4,
					oxmIdDstField: openflow15.NXM_NX_CT_LABEL,
					srcOffset:     4,
					dstOffset:     0,
					nBits:         4,
				},
			},
			{
				"NXM_OF_ETH_DST",
				&Range{0, 47},
				&Range{1, 48},
				&actionCopyField{
					oxmIdSrcClass: openflow15.OXM_CLASS_NXM_0,
					oxmIdDstClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdSrcField: openflow15.NXM_OF_ETH_DST,
					oxmIdDstField: openflow15.NXM_NX_CT_LABEL,
					srcOffset:     0,
					dstOffset:     1,
					nBits:         48,
				},
			},
		}
		for _, tc := range testCases {
			actions := table.BuildFlow(1).Action().CT(commit, nextTable, zone, nil).MoveToLabel(tc.srcRegName, tc.srcRng, tc.dstRng).(*ofCTAction).actions
			assert.Equal(t, 1, len(actions))
			checkActionCopyField(t, tc.expected, actions[0])
		}
	})
	t.Run("MoveToCtMarkField", func(t *testing.T) {
		testCases := []struct {
			srcRegField    *RegField
			dstCtMarkField *CtMarkField
			expected       *actionCopyField
		}{
			{
				NewRegField(1, 1, 16),
				NewCTMarkField(2, 17),
				&actionCopyField{
					oxmIdSrcClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdDstClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdSrcField: openflow15.NXM_NX_REG1,
					oxmIdDstField: openflow15.NXM_NX_CT_MARK,
					srcOffset:     1,
					dstOffset:     2,
					nBits:         16,
				},
			},
			{
				NewRegField(4, 0, 31),
				NewCTMarkField(0, 31),
				&actionCopyField{
					oxmIdSrcClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdDstClass: openflow15.OXM_CLASS_NXM_1,
					oxmIdSrcField: openflow15.NXM_NX_REG4,
					oxmIdDstField: openflow15.NXM_NX_CT_MARK,
					srcOffset:     0,
					dstOffset:     0,
					nBits:         32,
				},
			},
		}
		for _, tc := range testCases {
			actions := table.BuildFlow(1).Action().CT(commit, nextTable, zone, nil).MoveToCtMarkField(tc.srcRegField, tc.dstCtMarkField).(*ofCTAction).actions
			assert.Equal(t, 1, len(actions))
			checkActionCopyField(t, tc.expected, actions[0])
		}
	})
	t.Run("SNAT,DNAT,NAT", func(t *testing.T) {
		testCases := []struct {
			isSNAT    bool
			isDNAT    bool
			ipRange   *IPRange
			portRange *PortRange
			expected  *nxActionCTNAT
		}{
			{
				true,
				false,
				&IPRange{ipv4Min, ipv4Min},
				&PortRange{portMin, portMin},
				newExpectedNXActionCTNAT(openflow15.NX_NAT_F_SRC, ipv4Min, ipv4Min, &portMin, &portMin),
			},
			{
				false,
				true,
				&IPRange{ipv6Min, ipv6Min},
				&PortRange{portMin, portMin},
				newExpectedNXActionCTNAT(openflow15.NX_NAT_F_DST, ipv6Min, ipv6Min, &portMin, &portMin),
			},
			{
				true,
				false,
				&IPRange{ipv4Min, ipv4Max},
				&PortRange{portMin, portMax},
				newExpectedNXActionCTNAT(openflow15.NX_NAT_F_SRC, ipv4Min, ipv4Max, &portMin, &portMax),
			},
			{
				false,
				true,
				&IPRange{ipv6Min, ipv6Max},
				&PortRange{portMin, portMax},
				newExpectedNXActionCTNAT(openflow15.NX_NAT_F_DST, ipv6Min, ipv6Max, &portMin, &portMax),
			},
			{
				false,
				false,
				nil,
				nil,
				newExpectedNXActionCTNAT(0, nil, nil, nil, nil),
			},
		}
		for _, tc := range testCases {
			var actions []openflow15.Action
			if tc.isSNAT {
				actions = table.BuildFlow(1).Action().CT(commit, nextTable, zone, nil).SNAT(tc.ipRange, tc.portRange).(*ofCTAction).actions
			} else if tc.isDNAT {
				actions = table.BuildFlow(1).Action().CT(commit, nextTable, zone, nil).DNAT(tc.ipRange, tc.portRange).(*ofCTAction).actions
			} else {
				actions = table.BuildFlow(1).Action().CT(commit, nextTable, zone, nil).NAT().(*ofCTAction).actions
			}
			assert.Equal(t, 1, len(actions))
			checkNXActionCTNAT(t, tc.expected, actions[0])
		}
	})
}

type nxLearnSpec struct {
	srcClass  uint16
	srcField  uint8
	srcOffset uint16
	dstClass  uint16
	dstField  uint8
	dstOffset uint16
	srcValue  []uint8
}

func newExpectedMatchEthernetProtocolIPAction(isIPv6 bool) *nxLearnSpec {
	spec := &nxLearnSpec{
		dstClass: openflow15.OXM_CLASS_NXM_0,
		dstField: openflow15.NXM_OF_ETH_TYPE,
	}
	ethTypeVal := make([]byte, 2)
	var ipProto uint16 = 0x800
	if isIPv6 {
		ipProto = 0x86dd
	}
	binary.BigEndian.PutUint16(ethTypeVal, ipProto)
	spec.srcValue = ethTypeVal
	return spec
}

func newExpectedMatchLearnedTransportDstActions(protocol Protocol) []*nxLearnSpec {
	var ipProtoValue int
	var field uint8
	isIPv6 := false
	switch protocol {
	case ProtocolTCP:
		ipProtoValue = ofctrl.IP_PROTO_TCP
		field = openflow15.OXM_FIELD_TCP_DST
	case ProtocolUDP:
		ipProtoValue = ofctrl.IP_PROTO_UDP
		field = openflow15.OXM_FIELD_UDP_DST
	case ProtocolSCTP:
		ipProtoValue = ofctrl.IP_PROTO_SCTP
		field = openflow15.OXM_FIELD_SCTP_DST
	case ProtocolTCPv6:
		ipProtoValue = ofctrl.IP_PROTO_TCP
		field = openflow15.OXM_FIELD_TCP_DST
		isIPv6 = true
	case ProtocolUDPv6:
		ipProtoValue = ofctrl.IP_PROTO_UDP
		field = openflow15.OXM_FIELD_UDP_DST
		isIPv6 = true
	case ProtocolSCTPv6:
		ipProtoValue = ofctrl.IP_PROTO_SCTP
		field = openflow15.OXM_FIELD_SCTP_DST
		isIPv6 = true
	}

	specs := []*nxLearnSpec{newExpectedMatchEthernetProtocolIPAction(isIPv6)}

	ipTypeVal := make([]byte, 2)
	ipTypeVal[1] = byte(ipProtoValue)
	spec := &nxLearnSpec{
		dstClass: openflow15.OXM_CLASS_NXM_0,
		dstField: openflow15.NXM_OF_IP_PROTO,
		srcValue: ipTypeVal,
	}
	specs = append(specs, spec)

	spec = &nxLearnSpec{
		srcClass: openflow15.OXM_CLASS_OPENFLOW_BASIC,
		srcField: field,
		dstClass: openflow15.OXM_CLASS_OPENFLOW_BASIC,
		dstField: field,
	}
	specs = append(specs, spec)

	return specs
}

func checkLearnSpecs(t *testing.T, expected []*nxLearnSpec, specs []*openflow15.NXLearnSpec) {
	assert.Equal(t, len(expected), len(specs))
	for i := 0; i < len(expected); i++ {
		if specs[i].SrcField != nil {
			assert.Equal(t, expected[i].srcClass, specs[i].SrcField.Field.Class)
			assert.Equal(t, expected[i].srcField, specs[i].SrcField.Field.Field)
			assert.Equal(t, expected[i].srcOffset, specs[i].SrcField.Ofs)
		}
		if specs[i].DstField != nil {
			assert.Equal(t, expected[i].dstClass, specs[i].DstField.Field.Class)
			assert.Equal(t, expected[i].dstField, specs[i].DstField.Field.Field)
			assert.Equal(t, expected[i].dstOffset, specs[i].DstField.Ofs)
		}
		if specs[i].SrcValue != nil {
			assert.Equal(t, expected[i].srcValue, specs[i].SrcValue)
		}
	}
}

func TestLearnActions(t *testing.T) {
	table := NewOFTable(tableID1, tableName, stageID, piplineID, missAction)
	targetTable := uint8(100)
	priority := uint16(101)
	idleTimeout := uint16(120)
	hardTimeout := uint16(3600)
	cookieID := uint64(0xffffffff)

	t.Run("MatchEthernetProtocolIP", func(t *testing.T) {
		testCases := []struct {
			isIPv6   bool
			expected []*nxLearnSpec
		}{
			{false, []*nxLearnSpec{newExpectedMatchEthernetProtocolIPAction(false)}},
			{true, []*nxLearnSpec{newExpectedMatchEthernetProtocolIPAction(true)}},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).Action().Learn(targetTable, priority, idleTimeout, hardTimeout, cookieID)
			action := fb.MatchEthernetProtocolIP(tc.isIPv6).(*ofLearnAction).nxLearn.GetActionMessage().(*openflow15.NXActionLearn)
			checkLearnSpecs(t, tc.expected, action.LearnSpecs)
		}
	})
	t.Run("MatchTransportDst", func(t *testing.T) {
		testCases := []struct {
			protocol Protocol
			expected []*nxLearnSpec
		}{
			{ProtocolTCP, newExpectedMatchLearnedTransportDstActions(ProtocolTCP)},
			{ProtocolTCPv6, newExpectedMatchLearnedTransportDstActions(ProtocolTCPv6)},
			{ProtocolUDP, newExpectedMatchLearnedTransportDstActions(ProtocolUDP)},
			{ProtocolUDPv6, newExpectedMatchLearnedTransportDstActions(ProtocolUDPv6)},
			{ProtocolSCTP, newExpectedMatchLearnedTransportDstActions(ProtocolSCTP)},
			{ProtocolSCTPv6, newExpectedMatchLearnedTransportDstActions(ProtocolSCTPv6)},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).Action().Learn(targetTable, priority, idleTimeout, hardTimeout, cookieID)
			action := fb.MatchTransportDst(tc.protocol).(*ofLearnAction).nxLearn.GetActionMessage().(*openflow15.NXActionLearn)
			checkLearnSpecs(t, tc.expected, action.LearnSpecs)
		}
	})
	t.Run("MatchLearnedSrcIP", func(t *testing.T) {
		expected := &nxLearnSpec{
			srcClass: openflow15.OXM_CLASS_NXM_0,
			srcField: openflow15.NXM_OF_IP_SRC,
			dstClass: openflow15.OXM_CLASS_NXM_0,
			dstField: openflow15.NXM_OF_IP_SRC,
		}
		fb := table.BuildFlow(1).Action().Learn(targetTable, priority, idleTimeout, hardTimeout, cookieID)
		action := fb.MatchLearnedSrcIP().(*ofLearnAction).nxLearn.GetActionMessage().(*openflow15.NXActionLearn)
		checkLearnSpecs(t, []*nxLearnSpec{expected}, action.LearnSpecs)
	})
	t.Run("MatchLearnedDstIP", func(t *testing.T) {
		expected := &nxLearnSpec{
			srcClass: openflow15.OXM_CLASS_NXM_0,
			srcField: openflow15.NXM_OF_IP_DST,
			dstClass: openflow15.OXM_CLASS_NXM_0,
			dstField: openflow15.NXM_OF_IP_DST,
		}
		fb := table.BuildFlow(1).Action().Learn(targetTable, priority, idleTimeout, hardTimeout, cookieID)
		action := fb.MatchLearnedDstIP().(*ofLearnAction).nxLearn.GetActionMessage().(*openflow15.NXActionLearn)
		checkLearnSpecs(t, []*nxLearnSpec{expected}, action.LearnSpecs)
	})
	t.Run("MatchLearnedSrcIPv6", func(t *testing.T) {
		expected := &nxLearnSpec{
			srcClass: openflow15.OXM_CLASS_NXM_1,
			srcField: openflow15.NXM_NX_IPV6_SRC,
			dstClass: openflow15.OXM_CLASS_NXM_1,
			dstField: openflow15.NXM_NX_IPV6_SRC,
		}
		fb := table.BuildFlow(1).Action().Learn(targetTable, priority, idleTimeout, hardTimeout, cookieID)
		action := fb.MatchLearnedSrcIPv6().(*ofLearnAction).nxLearn.GetActionMessage().(*openflow15.NXActionLearn)
		checkLearnSpecs(t, []*nxLearnSpec{expected}, action.LearnSpecs)
	})
	t.Run("MatchLearnedDstIPv6", func(t *testing.T) {
		expected := &nxLearnSpec{
			srcClass: openflow15.OXM_CLASS_NXM_1,
			srcField: openflow15.NXM_NX_IPV6_DST,
			dstClass: openflow15.OXM_CLASS_NXM_1,
			dstField: openflow15.NXM_NX_IPV6_DST,
		}
		fb := table.BuildFlow(1).Action().Learn(targetTable, priority, idleTimeout, hardTimeout, cookieID)
		action := fb.MatchLearnedDstIPv6().(*ofLearnAction).nxLearn.GetActionMessage().(*openflow15.NXActionLearn)
		checkLearnSpecs(t, []*nxLearnSpec{expected}, action.LearnSpecs)
	})
	t.Run("MatchRegMark", func(t *testing.T) {
		testCases := []struct {
			mark     *RegMark
			expected *nxLearnSpec
		}{
			{
				NewRegMark(NewRegField(11, 1, 16), 0xffff),
				&nxLearnSpec{
					dstClass:  openflow15.OXM_CLASS_NXM_1,
					dstField:  openflow15.NXM_NX_REG11,
					dstOffset: 1,
					srcValue:  []uint8{0xff, 0xff},
				},
			},
			{
				NewRegMark(NewRegField(1, 0, 31), 0xffff_ffff),
				&nxLearnSpec{
					dstClass:  openflow15.OXM_CLASS_NXM_1,
					dstField:  openflow15.NXM_NX_REG1,
					dstOffset: 0,
					srcValue:  []uint8{0xff, 0xff, 0xff, 0xff},
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).Action().Learn(targetTable, priority, idleTimeout, hardTimeout, cookieID)
			action := fb.MatchRegMark(tc.mark).(*ofLearnAction).nxLearn.GetActionMessage().(*openflow15.NXActionLearn)
			checkLearnSpecs(t, []*nxLearnSpec{tc.expected}, action.LearnSpecs)
		}
	})
	t.Run("LoadFieldToField", func(t *testing.T) {
		testCases := []struct {
			srcField *RegField
			dstField *RegField
			expected *nxLearnSpec
		}{
			{
				NewRegField(1, 1, 16),
				NewRegField(2, 2, 17),
				&nxLearnSpec{
					srcClass:  openflow15.OXM_CLASS_NXM_1,
					srcField:  openflow15.NXM_NX_REG1,
					srcOffset: 1,
					dstClass:  openflow15.OXM_CLASS_NXM_1,
					dstField:  openflow15.NXM_NX_REG2,
					dstOffset: 2,
				},
			},
			{
				NewRegField(3, 0, 31),
				NewRegField(4, 0, 31),
				&nxLearnSpec{
					srcClass:  openflow15.OXM_CLASS_NXM_1,
					srcField:  openflow15.NXM_NX_REG3,
					srcOffset: 0,
					dstClass:  openflow15.OXM_CLASS_NXM_1,
					dstField:  openflow15.NXM_NX_REG4,
					dstOffset: 0,
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).Action().Learn(targetTable, priority, idleTimeout, hardTimeout, cookieID)
			action := fb.LoadFieldToField(tc.srcField, tc.dstField).(*ofLearnAction).nxLearn.GetActionMessage().(*openflow15.NXActionLearn)
			checkLearnSpecs(t, []*nxLearnSpec{tc.expected}, action.LearnSpecs)
		}
	})
	t.Run("LoadXXRegToXXReg", func(t *testing.T) {
		testCases := []struct {
			srcField *XXRegField
			dstField *XXRegField
			expected *nxLearnSpec
		}{
			{
				NewXXRegField(0, 1, 100),
				NewXXRegField(1, 2, 101),
				&nxLearnSpec{
					srcClass:  openflow15.OXM_CLASS_NXM_1,
					srcField:  openflow15.NXM_NX_XXREG0,
					srcOffset: 1,
					dstClass:  openflow15.OXM_CLASS_NXM_1,
					dstField:  openflow15.NXM_NX_XXREG1,
					dstOffset: 2,
				},
			},
			{
				NewXXRegField(2, 0, 127),
				NewXXRegField(3, 0, 127),
				&nxLearnSpec{
					srcClass:  openflow15.OXM_CLASS_NXM_1,
					srcField:  openflow15.NXM_NX_XXREG2,
					srcOffset: 0,
					dstClass:  openflow15.OXM_CLASS_NXM_1,
					dstField:  openflow15.NXM_NX_XXREG3,
					dstOffset: 0,
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).Action().Learn(targetTable, priority, idleTimeout, hardTimeout, cookieID)
			action := fb.LoadXXRegToXXReg(tc.srcField, tc.dstField).(*ofLearnAction).nxLearn.GetActionMessage().(*openflow15.NXActionLearn)
			checkLearnSpecs(t, []*nxLearnSpec{tc.expected}, action.LearnSpecs)
		}
	})
	t.Run("LoadRegMark", func(t *testing.T) {
		testCases := []struct {
			mark     *RegMark
			expected *nxLearnSpec
		}{
			{
				NewRegMark(NewRegField(11, 1, 16), 0xffff),
				&nxLearnSpec{
					dstClass:  openflow15.OXM_CLASS_NXM_1,
					dstField:  openflow15.NXM_NX_REG11,
					dstOffset: 1,
					srcValue:  []uint8{0xff, 0xff},
				},
			},
			{
				NewRegMark(NewRegField(1, 0, 31), 0xffff_ffff),
				&nxLearnSpec{
					dstClass:  openflow15.OXM_CLASS_NXM_1,
					dstField:  openflow15.NXM_NX_REG1,
					dstOffset: 0,
					srcValue:  []uint8{0xff, 0xff, 0xff, 0xff},
				},
			},
		}
		for _, tc := range testCases {
			fb := table.BuildFlow(1).Action().Learn(targetTable, priority, idleTimeout, hardTimeout, cookieID)
			action := fb.LoadRegMark(tc.mark).(*ofLearnAction).nxLearn.GetActionMessage().(*openflow15.NXActionLearn)
			checkLearnSpecs(t, []*nxLearnSpec{tc.expected}, action.LearnSpecs)
		}
	})
	t.Run("DeleteLearned", func(t *testing.T) {
		fb := table.BuildFlow(1).Action().Learn(targetTable, priority, idleTimeout, hardTimeout, cookieID)
		action := fb.DeleteLearned().(*ofLearnAction).nxLearn.GetActionMessage().(*openflow15.NXActionLearn)
		assert.Equal(t, uint16(openflow15.NX_LEARN_F_DELETE_LEARNED), action.Flags)
	})
}
