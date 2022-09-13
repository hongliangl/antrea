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

package openflow

import (
	"net"
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
)

func getGroupMod(t *testing.T, g Group) *openflow15.GroupMod {
	msgs, err := g.GetBundleMessages(AddMessage)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(msgs))
	return msgs[0].GetMessage().(*openflow15.GroupMod)
}

func TestBucketBuilder(t *testing.T) {
	g := &ofGroup{ofctrl: &ofctrl.Group{}}

	t.Run("Weight", func(t *testing.T) {
		testWeights := []uint16{100, 190}

		for _, weight := range testWeights {
			g.ResetBuckets()
			group := g.Bucket().Weight(weight).Done()
			groupMod := getGroupMod(t, group)
			assert.Equal(t, 1, len(groupMod.Buckets))
			assert.Equal(t, 1, len(groupMod.Buckets[0].Properties))
			assert.Equal(t, weight, groupMod.Buckets[0].Properties[0].(*openflow15.GroupBucketPropWeight).Weight)
		}
	})
	t.Run("LoadToRegField", func(t *testing.T) {
		testCases := []struct {
			regField *RegField
			value    uint32
			expected *actionSetField
		}{
			{
				regField: NewRegField(1, 0, 31),
				value:    uint32(0xffff_ffff),
				expected: &actionSetField{
					class:      openflow15.OXM_CLASS_NXM_1,
					field:      openflow15.NXM_NX_REG1,
					fieldValue: &openflow15.Uint32Message{Data: uint32(0xffff_ffff)},
					fieldMask:  &openflow15.Uint32Message{Data: uint32(0xffff_ffff)},
				},
			},
			{
				regField: NewRegField(1, 4, 15),
				value:    uint32(0xf),
				expected: &actionSetField{
					class:      openflow15.OXM_CLASS_NXM_1,
					field:      openflow15.NXM_NX_REG1,
					fieldValue: &openflow15.Uint32Message{Data: uint32(0xf0)},
					fieldMask:  &openflow15.Uint32Message{Data: uint32(0xfff0)},
				},
			},
		}
		for _, tc := range testCases {
			g.ResetBuckets()
			group := g.Bucket().LoadToRegField(tc.regField, tc.value).Done()
			groupMod := getGroupMod(t, group)
			assert.Equal(t, 1, len(groupMod.Buckets))
			checkActionSetField(t, []*actionSetField{tc.expected}, groupMod.Buckets[0].Actions)
		}
	})
	t.Run("LoadXXReg", func(t *testing.T) {
		testCases := []struct {
			regID    int
			data     []byte
			expected *actionSetField
		}{
			{
				regID: 0,
				data:  []byte{0x11, 0x22, 0x33, 0x44},
				expected: &actionSetField{
					class:      openflow15.OXM_CLASS_NXM_1,
					field:      openflow15.NXM_NX_XXREG0,
					fieldValue: util.NewBuffer([]byte{0x11, 0x22, 0x33, 0x44}),
				},
			},
			{
				regID: 2,
				data:  []byte{0x11, 0x22, 0x33, 0x44},
				expected: &actionSetField{
					class:      openflow15.OXM_CLASS_NXM_1,
					field:      openflow15.NXM_NX_XXREG2,
					fieldValue: util.NewBuffer([]byte{0x11, 0x22, 0x33, 0x44}),
				},
			},
		}
		for _, tc := range testCases {
			g.ResetBuckets()
			group := g.Bucket().LoadXXReg(tc.regID, tc.data).Done()
			groupMod := getGroupMod(t, group)
			assert.Equal(t, 1, len(groupMod.Buckets))
			checkActionSetField(t, []*actionSetField{tc.expected}, groupMod.Buckets[0].Actions)
		}
	})
	t.Run("SetTunnelDst", func(t *testing.T) {
		testCases := []struct {
			dstIP    net.IP
			expected *actionSetField
		}{
			{
				dstIP: net.ParseIP("1.1.1.1"),
				expected: &actionSetField{
					class:         openflow15.OXM_CLASS_NXM_1,
					field:         openflow15.NXM_NX_TUN_IPV4_DST,
					tunnelIPv4Dst: net.ParseIP("1.1.1.1"),
				},
			},
			{
				dstIP: net.ParseIP("2.2.2.2"),
				expected: &actionSetField{
					class:         openflow15.OXM_CLASS_NXM_1,
					field:         openflow15.NXM_NX_TUN_IPV4_DST,
					tunnelIPv4Dst: net.ParseIP("2.2.2.2"),
				},
			},
			{
				dstIP: net.ParseIP("fec0::1111"),
				expected: &actionSetField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_TUN_IPV6_DST,
					ipv6Dst: net.ParseIP("fec0::1111"),
				},
			},
			{
				dstIP: net.ParseIP("fec0::2222"),
				expected: &actionSetField{
					class:   openflow15.OXM_CLASS_NXM_1,
					field:   openflow15.NXM_NX_TUN_IPV6_DST,
					ipv6Dst: net.ParseIP("fec0::2222"),
				},
			},
		}
		for _, tc := range testCases {
			g.ResetBuckets()
			group := g.Bucket().SetTunnelDst(tc.dstIP).Done()
			groupMod := getGroupMod(t, group)
			assert.Equal(t, 1, len(groupMod.Buckets))
			checkActionSetField(t, []*actionSetField{tc.expected}, groupMod.Buckets[0].Actions)
		}
	})
	t.Run("ResubmitToTable", func(t *testing.T) {
		testCases := []struct {
			tableID uint8
		}{
			{uint8(8)},
			{uint8(9)},
		}
		for _, tc := range testCases {
			g.ResetBuckets()
			group := g.Bucket().ResubmitToTable(tc.tableID).Done()
			groupMod := getGroupMod(t, group)
			assert.Equal(t, 1, len(groupMod.Buckets))
			assert.Equal(t, 1, len(groupMod.Buckets[0].Actions))
			assert.IsType(t, &openflow15.NXActionResubmitTable{}, groupMod.Buckets[0].Actions[0])

			action := groupMod.Buckets[0].Actions[0].(*openflow15.NXActionResubmitTable)
			assert.Equal(t, uint16(openflow15.OFPP_IN_PORT), action.InPort)
			assert.Equal(t, tc.tableID, action.TableID)
		}
	})
}
