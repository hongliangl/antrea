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
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
)

func getMeterMod(t *testing.T, m Meter) *openflow15.MeterMod {
	msgs, err := m.GetBundleMessages(AddMessage)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(msgs))
	return msgs[0].GetMessage().(*openflow15.MeterMod)
}

func TestMeterBandBuilder(t *testing.T) {
	m := &ofMeter{ofctrl: &ofctrl.Meter{}}

	t.Run("MeterType", func(t *testing.T) {
		testCases := []struct {
			meterType        ofctrl.MeterType
			expectedBandType util.Message
		}{
			{ofctrl.MeterDrop, &openflow15.MeterBandDrop{}},
			{ofctrl.MeterDSCPRemark, &openflow15.MeterBandDSCP{}},
			{ofctrl.MeterExperimenter, &openflow15.MeterBandExperimenter{}},
		}
		for _, tc := range testCases {
			m.ResetMeterBands()
			meter := m.MeterBand().MeterType(tc.meterType).Done()
			meterMod := getMeterMod(t, meter)
			assert.Equal(t, 1, len(meterMod.MeterBands))
			assert.IsType(t, tc.expectedBandType, meterMod.MeterBands[0])
		}
	})
	t.Run("Rate", func(t *testing.T) {
		testCases := []struct {
			rate uint32
		}{
			{100},
			{200},
		}
		for _, tc := range testCases {
			m.ResetMeterBands()
			meter := m.MeterBand().MeterType(ofctrl.MeterDSCPRemark).Rate(tc.rate).Done()
			meterMod := getMeterMod(t, meter)
			assert.Equal(t, 1, len(meterMod.MeterBands))
			assert.Equal(t, tc.rate, meterMod.MeterBands[0].(*openflow15.MeterBandDSCP).MeterBandHeader.Rate)
		}
	})
	t.Run("Burst", func(t *testing.T) {
		testCases := []struct {
			burst uint32
		}{
			{100},
			{200},
		}
		for _, tc := range testCases {
			m.ResetMeterBands()
			meter := m.MeterBand().MeterType(ofctrl.MeterDSCPRemark).Burst(tc.burst).Done()
			meterMod := getMeterMod(t, meter)
			assert.Equal(t, 1, len(meterMod.MeterBands))
			assert.Equal(t, tc.burst, meterMod.MeterBands[0].(*openflow15.MeterBandDSCP).MeterBandHeader.BurstSize)
		}
	})
	t.Run("PrecLevel", func(t *testing.T) {
		testCases := []struct {
			precLevel uint8
		}{
			{100},
			{200},
		}
		for _, tc := range testCases {
			m.ResetMeterBands()
			meter := m.MeterBand().MeterType(ofctrl.MeterDSCPRemark).PrecLevel(tc.precLevel).Done()
			meterMod := getMeterMod(t, meter)
			assert.Equal(t, 1, len(meterMod.MeterBands))
			assert.Equal(t, tc.precLevel, meterMod.MeterBands[0].(*openflow15.MeterBandDSCP).PrecLevel)
		}
	})
	t.Run("Experimenter", func(t *testing.T) {
		testCases := []struct {
			experimenter uint32
		}{
			{100},
			{200},
		}
		for _, tc := range testCases {
			m.ResetMeterBands()
			meter := m.MeterBand().MeterType(ofctrl.MeterExperimenter).Experimenter(tc.experimenter).Done()
			meterMod := getMeterMod(t, meter)
			assert.Equal(t, 1, len(meterMod.MeterBands))
			assert.Equal(t, tc.experimenter, meterMod.MeterBands[0].(*openflow15.MeterBandExperimenter).Experimenter)
		}
	})
}
