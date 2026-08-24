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

package hostdp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseMode(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		expectedMode Mode
		expectedErr  string
	}{
		{name: "observe", value: "observe", expectedMode: ModeObserve},
		{name: "forward", value: "forward", expectedMode: ModeForward},
		{name: "empty", value: "", expectedErr: `mode "" is unknown`},
		{name: "unknown", value: "Forward", expectedErr: `mode "Forward" is unknown`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, err := ParseMode(tt.value)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedMode, mode)
		})
	}
}
