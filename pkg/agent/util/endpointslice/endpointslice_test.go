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

package endpointslice

import (
	"testing"

	"github.com/stretchr/testify/assert"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/utils/ptr"
)

func TestCanServe(t *testing.T) {
	tests := []struct {
		name       string
		conditions discoveryv1.EndpointConditions
		expected   bool
	}{
		{name: "all conditions nil", expected: true},
		{name: "ready", conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)}, expected: true},
		{name: "ready, serving false", conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true), Serving: ptr.To(false)}, expected: true},
		{name: "not ready, serving nil", conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false)}, expected: true},
		{name: "not ready, serving", conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false), Serving: ptr.To(true)}, expected: true},
		{name: "not ready, not serving", conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false), Serving: ptr.To(false)}, expected: false},
		{
			// A Pod which is terminating but still draining its connections.
			name:       "terminating and serving",
			conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false), Serving: ptr.To(true), Terminating: ptr.To(true)},
			expected:   true,
		},
		{
			name:       "terminating and not serving",
			conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false), Serving: ptr.To(false), Terminating: ptr.To(true)},
			expected:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, CanServe(discoveryv1.Endpoint{Conditions: tt.conditions}))
		})
	}
}
