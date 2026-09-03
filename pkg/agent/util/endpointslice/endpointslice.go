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
	discoveryv1 "k8s.io/api/discovery/v1"
)

// CanServe reports whether traffic sent to the endpoint would be delivered. It is true for a ready
// endpoint, and for an endpoint which is not ready but still serving, which is the state of a Pod
// that is terminating while it drains its connections.
func CanServe(ep discoveryv1.Endpoint) bool {
	if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
		return true
	}
	if ep.Conditions.Serving == nil || *ep.Conditions.Serving {
		return true
	}
	return false
}
