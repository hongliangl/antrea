#!/usr/bin/env bash

# Copyright 2026 Antrea Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Check that the committed BPF objects are up to date.

set -o errexit
set -o nounset
set -o pipefail

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${THIS_DIR}/.."

make bpf-objects
if ! git diff --exit-code -- pkg/agent/ebpf/internal/objects/; then
    echo "BPF objects are out of date. Run 'make bpf-objects' and commit the generated changes." >&2
    exit 1
fi
