// Copyright 2019 The gVisor Authors.
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

// Package platforms imports all available platform packages.
package platforms

import (
	// Import platforms that runsc might use.
	_ "gvisor.dev/gvisor/pkg/sentry/platform/kvm"
	_ "gvisor.dev/gvisor/pkg/sentry/platform/ptrace"
)

const (
	// Ptrace runs the sandbox with the ptrace platform.
	Ptrace = "ptrace"

	// KVM runs the sandbox with the KVM platform.
	KVM = "kvm"

	// Seccomp runs the sandbox with the seccomp platform.
	Seccomp = "seccomp"
)
