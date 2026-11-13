// Copyright 2026 The gVisor Authors.
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

//go:build linux && (amd64 || arm64)

// Package staticpie provides the entry point of static position-independent
// executables (static PIE) built with the Go internal linker.
//
// The Go internal linker can only make a PIE that requests a dynamic loader
// (PT_INTERP), and the dynamic loader applies the relocations of the PIE. The
// entry point in this package, _rt0_gvisor_static_pie, does that work
// instead, such that the binary does not need a dynamic loader:
//
//   - It finds the load bias from the PT_PHDR program header and AT_PHDR.
//   - It applies all R_*_RELATIVE relocations in DT_RELA.
//   - It makes the pages of the PT_GNU_RELRO range read-only.
//   - It jumps to the Go runtime entry point.
//
// If the binary has an unexpected structure, the entry point prints a message
// and exits with status 127.
//
// To build such a binary, use the static_pie attribute of go_binary in
// //tools:defs.bzl. This links the binary with "-buildmode=pie" and
// "-E _rt0_gvisor_static_pie", and then uses //tools/staticpie to remove the
// PT_INTERP program header. //tools/staticpie also makes sure that the binary
// contains only relocations that the entry point can apply.
package staticpie
