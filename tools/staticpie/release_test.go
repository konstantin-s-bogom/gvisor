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

package main

import (
	"debug/elf"
	"flag"
	"io/fs"
	"path/filepath"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

var wantStaticPIE = flag.Bool("want_static_pie", true, "whether the Go binaries of the release must be static PIEs")

// notStaticPIE are the Go binaries of the release, relative to the release
// directory, that are not static PIEs.
var notStaticPIE = map[string]bool{
	"containerd-shim-runsc-v1": true,
}

// TestRelease checks that the Go binaries of //:release are static PIEs.
func TestRelease(t *testing.T) {
	if !*wantStaticPIE {
		t.Skip("the Go binaries of this release flavor are not static PIEs")
	}
	runsc, err := testutil.FindFile("release/runsc")
	if err != nil {
		t.Fatalf("cannot find release: %v", err)
	}
	dir := filepath.Dir(runsc)
	checked := 0
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		f, err := elf.Open(path)
		if err != nil {
			// Not an ELF file.
			return nil
		}
		defer f.Close()
		if f.Section(".go.buildinfo") == nil || notStaticPIE[rel] {
			return nil
		}
		checked++
		if f.Type != elf.ET_DYN {
			t.Errorf("%s: got type %v, want %v", rel, f.Type, elf.ET_DYN)
		}
		for _, p := range f.Progs {
			if p.Type == elf.PT_INTERP {
				t.Errorf("%s: got PT_INTERP", rel)
			}
		}
		if a, ok := arches[f.Machine]; !ok {
			t.Errorf("%s: unsupported machine %v", rel, f.Machine)
		} else if err := checkEntry(f, a.entryCode); err != nil {
			t.Errorf("%s: %v", rel, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("cannot walk %s: %v", dir, err)
	}
	if checked == 0 {
		t.Errorf("no Go binaries in %s", dir)
	}
}
