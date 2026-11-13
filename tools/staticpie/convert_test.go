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
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// report is the output of //tools/staticpie/testbinary.
type report struct {
	Func           uintptr
	Global         uintptr
	RelocatedOK    bool
	FuncWritable   bool
	GlobalWritable bool
	RELROSize      uint64
	RELROWritable  bool
}

func testBinary(t *testing.T) string {
	t.Helper()
	path, err := testutil.FindFile("tools/staticpie/testbinary/testbinary")
	if err != nil {
		t.Fatalf("cannot find test binary: %v", err)
	}
	return path
}

func TestRun(t *testing.T) {
	path := testBinary(t)
	const runs = 8
	funcs := make(map[uintptr]struct{})
	for i := 0; i < runs; i++ {
		var stdout, stderr bytes.Buffer
		cmd := exec.Command(path)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%s failed: %v, stderr: %s", path, err, stderr.String())
		}
		var r report
		if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
			t.Fatalf("cannot parse %q: %v", stdout.String(), err)
		}
		t.Logf("run %d: %+v", i, r)
		if !r.RelocatedOK {
			t.Errorf("relocated data has wrong values")
		}
		if r.FuncWritable {
			t.Errorf("text at %#x is writable", r.Func)
		}
		if !r.GlobalWritable {
			t.Errorf("global variable at %#x is not writable", r.Global)
		}
		if r.RELROSize == 0 {
			t.Errorf("no RELRO range")
		}
		if r.RELROWritable {
			t.Errorf("RELRO range is writable")
		}
		funcs[r.Func] = struct{}{}
	}
	if !randomizationEnabled(t) {
		t.Logf("address space randomization is disabled; not checking addresses")
		return
	}
	if len(funcs) < 2 {
		t.Errorf("text address is the same in all %d runs", runs)
	}
}

// randomizationEnabled returns true if the kernel loads child processes of
// the test at random addresses.
func randomizationEnabled(t *testing.T) bool {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/kernel/randomize_va_space")
	if err != nil {
		t.Fatalf("cannot read randomize_va_space: %v", err)
	}
	if strings.TrimSpace(string(b)) == "0" {
		return false
	}
	// personality(0xffffffff) returns the current personality.
	persona, _, errno := unix.RawSyscall(unix.SYS_PERSONALITY, 0xffffffff, 0, 0)
	if errno != 0 {
		t.Fatalf("cannot get personality: %v", errno)
	}
	const addrNoRandomize = 0x0040000
	return persona&addrNoRandomize == 0
}

func TestELF(t *testing.T) {
	f, err := elf.Open(testBinary(t))
	if err != nil {
		t.Fatalf("cannot open test binary: %v", err)
	}
	defer f.Close()
	if f.Type != elf.ET_DYN {
		t.Errorf("got type %v, want %v", f.Type, elf.ET_DYN)
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			t.Errorf("got PT_INTERP")
		}
	}
	if s := f.Section(".interp"); s != nil {
		b, err := s.Data()
		if err != nil {
			t.Fatalf("cannot read .interp: %v", err)
		}
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("got .interp %q, want zeros", b)
		}
	}
}

// TestEntryFailure checks that the entry point exits with status 127 and a
// message if it cannot start the binary.
func TestEntryFailure(t *testing.T) {
	static, err := os.ReadFile(testBinary(t))
	if err != nil {
		t.Fatalf("cannot read test binary: %v", err)
	}
	f, err := elf.NewFile(bytes.NewReader(static))
	if err != nil {
		t.Fatalf("cannot parse ELF: %v", err)
	}
	relas, err := f.DynValue(elf.DT_RELA)
	if err != nil || len(relas) != 1 {
		t.Fatalf("cannot find DT_RELA: %v %v", relas, err)
	}
	for _, test := range []struct {
		name   string
		modify func(data []byte)
	}{
		{
			name: "NoPHDR",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint32(data[phdrOffset(t, f, data, elf.PT_PHDR):], uint32(elf.PT_NOTE))
			},
		},
		{
			name: "RelocationType",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint64(data[fileOffset(t, f, relas[0])+relaInfo:], 1)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := bytes.Clone(static)
			test.modify(data)
			path := filepath.Join(t.TempDir(), "binary")
			if err := os.WriteFile(path, data, 0755); err != nil {
				t.Fatalf("cannot write binary: %v", err)
			}
			var stderr bytes.Buffer
			cmd := exec.Command(path)
			cmd.Stderr = &stderr
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 127 {
				t.Errorf("got error %v, want exit status 127", err)
			}
			if want := "static PIE: cannot relocate the binary\n"; stderr.String() != want {
				t.Errorf("got stderr %q, want %q", stderr.String(), want)
			}
		})
	}
}

// restoreInterp returns a copy of the static PIE data with PT_INTERP instead of
// the PT_NULL program header that convert wrote.
func restoreInterp(t *testing.T, data []byte) []byte {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("cannot parse ELF: %v", err)
	}
	out := bytes.Clone(data)
	phoff, phentsize := phdrTable(out)
	for i, p := range f.Progs {
		if p.Type == elf.PT_NULL {
			binary.LittleEndian.PutUint32(out[phoff+uint64(i)*phentsize:], uint32(elf.PT_INTERP))
			return out
		}
	}
	t.Fatalf("no PT_NULL")
	return nil
}

// fileOffset returns the file offset of virtual address addr.
func fileOffset(t *testing.T, f *elf.File, addr uint64) uint64 {
	t.Helper()
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && addr >= p.Vaddr && addr < p.Vaddr+p.Filesz {
			return p.Off + addr - p.Vaddr
		}
	}
	t.Fatalf("address %#x is not in a PT_LOAD", addr)
	return 0
}

// dynOffset returns the file offset of the first dynamic entry with tag.
func dynOffset(t *testing.T, f *elf.File, data []byte, tag elf.DynTag) uint64 {
	t.Helper()
	for _, p := range f.Progs {
		if p.Type != elf.PT_DYNAMIC {
			continue
		}
		for off := p.Off; off+dynSize <= p.Off+p.Filesz; off += dynSize {
			if elf.DynTag(binary.LittleEndian.Uint64(data[off:])) == tag {
				return off
			}
		}
	}
	t.Fatalf("no dynamic entry %v", tag)
	return 0
}

// Offsets of ELF64 header fields.
const (
	ehdrType  = 16
	ehdrEntry = 24
)

// Offsets of ELF64 program header fields.
const (
	phdrFlags = 4
	phdrVaddr = 16
	phdrMemsz = 40
)

// Offsets of ELF64 dynamic entry and relocation fields.
const (
	dynVal     = 8
	relaInfo   = 8
	relaAddend = 16
)

// phdrOffset returns the file offset of the first program header with type
// typ.
func phdrOffset(t *testing.T, f *elf.File, data []byte, typ elf.ProgType) uint64 {
	t.Helper()
	phoff, phentsize := phdrTable(data)
	for i, p := range f.Progs {
		if p.Type == typ {
			return phoff + uint64(i)*phentsize
		}
	}
	t.Fatalf("no program header %v", typ)
	return 0
}

// loadOffset returns the file offset of the program header of the first
// PT_LOAD with flag.
func loadOffset(t *testing.T, f *elf.File, data []byte, flag elf.ProgFlag) uint64 {
	t.Helper()
	phoff, phentsize := phdrTable(data)
	for i, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&flag != 0 {
			return phoff + uint64(i)*phentsize
		}
	}
	t.Fatalf("no PT_LOAD with %v", flag)
	return 0
}

// writableLoad returns the last writable PT_LOAD.
func writableLoad(t *testing.T, f *elf.File) *elf.Prog {
	t.Helper()
	var w *elf.Prog
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_W != 0 {
			w = p
		}
	}
	if w == nil {
		t.Fatalf("no writable PT_LOAD")
	}
	return w
}

// symbolValueOffset returns the file offset of the value of symbol name in the
// symbol table.
func symbolValueOffset(t *testing.T, f *elf.File, data []byte, name string) (uint64, bool) {
	t.Helper()
	symtab := f.SectionByType(elf.SHT_SYMTAB)
	if symtab == nil {
		return 0, false
	}
	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("cannot read symbols: %v", err)
	}
	for i, s := range syms {
		if s.Name == name {
			// f.Symbols skips the first, empty, symbol.
			const symSize, valueOffset = 24, 8
			return symtab.Offset + uint64(i+1)*symSize + valueOffset, true
		}
	}
	t.Fatalf("no symbol %s", name)
	return 0, false
}

func TestConvert(t *testing.T) {
	static, err := os.ReadFile(testBinary(t))
	if err != nil {
		t.Fatalf("cannot read test binary: %v", err)
	}
	dynamic := restoreInterp(t, static)
	f, err := elf.NewFile(bytes.NewReader(dynamic))
	if err != nil {
		t.Fatalf("cannot parse ELF: %v", err)
	}
	relas, err := f.DynValue(elf.DT_RELA)
	if err != nil || len(relas) != 1 {
		t.Fatalf("cannot find DT_RELA: %v %v", relas, err)
	}
	firstRela := fileOffset(t, f, relas[0])
	_, symErr := f.Symbols()

	t.Run("OK", func(t *testing.T) {
		data := bytes.Clone(dynamic)
		if err := convert(data); err != nil {
			t.Fatalf("convert failed: %v", err)
		}
		if !bytes.Equal(data, static) {
			t.Errorf("convert result differs from the test binary")
		}
	})

	for _, test := range []struct {
		name   string
		modify func(data []byte)
		want   string
		skip   bool
	}{
		{
			name:   "NoInterp",
			modify: func(data []byte) { copy(data, static) },
			want:   "no PT_INTERP",
		},
		{
			name: "NotPIE",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint16(data[ehdrType:], uint16(elf.ET_EXEC))
			},
			want: "want ET_DYN",
		},
		{
			name: "WrongEntryCode",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint64(data[ehdrEntry:], f.Entry+1)
			},
			want: "is not " + entrySymbol,
		},
		{
			name: "WrongEntrySymbol",
			modify: func(data []byte) {
				// Change the symbol value, such that the code at the entry
				// point is still correct.
				off, ok := symbolValueOffset(t, f, data, entrySymbol)
				if !ok {
					return
				}
				binary.LittleEndian.PutUint64(data[off:], f.Entry+1)
			},
			want: "got entry point",
			skip: errors.Is(symErr, elf.ErrNoSymbols),
		},
		{
			name: "NoRELRO",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint32(data[phdrOffset(t, f, data, elf.PT_GNU_RELRO):], uint32(elf.PT_NOTE))
			},
			want: "no PT_GNU_RELRO",
		},
		{
			name: "RELROMisaligned",
			modify: func(data []byte) {
				off := phdrOffset(t, f, data, elf.PT_GNU_RELRO) + phdrVaddr
				binary.LittleEndian.PutUint64(data[off:], binary.LittleEndian.Uint64(data[off:])+8)
			},
			want: "is not aligned",
		},
		{
			name: "RELROPageShared",
			modify: func(data []byte) {
				// End the RELRO range before the end of its PT_LOAD.
				off := phdrOffset(t, f, data, elf.PT_GNU_RELRO) + phdrMemsz
				binary.LittleEndian.PutUint64(data[off:], binary.LittleEndian.Uint64(data[off:])-8)
			},
			want: "in the same page",
		},
		{
			name: "NoDynamicNull",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint64(data[dynOffset(t, f, data, elf.DT_NULL):], uint64(elf.DT_GNU_HASH))
			},
			want: "no DT_NULL",
		},
		{
			name: "RelocationType",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint64(data[firstRela+relaInfo:], 1)
			},
			want: "got type 1",
		},
		{
			name: "RelocationSymbol",
			modify: func(data []byte) {
				info := binary.LittleEndian.Uint64(data[firstRela+relaInfo:])
				binary.LittleEndian.PutUint64(data[firstRela+relaInfo:], info|1<<32)
			},
			want: "symbol 1",
		},
		{
			name: "RelocationNotWritable",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint64(data[firstRela:], f.Entry)
			},
			want: "not in a writable PT_LOAD",
		},
		{
			name: "DynamicTag",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint64(data[dynOffset(t, f, data, elf.DT_DEBUG):], uint64(elf.DT_NEEDED))
			},
			want: "unsupported dynamic tag DT_NEEDED",
		},
		{
			name: "NoPHDR",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint32(data[phdrOffset(t, f, data, elf.PT_PHDR):], uint32(elf.PT_NOTE))
			},
			want: "no PT_PHDR",
		},
		{
			name: "NoDynamic",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint32(data[phdrOffset(t, f, data, elf.PT_DYNAMIC):], uint32(elf.PT_NOTE))
			},
			want: "no PT_DYNAMIC",
		},
		{
			name: "DuplicatePHDR",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint32(data[phdrOffset(t, f, data, elf.PT_NOTE):], uint32(elf.PT_PHDR))
			},
			want: "more than one PT_PHDR",
		},
		{
			name: "WritableExecutable",
			modify: func(data []byte) {
				off := loadOffset(t, f, data, elf.PF_X) + phdrFlags
				binary.LittleEndian.PutUint32(data[off:], binary.LittleEndian.Uint32(data[off:])|uint32(elf.PF_W))
			},
			want: "writable and executable",
		},
		{
			name: "ExecutableStack",
			modify: func(data []byte) {
				off := phdrOffset(t, f, data, elf.PT_GNU_STACK) + phdrFlags
				binary.LittleEndian.PutUint32(data[off:], binary.LittleEndian.Uint32(data[off:])|uint32(elf.PF_X))
			},
			want: "no PT_GNU_STACK without PF_X",
		},
		{
			name: "RELRONotWritable",
			modify: func(data []byte) {
				off := loadOffset(t, f, data, elf.PF_W) + phdrFlags
				binary.LittleEndian.PutUint32(data[off:], binary.LittleEndian.Uint32(data[off:])&^uint32(elf.PF_W))
			},
			want: "is not in a writable PT_LOAD",
		},
		{
			name: "DuplicateDynamicTag",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint64(data[dynOffset(t, f, data, elf.DT_DEBUG):], uint64(elf.DT_RELA))
			},
			want: "more than one dynamic tag DT_RELA",
		},
		{
			name: "RelaEnt",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint64(data[dynOffset(t, f, data, elf.DT_RELAENT)+dynVal:], 16)
			},
			want: "got DT_RELAENT 16",
		},
		{
			name: "PLTRelSz",
			modify: func(data []byte) {
				off := dynOffset(t, f, data, elf.DT_DEBUG)
				binary.LittleEndian.PutUint64(data[off:], uint64(elf.DT_PLTRELSZ))
				binary.LittleEndian.PutUint64(data[off+dynVal:], relaSize)
			},
			want: "got DT_PLTRELSZ 24",
		},
		{
			name: "TextRel",
			modify: func(data []byte) {
				off := dynOffset(t, f, data, elf.DT_DEBUG)
				binary.LittleEndian.PutUint64(data[off:], uint64(elf.DT_FLAGS))
				binary.LittleEndian.PutUint64(data[off+dynVal:], uint64(elf.DF_TEXTREL))
			},
			want: "unsupported DT_FLAGS",
		},
		{
			name: "RelaSzNotMultiple",
			modify: func(data []byte) {
				off := dynOffset(t, f, data, elf.DT_RELASZ) + dynVal
				binary.LittleEndian.PutUint64(data[off:], binary.LittleEndian.Uint64(data[off:])-1)
			},
			want: "is not a multiple of",
		},
		{
			name: "RelaSzWithoutRela",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint64(data[dynOffset(t, f, data, elf.DT_RELA)+dynVal:], 0)
			},
			want: "DT_RELASZ without DT_RELA",
		},
		{
			name: "RelocationAddend",
			modify: func(data []byte) {
				binary.LittleEndian.PutUint64(data[firstRela+relaAddend:], 1<<62)
			},
			want: "is not in a PT_LOAD",
		},
		{
			name: "RelocationAtEnd",
			modify: func(data []byte) {
				// The last byte of the relocated word is after the end of
				// the writable PT_LOAD.
				p := writableLoad(t, f)
				binary.LittleEndian.PutUint64(data[firstRela:], p.Vaddr+p.Memsz-7)
			},
			want: "not in a writable PT_LOAD",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.skip {
				t.Skip("not applicable to this binary")
			}
			data := bytes.Clone(dynamic)
			test.modify(data)
			orig := bytes.Clone(data)
			err := convert(data)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("got error %v, want error containing %q", err, test.want)
			}
			if !bytes.Equal(data, orig) {
				t.Errorf("convert changed the data after an error")
			}
		})
	}
}
