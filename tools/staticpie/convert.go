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
	"errors"
	"fmt"
)

// entrySymbol is the entry point that //pkg/staticpie defines.
const entrySymbol = "_rt0_gvisor_static_pie"

const (
	dynSize  = 16
	relaSize = 24
)

// Offsets of ELF64 header fields.
const (
	ehdrPhoff     = 32
	ehdrPhentsize = 54
)

// arch describes the properties of an architecture that convert checks.
type arch struct {
	// relative is the type of relative relocations.
	relative uint32
	// maxPageSize is the largest page size that Linux supports.
	maxPageSize uint64
	// entryCode is the machine code of the first two instructions of
	// entrySymbol.
	entryCode []byte
}

var arches = map[elf.Machine]arch{
	elf.EM_X86_64: {
		relative:    uint32(elf.R_X86_64_RELATIVE),
		maxPageSize: 4 << 10,
		entryCode: []byte{
			0x48, 0x8b, 0x04, 0x24, // MOVQ 0(SP), AX
			0x48, 0x8d, 0x5c, 0xc4, 0x10, // LEAQ 16(SP)(AX*8), BX
		},
	},
	elf.EM_AARCH64: {
		relative:    uint32(elf.R_AARCH64_RELATIVE),
		maxPageSize: 64 << 10,
		entryCode: []byte{
			0xe0, 0x03, 0x40, 0xf9, // MOVD 0(RSP), R0
			0xe1, 0x03, 0x00, 0x91, // MOVD RSP, R1
		},
	},
}

// allowedDynTags are the dynamic section tags that can be in the input. The
// entry point of //pkg/staticpie uses only DT_RELA and DT_RELASZ. The other
// tags are in the input, but they have no effect without a dynamic loader.
// Tags that are not in this set can have an effect that the entry point does
// not implement, thus convert does not accept them.
var allowedDynTags = map[elf.DynTag]bool{
	elf.DT_NULL:       true,
	elf.DT_HASH:       true,
	elf.DT_GNU_HASH:   true,
	elf.DT_STRTAB:     true,
	elf.DT_SYMTAB:     true,
	elf.DT_STRSZ:      true,
	elf.DT_SYMENT:     true,
	elf.DT_RELA:       true,
	elf.DT_RELASZ:     true,
	elf.DT_RELAENT:    true,
	elf.DT_PLTGOT:     true,
	elf.DT_PLTREL:     true,
	elf.DT_PLTRELSZ:   true,
	elf.DT_JMPREL:     true,
	elf.DT_DEBUG:      true,
	elf.DT_FLAGS:      true,
	elf.DT_FLAGS_1:    true,
	elf.DT_VERSYM:     true,
	elf.DT_VERNEED:    true,
	elf.DT_VERNEEDNUM: true,
}

// convert changes data, an ELF PIE, into a static PIE. It returns an error if
// the entry point of //pkg/staticpie cannot start the result.
func convert(data []byte) error {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return err
	}
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB {
		return fmt.Errorf("got %v %v, want %v %v", f.Class, f.Data, elf.ELFCLASS64, elf.ELFDATA2LSB)
	}
	if f.Type != elf.ET_DYN {
		return fmt.Errorf("got type %v, want %v; is the binary linked with -buildmode=pie?", f.Type, elf.ET_DYN)
	}
	a, ok := arches[f.Machine]
	if !ok {
		return fmt.Errorf("unsupported machine %v", f.Machine)
	}

	interp := -1
	var phdr, dynamic, relro, stack *elf.Prog
	for i, p := range f.Progs {
		switch p.Type {
		case elf.PT_LOAD:
			if p.Flags&elf.PF_W != 0 && p.Flags&elf.PF_X != 0 {
				return fmt.Errorf("PT_LOAD at %#x is writable and executable", p.Vaddr)
			}
		case elf.PT_GNU_STACK:
			if stack != nil {
				return errors.New("more than one PT_GNU_STACK")
			}
			stack = p
		case elf.PT_INTERP:
			if interp >= 0 {
				return errors.New("more than one PT_INTERP")
			}
			interp = i
		case elf.PT_PHDR:
			if phdr != nil {
				return errors.New("more than one PT_PHDR")
			}
			phdr = p
		case elf.PT_DYNAMIC:
			if dynamic != nil {
				return errors.New("more than one PT_DYNAMIC")
			}
			dynamic = p
		case elf.PT_GNU_RELRO:
			if relro != nil {
				return errors.New("more than one PT_GNU_RELRO")
			}
			relro = p
		}
	}
	if interp < 0 {
		return errors.New("no PT_INTERP")
	}
	if phdr == nil {
		return errors.New("no PT_PHDR")
	}
	if dynamic == nil {
		return errors.New("no PT_DYNAMIC")
	}
	if relro == nil {
		return errors.New("no PT_GNU_RELRO")
	}
	if stack == nil || stack.Flags&elf.PF_X != 0 {
		return errors.New("no PT_GNU_STACK without PF_X")
	}
	if err := checkRELRO(f, relro, a.maxPageSize); err != nil {
		return err
	}
	if err := checkEntry(f, a.entryCode); err != nil {
		return err
	}

	// Read the dynamic section.
	dyn := make([]byte, dynamic.Filesz)
	if _, err := dynamic.ReadAt(dyn, 0); err != nil {
		return fmt.Errorf("cannot read PT_DYNAMIC: %w", err)
	}
	var rela, relasz uint64
	foundNull := false
	seen := make(map[elf.DynTag]bool)
	for off := 0; !foundNull && off+dynSize <= len(dyn); off += dynSize {
		tag := elf.DynTag(binary.LittleEndian.Uint64(dyn[off:]))
		val := binary.LittleEndian.Uint64(dyn[off+8:])
		if !allowedDynTags[tag] {
			return fmt.Errorf("unsupported dynamic tag %v", tag)
		}
		if seen[tag] {
			return fmt.Errorf("more than one dynamic tag %v", tag)
		}
		seen[tag] = true
		switch tag {
		case elf.DT_NULL:
			foundNull = true
		case elf.DT_RELA:
			rela = val
		case elf.DT_RELASZ:
			relasz = val
		case elf.DT_RELAENT:
			if val != relaSize {
				return fmt.Errorf("got DT_RELAENT %d, want %d", val, relaSize)
			}
		case elf.DT_PLTRELSZ:
			if val != 0 {
				return fmt.Errorf("got DT_PLTRELSZ %d, want 0", val)
			}
		case elf.DT_VERNEEDNUM:
			if val != 0 {
				return fmt.Errorf("got DT_VERNEEDNUM %d, want 0", val)
			}
		case elf.DT_FLAGS:
			if val&uint64(elf.DF_TEXTREL|elf.DF_STATIC_TLS) != 0 {
				return fmt.Errorf("unsupported DT_FLAGS %#x", val)
			}
		}
	}
	if !foundNull {
		return errors.New("no DT_NULL in PT_DYNAMIC")
	}
	if relasz%relaSize != 0 {
		return fmt.Errorf("DT_RELASZ %d is not a multiple of %d", relasz, relaSize)
	}
	if relasz != 0 && rela == 0 {
		return errors.New("DT_RELASZ without DT_RELA")
	}

	// Check the relocations.
	relocs, err := readVirtual(f, rela, relasz)
	if err != nil {
		return fmt.Errorf("cannot read DT_RELA: %w", err)
	}
	for off := 0; off < len(relocs); off += relaSize {
		offset := binary.LittleEndian.Uint64(relocs[off:])
		info := binary.LittleEndian.Uint64(relocs[off+8:])
		if info != uint64(a.relative) {
			return fmt.Errorf("relocation at %#x: got type %d symbol %d, want type %d symbol 0", offset, uint32(info), info>>32, a.relative)
		}
		if !inWritableLoad(f, offset, 8) {
			return fmt.Errorf("relocation at %#x is not in a writable PT_LOAD", offset)
		}
		if addend := binary.LittleEndian.Uint64(relocs[off+16:]); !inLoad(f, addend) {
			return fmt.Errorf("relocation at %#x: addend %#x is not in a PT_LOAD", offset, addend)
		}
	}

	// Remove PT_INTERP, and clear the interpreter path, which tools can
	// read from the section headers.
	p := f.Progs[interp]
	if p.Off > uint64(len(data)) || p.Filesz > uint64(len(data))-p.Off {
		return errors.New("PT_INTERP is not in the file")
	}
	phoff, phentsize := phdrTable(data)
	binary.LittleEndian.PutUint32(data[phoff+uint64(interp)*phentsize:], uint32(elf.PT_NULL))
	clear(data[p.Off : p.Off+p.Filesz])
	return nil
}

// inLoad returns true if addr is in a PT_LOAD, or at its end.
func inLoad(f *elf.File, addr uint64) bool {
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && addr >= p.Vaddr && addr-p.Vaddr <= p.Memsz {
			return true
		}
	}
	return false
}

// checkRELRO checks that the entry point can make the pages of relro
// read-only, and that this has no effect on other data. The entry point
// rounds the start and the end of relro up to the page size, thus no PT_LOAD
// can have data between the end of relro and the end of its page.
func checkRELRO(f *elf.File, relro *elf.Prog, maxPageSize uint64) error {
	if relro.Vaddr%maxPageSize != 0 {
		return fmt.Errorf("PT_GNU_RELRO start %#x is not aligned to %#x", relro.Vaddr, maxPageSize)
	}
	if !inWritableLoad(f, relro.Vaddr, relro.Memsz) {
		return fmt.Errorf("PT_GNU_RELRO [%#x, %#x) is not in a writable PT_LOAD", relro.Vaddr, relro.Vaddr+relro.Memsz)
	}
	end := relro.Vaddr + relro.Memsz
	pageEnd := (end + maxPageSize - 1) &^ (maxPageSize - 1)
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Vaddr < pageEnd && end < p.Vaddr+p.Memsz {
			return fmt.Errorf("PT_LOAD [%#x, %#x) has data after the end of PT_GNU_RELRO %#x in the same page", p.Vaddr, p.Vaddr+p.Memsz, end)
		}
	}
	return nil
}

// checkEntry checks that the entry point is entrySymbol. It compares the code
// at the entry point with entryCode, because the binary can be without a
// symbol table. If the binary has a symbol table, it also compares the entry
// point with the address of entrySymbol.
func checkEntry(f *elf.File, entryCode []byte) error {
	code, err := readVirtual(f, f.Entry, uint64(len(entryCode)))
	if err != nil {
		return fmt.Errorf("cannot read entry point: %w", err)
	}
	if !bytes.Equal(code, entryCode) {
		return fmt.Errorf("code at entry point %#x is not %s; is the binary linked with -E %s?", f.Entry, entrySymbol, entrySymbol)
	}
	syms, err := f.Symbols()
	if errors.Is(err, elf.ErrNoSymbols) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot read symbols: %w", err)
	}
	for _, s := range syms {
		if s.Name == entrySymbol {
			if s.Value != f.Entry {
				return fmt.Errorf("got entry point %#x, want %s at %#x; is the binary linked with -E %s?", f.Entry, entrySymbol, s.Value, entrySymbol)
			}
			return nil
		}
	}
	return fmt.Errorf("no symbol %s; does the binary import //pkg/staticpie?", entrySymbol)
}

// readVirtual returns size bytes of file data at virtual address addr.
func readVirtual(f *elf.File, addr, size uint64) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || addr < p.Vaddr || addr-p.Vaddr > p.Filesz || size > p.Filesz-(addr-p.Vaddr) {
			continue
		}
		b := make([]byte, size)
		if _, err := p.ReadAt(b, int64(addr-p.Vaddr)); err != nil {
			return nil, err
		}
		return b, nil
	}
	return nil, fmt.Errorf("range [%#x, %#x) is not in the file data of a PT_LOAD", addr, addr+size)
}

// inWritableLoad returns true if the range [addr, addr+size) is in a writable
// PT_LOAD.
func inWritableLoad(f *elf.File, addr, size uint64) bool {
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_W != 0 && addr >= p.Vaddr && addr-p.Vaddr <= p.Memsz && size <= p.Memsz-(addr-p.Vaddr) {
			return true
		}
	}
	return false
}

// phdrTable returns the file offset and the entry size of the program header
// table of a 64-bit little-endian ELF file.
func phdrTable(data []byte) (uint64, uint64) {
	return binary.LittleEndian.Uint64(data[ehdrPhoff:]), uint64(binary.LittleEndian.Uint16(data[ehdrPhentsize:]))
}
