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

// Binary testbinary is a static PIE that prints facts about its own address
// space as JSON.
package main

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
)

// Report is the output of testbinary.
type Report struct {
	// Func is the address of a function.
	Func uintptr
	// Global is the address of a global variable.
	Global uintptr

	// RelocatedOK is true if data that needs relocations has the correct
	// values.
	RelocatedOK bool

	// FuncWritable is true if the memory of Func is writable.
	FuncWritable bool
	// GlobalWritable is true if the memory of Global is writable.
	GlobalWritable bool
	// RELROSize is the size of the RELRO range, rounded up to pages.
	RELROSize uint64
	// RELROWritable is true if any page of the RELRO range is writable.
	RELROWritable bool
}

type greeter interface {
	greet() string
}

type english struct{}

func (english) greet() string { return "hello" }

var (
	global   int
	globalP          = &global
	globalI  greeter = english{}
	globalFn         = func() int { return 42 }
)

type mapping struct {
	start, end uint64
	writable   bool
}

func readMaps() ([]mapping, error) {
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var ms []mapping
	s := bufio.NewScanner(f)
	for s.Scan() {
		var m mapping
		var perms string
		if _, err := fmt.Sscanf(s.Text(), "%x-%x %s", &m.start, &m.end, &perms); err != nil {
			return nil, err
		}
		m.writable = strings.Contains(perms, "w")
		ms = append(ms, m)
	}
	return ms, s.Err()
}

// writable returns true if any byte in [start, end) is writable.
func writable(ms []mapping, start, end uint64) bool {
	for _, m := range ms {
		if m.writable && m.start < end && start < m.end {
			return true
		}
	}
	return false
}

// loadBias returns the load bias of the binary.
func loadBias(f *elf.File) (uint64, error) {
	auxv, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return 0, err
	}
	const atPHDR = 3
	for i := 0; i+16 <= len(auxv); i += 16 {
		if binary.LittleEndian.Uint64(auxv[i:]) != atPHDR {
			continue
		}
		phdr := binary.LittleEndian.Uint64(auxv[i+8:])
		for _, p := range f.Progs {
			if p.Type == elf.PT_PHDR {
				return phdr - p.Vaddr, nil
			}
		}
		return 0, fmt.Errorf("no PT_PHDR")
	}
	return 0, fmt.Errorf("no AT_PHDR")
}

func run() (*Report, error) {
	r := &Report{
		Func:   reflect.ValueOf(run).Pointer(),
		Global: reflect.ValueOf(&global).Pointer(),
	}
	r.RelocatedOK = globalP == &global && globalI.greet() == "hello" && globalFn() == 42

	ms, err := readMaps()
	if err != nil {
		return nil, err
	}
	r.FuncWritable = writable(ms, uint64(r.Func), uint64(r.Func)+1)
	r.GlobalWritable = writable(ms, uint64(r.Global), uint64(r.Global)+1)

	f, err := elf.Open("/proc/self/exe")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	bias, err := loadBias(f)
	if err != nil {
		return nil, err
	}
	pageSize := uint64(os.Getpagesize())
	for _, p := range f.Progs {
		if p.Type != elf.PT_GNU_RELRO {
			continue
		}
		start := (bias + p.Vaddr + pageSize - 1) &^ (pageSize - 1)
		end := (bias + p.Vaddr + p.Memsz + pageSize - 1) &^ (pageSize - 1)
		if start < end {
			r.RELROSize = end - start
			r.RELROWritable = writable(ms, start, end)
		}
	}
	return r, nil
}

func main() {
	r, err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "testbinary: %v\n", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		fmt.Fprintf(os.Stderr, "testbinary: %v\n", err)
		os.Exit(1)
	}
}
