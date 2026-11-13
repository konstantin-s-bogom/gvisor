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

//go:build linux && arm64

#include "textflag.h"

#define AT_NULL 0
#define AT_PHDR 3
#define AT_PHNUM 5
#define AT_PAGESZ 6

#define PT_DYNAMIC 2
#define PT_PHDR 6
#define PT_GNU_RELRO 0x6474e552

#define PHDR_SIZE 56
#define PHDR_TYPE 0
#define PHDR_VADDR 16
#define PHDR_MEMSZ 40

#define DT_NULL 0
#define DT_RELA 7
#define DT_RELASZ 8

#define RELA_SIZE 24
#define RELA_OFFSET 0
#define RELA_INFO 8
#define RELA_ADDEND 16
#define R_AARCH64_RELATIVE 1027

#define SYS_write 64
#define SYS_mprotect 226
#define SYS_exit_group 94
#define PROT_READ 1

#define FAIL_MSG_LEN 39

// _rt0_gvisor_static_pie is the entry point of a static PIE. See package
// documentation. //tools/staticpie checks the first two instructions.
//
// The kernel starts the process with RSP pointing to argc. RSP must have the
// same value when control goes to _rt0_arm64_linux. The other registers can
// change.
//
// Register use:
//	R8:  AT_PHDR.
//	R9:  AT_PHNUM.
//	R10: AT_PAGESZ.
//	R11: load bias.
//	R12: address of the dynamic section.
//	R13: start of the RELRO range.
//	R14: end of the RELRO range.
//	R15: 1 if there is a PT_PHDR program header.
TEXT _rt0_gvisor_static_pie(SB),NOSPLIT|NOFRAME,$0
	// Skip argc, argv and envp to find the auxiliary vector.
	MOVD	0(RSP), R0
	MOVD	RSP, R1
	ADD	R0<<3, R1, R1
	ADD	$16, R1, R1
envp:
	MOVD	0(R1), R2
	ADD	$8, R1, R1
	CBNZ	R2, envp

	MOVD	$0, R8
	MOVD	$0, R9
	MOVD	$0, R10
auxv:
	MOVD	0(R1), R2
	MOVD	8(R1), R3
	ADD	$16, R1, R1
	CMP	$AT_NULL, R2
	BEQ	auxvdone
	CMP	$AT_PHDR, R2
	BNE	2(PC)
	MOVD	R3, R8
	CMP	$AT_PHNUM, R2
	BNE	2(PC)
	MOVD	R3, R9
	CMP	$AT_PAGESZ, R2
	BNE	2(PC)
	MOVD	R3, R10
	B	auxv
auxvdone:
	CBZ	R8, fail
	CBZ	R10, fail

	// Find the load bias, the dynamic section and the RELRO range.
	MOVD	$0, R12
	MOVD	$0, R13
	MOVD	$0, R14
	MOVD	$0, R15
	MOVD	R8, R1
	MOVD	R9, R2
	MOVD	$PT_GNU_RELRO, R4
phdr:
	CBZ	R2, phdrdone
	MOVWU	PHDR_TYPE(R1), R3
	CMP	$PT_PHDR, R3
	BNE	notphdr
	MOVD	PHDR_VADDR(R1), R5
	SUB	R5, R8, R11
	MOVD	$1, R15
notphdr:
	CMP	$PT_DYNAMIC, R3
	BNE	notdynamic
	MOVD	PHDR_VADDR(R1), R12
notdynamic:
	CMP	R4, R3
	BNE	notrelro
	MOVD	PHDR_VADDR(R1), R13
	MOVD	PHDR_MEMSZ(R1), R5
	ADD	R13, R5, R14
notrelro:
	ADD	$PHDR_SIZE, R1, R1
	SUB	$1, R2, R2
	B	phdr
phdrdone:
	CBZ	R15, fail
	CBZ	R12, fail
	ADD	R11, R12, R12

	// Find the relocation table in the dynamic section.
	MOVD	$0, R6
	MOVD	$0, R7
dynamic:
	MOVD	0(R12), R2
	MOVD	8(R12), R3
	ADD	$16, R12, R12
	CMP	$DT_NULL, R2
	BEQ	dynamicdone
	CMP	$DT_RELA, R2
	BNE	2(PC)
	MOVD	R3, R6
	CMP	$DT_RELASZ, R2
	BNE	2(PC)
	MOVD	R3, R7
	B	dynamic
dynamicdone:
	CBZ	R7, relocdone
	CBZ	R6, fail

	// Apply the relocations: *(bias + r_offset) = bias + r_addend.
	ADD	R11, R6, R6
	ADD	R6, R7, R7
	MOVD	$R_AARCH64_RELATIVE, R4
reloc:
	CMP	R7, R6
	BHS	relocdone
	MOVD	RELA_INFO(R6), R2
	CMP	R4, R2
	BNE	fail
	MOVD	RELA_OFFSET(R6), R2
	ADD	R11, R2, R2
	MOVD	RELA_ADDEND(R6), R3
	ADD	R11, R3, R3
	MOVD	R3, 0(R2)
	ADD	$RELA_SIZE, R6, R6
	B	reloc
relocdone:

	// Make the pages of the RELRO range read-only. Round the start and the
	// end of the range up to pages. //tools/staticpie makes sure that the
	// start is page-aligned, and that no PT_LOAD has data in the rest of the
	// last page.
	ADD	R11, R13, R13
	ADD	R11, R14, R14
	SUB	$1, R10, R2
	ADD	R2, R13, R13
	ADD	R2, R14, R14
	BIC	R2, R13, R13
	BIC	R2, R14, R14
	CMP	R14, R13
	BHS	relrodone
	MOVD	R13, R0
	SUB	R13, R14, R1
	MOVD	$PROT_READ, R2
	MOVD	$SYS_mprotect, R8
	SVC
	CBNZ	R0, fail
relrodone:
	B	_rt0_arm64_linux(SB)

fail:
	MOVD	$2, R0
	MOVD	$failmsg<>(SB), R1
	MOVD	$FAIL_MSG_LEN, R2
	MOVD	$SYS_write, R8
	SVC
	MOVD	$127, R0
	MOVD	$SYS_exit_group, R8
	SVC
	UNDEF

DATA failmsg<>+0(SB)/8, $"static P"
DATA failmsg<>+8(SB)/8, $"IE: cann"
DATA failmsg<>+16(SB)/8, $"ot reloc"
DATA failmsg<>+24(SB)/8, $"ate the "
DATA failmsg<>+32(SB)/8, $"binary\n\x00"
GLOBL failmsg<>(SB), RODATA, $40
