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

//go:build linux && amd64

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
#define R_X86_64_RELATIVE 8

#define SYS_write 1
#define SYS_mprotect 10
#define SYS_exit_group 231
#define PROT_READ 1

#define FAIL_MSG_LEN 39

// _rt0_gvisor_static_pie is the entry point of a static PIE. See package
// documentation. //tools/staticpie checks the first two instructions.
//
// The kernel starts the process with SP pointing to argc. SP must have the
// same value when control goes to _rt0_amd64_linux. The other registers can
// change. SYSCALL changes RCX and R11.
//
// Register use:
//	R8:  AT_PHDR.
//	R9:  AT_PHNUM.
//	R10: AT_PAGESZ.
//	R12: address of the dynamic section.
//	R13: start of the RELRO range.
//	R14: end of the RELRO range.
//	R15: load bias.
//	BP:  1 if there is a PT_PHDR program header.
TEXT _rt0_gvisor_static_pie(SB),NOSPLIT|NOFRAME,$0
	// Skip argc, argv and envp to find the auxiliary vector.
	MOVQ 0(SP), AX
	LEAQ 16(SP)(AX*8), BX
envp:
	MOVQ 0(BX), CX
	ADDQ $8, BX
	TESTQ CX, CX
	JNE envp

	XORQ R8, R8
	XORQ R9, R9
	XORQ R10, R10
auxv:
	MOVQ 0(BX), CX
	MOVQ 8(BX), DX
	ADDQ $16, BX
	CMPQ CX, $AT_NULL
	JEQ auxvdone
	CMPQ CX, $AT_PHDR
	JNE 2(PC)
	MOVQ DX, R8
	CMPQ CX, $AT_PHNUM
	JNE 2(PC)
	MOVQ DX, R9
	CMPQ CX, $AT_PAGESZ
	JNE 2(PC)
	MOVQ DX, R10
	JMP auxv
auxvdone:
	TESTQ R8, R8
	JEQ fail
	TESTQ R10, R10
	JEQ fail

	// Find the load bias, the dynamic section and the RELRO range.
	XORQ R12, R12
	XORQ R13, R13
	XORQ R14, R14
	XORQ BP, BP
	MOVQ R8, BX
	MOVQ R9, CX
phdr:
	TESTQ CX, CX
	JEQ phdrdone
	MOVL PHDR_TYPE(BX), AX
	CMPL AX, $PT_PHDR
	JNE notphdr
	MOVQ R8, R15
	SUBQ PHDR_VADDR(BX), R15
	MOVQ $1, BP
notphdr:
	CMPL AX, $PT_DYNAMIC
	JNE notdynamic
	MOVQ PHDR_VADDR(BX), R12
notdynamic:
	CMPL AX, $PT_GNU_RELRO
	JNE notrelro
	MOVQ PHDR_VADDR(BX), R13
	MOVQ R13, R14
	ADDQ PHDR_MEMSZ(BX), R14
notrelro:
	ADDQ $PHDR_SIZE, BX
	DECQ CX
	JMP phdr
phdrdone:
	TESTQ BP, BP
	JEQ fail
	TESTQ R12, R12
	JEQ fail
	ADDQ R15, R12

	// Round the start and the end of the RELRO range up to pages.
	// //tools/staticpie makes sure that the start is page-aligned, and
	// that no PT_LOAD has data in the rest of the last page.
	ADDQ R15, R13
	ADDQ R15, R14
	MOVQ R10, AX
	DECQ AX
	ADDQ AX, R13
	ADDQ AX, R14
	NOTQ AX
	ANDQ AX, R13
	ANDQ AX, R14

	// Find the relocation table in the dynamic section.
	XORQ SI, SI
	XORQ DI, DI
dynamic:
	MOVQ 0(R12), CX
	MOVQ 8(R12), DX
	ADDQ $16, R12
	CMPQ CX, $DT_NULL
	JEQ dynamicdone
	CMPQ CX, $DT_RELA
	JNE 2(PC)
	MOVQ DX, SI
	CMPQ CX, $DT_RELASZ
	JNE 2(PC)
	MOVQ DX, DI
	JMP dynamic
dynamicdone:
	TESTQ DI, DI
	JEQ relocdone
	TESTQ SI, SI
	JEQ fail

	// Apply the relocations: *(bias + r_offset) = bias + r_addend.
	ADDQ R15, SI
	ADDQ SI, DI
reloc:
	CMPQ SI, DI
	JAE relocdone
	CMPQ RELA_INFO(SI), $R_X86_64_RELATIVE
	JNE fail
	MOVQ RELA_OFFSET(SI), AX
	ADDQ R15, AX
	MOVQ RELA_ADDEND(SI), DX
	ADDQ R15, DX
	MOVQ DX, 0(AX)
	ADDQ $RELA_SIZE, SI
	JMP reloc
relocdone:

	// Make the pages of the RELRO range read-only.
	CMPQ R13, R14
	JAE relrodone
	MOVQ R13, DI
	MOVQ R14, SI
	SUBQ R13, SI
	MOVQ $PROT_READ, DX
	MOVQ $SYS_mprotect, AX
	SYSCALL
	TESTQ AX, AX
	JNE fail
relrodone:
	XORQ BP, BP
	JMP _rt0_amd64_linux(SB)

fail:
	MOVQ $2, DI
	LEAQ failmsg<>(SB), SI
	MOVQ $FAIL_MSG_LEN, DX
	MOVQ $SYS_write, AX
	SYSCALL
	MOVQ $127, DI
	MOVQ $SYS_exit_group, AX
	SYSCALL
	INT $3

DATA failmsg<>+0(SB)/8, $"static P"
DATA failmsg<>+8(SB)/8, $"IE: cann"
DATA failmsg<>+16(SB)/8, $"ot reloc"
DATA failmsg<>+24(SB)/8, $"ate the "
DATA failmsg<>+32(SB)/8, $"binary\n\x00"
GLOBL failmsg<>(SB), RODATA, $40
