// SPDX-License-Identifier: BSD-2-Clause-Patent
// Original assembly implementing AArch64 instruction-cache synchronization.
// Algorithm reference (not copied C source): LLVM compiler-rt clear_cache.c:
// https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/compiler-rt/lib/builtins/clear_cache.c
// X0 = start, X1 = exclusive end. Only caller-saved X2-X5/NZCV are modified.
// CTR_EL0 gives minimum cache line sizes and the IDC/DIC coherency guarantees.
// The loader maps this helper; Python flushes generated code before RW -> RX.
// No libc dependency, syscall, PAC instruction or writable executable segment.

.arch armv8-a
.text
.balign 4
.global __clear_cache
.type __clear_cache, %function
__clear_cache:
    cmp x0, x1
    b.hs .Lfinish
    mrs x2, ctr_el0
    tbnz x2, #28, .Ldata_done
    ubfx x3, x2, #16, #4
    mov x5, #4
    lsl x3, x5, x3
    sub x4, x3, #1
    bic x4, x0, x4
.Ldata_loop:
    dc cvau, x4
    add x4, x4, x3
    cmp x4, x1
    b.lo .Ldata_loop
.Ldata_done:
    dsb ish
    tbnz x2, #29, .Lfinish
    and x3, x2, #15
    mov x5, #4
    lsl x3, x5, x3
    sub x4, x3, #1
    bic x4, x0, x4
.Linstruction_loop:
    ic ivau, x4
    add x4, x4, x3
    cmp x4, x1
    b.lo .Linstruction_loop
    dsb ish
.Lfinish:
    isb
    ret
.size __clear_cache, .-__clear_cache
.section .note.GNU-stack,"",%progbits
