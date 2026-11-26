/* Standalone EL0/EL1 vectors, with the exact patched XNU entry/return blocks.
 * These fixture offsets describe arm_saved_state64 without XNU's 8-byte header;
 * the real locore build uses its separately bound generated assym.s values. */
#define CONFIG_ROUTE_A_PACGA_SVC 1
#include "route_a_pacga_abi.h"
#define SS64_CPSR 264
#define SS64_X18 144
#define PSR64_MODE_MASK ROUTE_A_PACGA_MODE_MASK
/* ac9718fb:osfmk/arm64/machine_machdep.h */
#define MACHDEP_TPIDR_FLAG_PRESERVE_X18_SHIFT 48
.section .text.boot, "ax"
.global _start
.type _start, %function
_start:
    msr spsel, #1
    ldr x1, =_stack_top
    mov sp, x1
    msr daifset, #15
    mrs x0, CurrentEL
    cmp x0, #4
    b.eq .Lel1
    cmp x0, #8
    b.ne probe_unexpected
    msr sp_el1, x1
    mov x0, #(1 << 31)
    orr x0, x0, #(1 << 40)
    orr x0, x0, #(1 << 41)
    msr hcr_el2, x0
    msr cptr_el2, xzr
    adr x0, .Lel1
    msr elr_el2, x0
    mov x0, #0x3c5
    msr spsr_el2, x0
    eret
.Lel1:
    msr spsel, #1
    ldr x0, =_stack_top
    mov sp, x0
    mrs x0, sctlr_el1
    bic x0, x0, #1
    bic x0, x0, #4
    bic x0, x0, #0x1000
    msr sctlr_el1, x0
    isb
    mov x0, #(3 << 20)
    msr cpacr_el1, x0
    adr x0, probe_vectors
    msr vbar_el1, x0
    isb
    ldr x0, =_bss_start
    ldr x1, =_bss_end
.Lzero:
    cmp x0, x1
    b.hs .Lready
    str xzr, [x0], #8
    b .Lzero
.Lready:
    msr tpidr_el0, xzr
    bl probe_main
    mov x0, #0x99
    bl probe_exit
.size _start, . - _start

/* Each vector is 128 bytes; lower-EL AArch64 synchronous is slot eight. */
.balign 2048
probe_vectors:
.rept 8
    b probe_unexpected
    .space 124
.endr
    b probe_sync_vector
    .space 124
.rept 7
    b probe_unexpected
    .space 124
.endr

probe_unexpected:
    msr spsel, #1
    mrs x0, esr_el1
    mrs x1, elr_el1
    mrs x2, far_el1
    bl probe_fault
    b .

/* The 288-byte frame follows pinned arm_saved_state64 (ordinary arm64).
 * C uses only GPRs. SIMD is captured separately on each entry for comparison. */
probe_sync_vector:
    sub sp, sp, #288
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    mrs x0, sp_el0
    str x0, [sp, #248]
    mrs x0, elr_el1
    str x0, [sp, #256]
    mrs x0, spsr_el1
    str w0, [sp, #264]
    mrs x0, far_el1
    str x0, [sp, #272]
    mrs x0, esr_el1
    str x0, [sp, #280]
    mov x0, sp
#include "entry-reset.inc"

    adr x0, observed_simd
    stp q0, q1, [x0, #0]
    stp q2, q3, [x0, #32]
    stp q4, q5, [x0, #64]
    stp q6, q7, [x0, #96]
    stp q8, q9, [x0, #128]
    stp q10, q11, [x0, #160]
    stp q12, q13, [x0, #192]
    stp q14, q15, [x0, #224]
    stp q16, q17, [x0, #256]
    stp q18, q19, [x0, #288]
    stp q20, q21, [x0, #320]
    stp q22, q23, [x0, #352]
    stp q24, q25, [x0, #384]
    stp q26, q27, [x0, #416]
    stp q28, q29, [x0, #448]
    stp q30, q31, [x0, #480]
    mrs x1, fpcr
    adr x0, observed_fpcr
    str x1, [x0]
    mrs x1, fpsr
    adr x0, observed_fpsr
    str x1, [x0]

    mov x0, sp
    bl probe_sync
    ldr x9, [sp, #248]
    msr sp_el0, x9
    ldr x9, [sp, #256]
    msr elr_el1, x9
    ldr w9, [sp, #264]
    msr spsr_el1, x9
    bl probe_apply_return_gate
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldr x19, [sp, #152] /* x18 was restored or cleared by the production gate. */
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    add sp, sp, #288
    eret


/* Called with SP pointing at the captured fixture state and IRQs masked. */
.type probe_apply_return_gate, %function
probe_apply_return_gate:
#include "return-gate.inc"
Lexception_return_restore_registers:
    ret

/* C-callable wrappers execute those same instructions for lifecycle negatives.
 * The production block uses only x1/x2/x18, leaving x9-x11 available here. */
.global probe_return_gate_test
.type probe_return_gate_test, %function
probe_return_gate_test:
    mov x9, sp
    mov x10, lr
    mrs x11, tpidr_el0
    msr tpidr_el0, x1
    mov sp, x0
    bl probe_apply_return_gate
    mov x0, x18
    mov sp, x9
    mov lr, x10
    msr tpidr_el0, x11
    ret

.global probe_entry_reset_test
.type probe_entry_reset_test, %function
probe_entry_reset_test:
#include "entry-reset.inc"
    ret

/* Preserve the EL1 caller, then enter an instruction with all EL0 registers
 * loaded. The test completion SVC returns to probe_return at EL1h. */
.global run_user_case
.type run_user_case, %function
run_user_case:
    sub sp, sp, #240
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    stp x29, x30, [sp, #80]
    stp q8, q9, [sp, #96]
    stp q10, q11, [sp, #128]
    stp q12, q13, [sp, #160]
    stp q14, q15, [sp, #192]
    mrs x1, fpcr
    mrs x2, fpsr
    stp x1, x2, [sp, #224]
    mov x30, x0

    adr x1, initial_simd
    ldp q0, q1, [x1, #0]
    ldp q2, q3, [x1, #32]
    ldp q4, q5, [x1, #64]
    ldp q6, q7, [x1, #96]
    ldp q8, q9, [x1, #128]
    ldp q10, q11, [x1, #160]
    ldp q12, q13, [x1, #192]
    ldp q14, q15, [x1, #224]
    ldp q16, q17, [x1, #256]
    ldp q18, q19, [x1, #288]
    ldp q20, q21, [x1, #320]
    ldp q22, q23, [x1, #352]
    ldp q24, q25, [x1, #384]
    ldp q26, q27, [x1, #416]
    ldp q28, q29, [x1, #448]
    ldp q30, q31, [x1, #480]
    adr x1, initial_fpcr
    ldr x2, [x1]
    msr fpcr, x2
    adr x1, initial_fpsr
    ldr x2, [x1]
    msr fpsr, x2

    ldr x1, [x30, #248]
    msr sp_el0, x1
    ldr w1, [x30, #264]
    msr spsr_el1, x1
    adr x1, probe_user_slot
    msr elr_el1, x1
    ldp x0, x1, [x30, #0]
    ldp x2, x3, [x30, #16]
    ldp x4, x5, [x30, #32]
    ldp x6, x7, [x30, #48]
    ldp x8, x9, [x30, #64]
    ldp x10, x11, [x30, #80]
    ldp x12, x13, [x30, #96]
    ldp x14, x15, [x30, #112]
    ldp x16, x17, [x30, #128]
    ldp x18, x19, [x30, #144]
    ldp x20, x21, [x30, #160]
    ldp x22, x23, [x30, #176]
    ldp x24, x25, [x30, #192]
    ldp x26, x27, [x30, #208]
    ldp x28, x29, [x30, #224]
    ldr x30, [x30, #240]
    eret

.global probe_return
probe_return:
    ldp q8, q9, [sp, #96]
    ldp q10, q11, [sp, #128]
    ldp q12, q13, [sp, #160]
    ldp q14, q15, [sp, #192]
    ldp x1, x2, [sp, #224]
    msr fpcr, x1
    msr fpsr, x2
    ldp x19, x20, [sp, #0]
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #48]
    ldp x27, x28, [sp, #64]
    ldp x29, x30, [sp, #80]
    add sp, sp, #240
    ret
.size run_user_case, . - run_user_case

.section .text.user, "ax"
.balign 64
.global probe_user_slot
probe_user_slot:
    .word 0xd4000001
    svc #0x7ffe
    brk #0
