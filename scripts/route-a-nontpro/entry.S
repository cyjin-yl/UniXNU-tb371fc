/* Isolated dyld fragment fixture, not an XNU boot shim.
 * Original dyld bytes are loaded separately and never patched.
 * EL1 implements ONLY the declared syscall-38/namespace-0 ENOTSUP model.
 */
.section .text
.global _start
_start:
    mrs x0, CurrentEL
    cmp x0, #4
    b.ne unexpected
    ldr x0, =0x4b020000
    mov sp, x0
    ldr x0, =vectors
    msr vbar_el1, x0
    mov x0, #(3 << 20)
    msr cpacr_el1, x0
    ldr x0, =0x4a000000
    msr ttbr0_el1, x0
    mov x0, #0xff
    msr mair_el1, x0
    ldr x0, =0x0000000200993519
    msr tcr_el1, x0
    dsb sy
    isb
    tlbi vmalle1
    dsb sy
    isb
    mrs x0, sctlr_el1
    bic x0, x0, #(1 << 25)
    bic x0, x0, #(1 << 24)
    orr x0, x0, #1
    msr sctlr_el1, x0
    isb
    ldr x0, =0x4b010000
    msr sp_el0, x0
    ldr x0, =user_main
    msr elr_el1, x0
    mov x0, #0
    msr spsr_el1, x0
    eret
.ltorg

.org 0x1000
vectors:
    b unexpected
.org 0x1080
    b unexpected
.org 0x1100
    b unexpected
.org 0x1180
    b unexpected
.org 0x1200
    b unexpected
.org 0x1280
    b unexpected
.org 0x1300
    b unexpected
.org 0x1380
    b unexpected
.org 0x1400
    b lower_sync
.org 0x1480
    b unexpected
.org 0x1500
    b unexpected
.org 0x1580
    b unexpected
.org 0x1600
    b unexpected
.org 0x1680
    b unexpected
.org 0x1700
    b unexpected
.org 0x1780
    b unexpected

.org 0x1900
lower_sync:
    stp x9, x10, [sp, #-16]!
    stp x11, x12, [sp, #-16]!
    ldr x9, =model_state
    ldr x10, [x9]
    cmp x10, #64
    b.hs unexpected
    add x10, x10, #1
    str x10, [x9]
    sub x10, x10, #1
    add x9, x9, #64
    add x9, x9, x10, lsl #8
    stp x0, x1, [x9]
    stp x2, x3, [x9, #16]
    stp x4, x5, [x9, #32]
    stp x6, x7, [x9, #48]
    str x16, [x9, #64]
    str x30, [x9, #72]
    mrs x10, esr_el1
    str x10, [x9, #80]
    mrs x10, elr_el1
    str x10, [x9, #88]
    mrs x10, sp_el0
    str x10, [x9, #96]
    mrs x10, spsr_el1
    str x10, [x9, #104]
    mrs x10, esr_el1
    lsr x10, x10, #26
    cmp x10, #0x15
    b.ne unexpected
    mrs x10, esr_el1
    and x10, x10, #0xffff
    cmp x10, #0x80
    b.ne unexpected
    cmp x16, #38
    b.ne unexpected
    cbnz x0, unexpected
    cbnz x1, unexpected
    cbnz x2, unexpected
    tst x3, #7
    b.ne unexpected
    ldr x10, =0x4b000000
    cmp x3, x10
    b.lo unexpected
    ldr x10, =0x4b00fff8
    cmp x3, x10
    b.hi unexpected
    ldr x10, [x3]
    str x10, [x9, #112]
    ldr x9, =0x4b000000
    cmp x10, x9
    b.lo unexpected
    ldr x9, =0x4b010000
    cmp x10, x9
    b.hs unexpected
    ldrb w11, [x10]
    ldr x9, =model_state
    ldr x10, [x9]
    sub x10, x10, #1
    add x9, x9, #64
    add x9, x9, x10, lsl #8
    str x11, [x9, #120]
    cbnz w11, unexpected
    ldr x9, =model_state
    ldr x10, [x9, #8]
    add x10, x10, #1
    str x10, [x9, #8]
    ldr x10, [x9]
    sub x10, x10, #1
    add x9, x9, #64
    add x9, x9, x10, lsl #8
    mov x0, #45
    mov x1, #0
    stp x0, x1, [x9, #128]
    mrs x10, spsr_el1
    orr x10, x10, #(1 << 29)
    str x10, [x9, #144]
    msr spsr_el1, x10
    ldp x11, x12, [sp], #16
    ldp x9, x10, [sp], #16
    eret
.ltorg

.org 0x2000
user_main:
    ldr x8, =0x49000000
    ldp x27, x28, [x8]
    ldr x26, [x8, #16]
1:
    ldr x16, [x28]
    ldp x0, x1, [x28, #8]
    ldp x2, x3, [x28, #24]
    mov x4, #0
    mov x5, #0
    mov x6, #0
    mov x7, #0
    blr x16
    stp x0, x1, [x26], #16
    add x28, x28, #40
    subs x27, x27, #1
    b.ne 1b
    b completed
.ltorg

.org 0x2100
completed:
    brk #0x501
    b completed

.org 0x2200
unexpected:
    ldr x9, =model_state
    mrs x10, esr_el1
    str x10, [x9, #16]
    mrs x10, elr_el1
    str x10, [x9, #24]
    mrs x10, far_el1
    str x10, [x9, #32]
    mrs x10, CurrentEL
    str x10, [x9, #40]
unexpected_saved:
    brk #0x502
    b unexpected_saved
.ltorg

.org 0x2300
model_state:
    .zero 64 + 64 * 256
