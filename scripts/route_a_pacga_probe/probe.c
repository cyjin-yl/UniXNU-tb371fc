/* Independent freestanding fixture. Keys/vectors below are public test data.
 * The PACGA register helper and SVC handler are extracted from the production
 * patch into handler.inc by the runner; the production random initializer is
 * deliberately not replaced or exercised by this fixture. */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "pacga_qarma5.h"

#ifndef PROBE_NATIVE
#error Select native-PACGA oracle or ordinary-arm64 SVC fixture
#endif

typedef struct {
    uint64_t x[29], fp, lr, sp, pc;
    uint32_t cpsr, reserved;
    uint64_t far, esr;
} arm_saved_state64_t;
typedef struct { arm_saved_state64_t state; } arm_saved_state_t;
_Static_assert(sizeof(arm_saved_state64_t) == 288, "saved state size");
_Static_assert(offsetof(arm_saved_state64_t, sp) == 248, "saved SP offset");
_Static_assert(offsetof(arm_saved_state64_t, cpsr) == 264, "saved CPSR offset");
static arm_saved_state64_t *saved_state64(arm_saved_state_t *state) { return &state->state; }

static struct route_a_pacga_key route_a_pacga_boot_key;
static uint32_t route_a_pacga_ready;
uint64_t initial_simd[32][2] __attribute__((aligned(16)));
uint64_t observed_simd[32][2] __attribute__((aligned(16)));
uint64_t initial_fpcr, initial_fpsr, observed_fpcr, observed_fpsr;
static arm_saved_state_t observed, expected;
static volatile unsigned phase, fallback;
static unsigned case_index;
static uint32_t selected_word;
extern uint32_t probe_user_slot[];
extern void probe_return(void);
extern void run_user_case(const arm_saved_state_t *);

void *memcpy(void *destination, const void *source, size_t length) {
    unsigned char *d = destination;
    const unsigned char *s = source;
    for (size_t i = 0; i < length; ++i) d[i] = s[i];
    return destination;
}
void *memset(void *destination, int value, size_t length) {
    unsigned char *d = destination;
    for (size_t i = 0; i < length; ++i) d[i] = (unsigned char)value;
    return destination;
}
static int different(const void *first, const void *second, size_t length) {
    const unsigned char *a = first, *b = second;
    for (size_t i = 0; i < length; ++i) if (a[i] != b[i]) return 1;
    return 0;
}
static void putchar_serial(char c) {
    volatile uint32_t *uart = (volatile uint32_t *)(uintptr_t)0x09000000;
    while (uart[0x18 / 4] & 0x20) {}
    uart[0] = (unsigned char)c;
}
static void puts_serial(const char *text) {
    while (*text) putchar_serial(*text++);
}
static void hex(uint64_t value) {
    const char *digits = "0123456789abcdef";
    for (unsigned i = 16; i != 0; --i) putchar_serial(digits[(value >> ((i - 1) * 4)) & 15]);
}
_Noreturn void probe_exit(uint64_t status) {
    uint64_t request[2] = {0x20026, status};
    register uint64_t operation __asm__("x0") = 0x20;
    register uint64_t argument __asm__("x1") = (uint64_t)(uintptr_t)request;
    __asm__ volatile("hlt #0xf000" : "+r"(operation) : "r"(argument) : "memory");
    for (;;) __asm__ volatile("wfe");
}
static _Noreturn void fail(uint64_t reason) {
    puts_serial("PACGA-FAIL reason="); hex(reason);
    puts_serial(" case="); hex(case_index);
    puts_serial("\n");
    probe_exit(reason);
}
_Noreturn void probe_fault(uint64_t syndrome, uint64_t pc, uint64_t address) {
    puts_serial("PACGA-FAULT esr="); hex(syndrome);
    puts_serial(" pc="); hex(pc);
    puts_serial(" far="); hex(address); puts_serial("\n");
    probe_exit(0xee);
}
static _Noreturn void panic(const char *message, ...) {
    puts_serial("PACGA-PANIC "); puts_serial(message); puts_serial("\n");
    probe_exit(0xef);
}

#include "handler.inc"

void probe_sync(arm_saved_state_t *state) {
    arm_saved_state64_t *s = saved_state64(state);
    if ((s->esr >> 26) != 0x15 || (s->cpsr & 15) != 0) fail(0x101);
    uint64_t pc = (uint64_t)(uintptr_t)probe_user_slot;
    unsigned immediate = (unsigned)s->esr & 0xffff;
    if (immediate == 0x7ffe) {
        if (s->pc != pc + 8 || phase != (PROBE_NATIVE ? 0U : 1U)) fail(0x102);
        observed = *state;
        phase = 2;
        s->pc = (uint64_t)(uintptr_t)probe_return;
        s->cpsr = 0x3c5;
        return;
    }
    if (PROBE_NATIVE || phase != 0 || s->pc != pc + 4 ||
        immediate != ((selected_word >> 5) & 0xffff)) fail(0x103);
    arm_saved_state_t before = *state;
    bool accepted = route_a_pacga_svc(state, s->esr);
    if (fallback) {
        if (accepted || different(&before, state, sizeof(before))) fail(0x104);
        /* Fixture stand-in for the unchanged ordinary dispatcher, reached
         * only after the production new handler returns false. */
        fallback = 2;
    } else if (!accepted) fail(0x105);
    if (s->pc != before.state.pc || s->sp != before.state.sp ||
        s->cpsr != before.state.cpsr) fail(0x106);
    phase = 1;
}

static uint64_t next_value(uint64_t *state) {
    /* Public deterministic vector generator, never production key material. */
    uint64_t value = *state;
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    return *state = value;
}
static void select_word(uint32_t word) {
    *(volatile uint32_t *)probe_user_slot = word;
    __asm__ volatile("dc cvau, %0\n\tdsb ish\n\tic ivau, %0\n\tdsb ish\n\tisb"
                     :: "r"(probe_user_slot) : "memory");
    selected_word = word;
}
static void prepare_vectors(arm_saved_state_t *input, unsigned index) {
    uint64_t generator = UINT64_C(0x683daba5417c8e1f) ^ ((uint64_t)index << 32) ^ index;
    memset(input, 0, sizeof(*input));
    for (unsigned r = 0; r < 29; ++r) input->state.x[r] = next_value(&generator);
    input->state.fp = next_value(&generator);
    input->state.lr = next_value(&generator);
    input->state.sp = UINT64_C(0xfedcba9876543210);
    input->state.pc = (uint64_t)(uintptr_t)probe_user_slot;
    input->state.cpsr = ((index & 15U) << 28) | 0x3c0;
    for (unsigned r = 0; r < 32; ++r) {
        initial_simd[r][0] = next_value(&generator);
        initial_simd[r][1] = next_value(&generator);
    }
    initial_fpcr = 0x00400000;
    initial_fpsr = 0x0800009f;
    route_a_pacga_boot_key.lo = next_value(&generator);
    route_a_pacga_boot_key.hi = next_value(&generator);
}
static void check_result(const arm_saved_state_t *input) {
    if (phase != 2) fail(0x201);
    if (different(observed.state.x, expected.state.x, sizeof(observed.state.x)) ||
        observed.state.fp != expected.state.fp || observed.state.lr != expected.state.lr ||
        observed.state.sp != input->state.sp ||
        observed.state.pc != input->state.pc + 8 ||
        observed.state.cpsr != input->state.cpsr) fail(0x202);
    if (different(initial_simd, observed_simd, sizeof(initial_simd)) ||
        initial_fpcr != observed_fpcr || initial_fpsr != observed_fpsr) fail(0x203);
}
void probe_main(void) {
    uint64_t isar1;
    __asm__ volatile("mrs %0, id_aa64isar1_el1" : "=r"(isar1));
    if (PROBE_NATIVE) {
        /* GPA=1 means the architected QARMA5 generic algorithm, not impdef. */
        if (((isar1 >> 24) & 15) != 1 || ((isar1 >> 28) & 15) != 0) fail(0x301);
    } else if (isar1 & UINT64_C(0xff000ff0)) fail(0x302);
    route_a_pacga_ready = 1; /* Public fixture key, not production startup. */
    uint64_t folded = 0;
    for (case_index = 0; case_index < 1024; ++case_index) {
        arm_saved_state_t input;
        prepare_vectors(&input, case_index);
        unsigned d = case_index & 31;
        unsigned n = (case_index >> 5) & 31;
        unsigned m = (case_index * 13 + (case_index >> 5) * 7) & 31;
        if (case_index >= 1 && case_index <= 4) {
            const unsigned aliases[4] = {0, 29, 30, 31};
            d = n = m = aliases[case_index - 1];
        }
        if (case_index == 0) {
            d = 0; n = 1; m = 2;
            route_a_pacga_boot_key.lo = UINT64_C(0xec2802d4e0a488e9);
            route_a_pacga_boot_key.hi = UINT64_C(0x84be85ce9804e94b);
            input.state.x[1] = UINT64_C(0xfb623599da6e8127);
            input.state.x[2] = UINT64_C(0x477d469dec0b8762);
        }
        uint64_t result = route_a_pacga_signature(
            route_a_pacga_register(&input.state, n, false),
            route_a_pacga_register(&input.state, m, true), &route_a_pacga_boot_key);
        if (case_index == 0 && result != UINT64_C(0xc003b93900000000)) fail(0x303);
        expected = input;
        if (d < 29) expected.state.x[d] = result;
        else if (d == 29) expected.state.fp = result;
        else if (d == 30) expected.state.lr = result;
        if (PROBE_NATIVE) {
            __asm__ volatile("msr S3_0_C2_C3_0, %0\n\tmsr S3_0_C2_C3_1, %1\n\tisb"
                             :: "r"(route_a_pacga_boot_key.lo), "r"(route_a_pacga_boot_key.hi)
                             : "memory");
            select_word(0x9ac03000U | d | (n << 5) | (m << 16));
        } else {
            select_word(0xd4000001U | ((0x8000U | d | (n << 5) | (m << 10)) << 5));
        }
        phase = 0;
        run_user_case(&input);
        check_result(&input);
        for (unsigned r = 0; r < 29; ++r) folded ^= observed.state.x[r];
        folded ^= observed.state.fp ^ observed.state.lr ^ observed.state.sp ^ observed.state.cpsr;
        folded = (folded << 3) | (folded >> 61);
    }
    if (!PROBE_NATIVE) {
        arm_saved_state_t input;
        prepare_vectors(&input, case_index);
        expected = input;
        phase = 0; fallback = 1;
        select_word(0xd4001001); /* Ordinary SVC #0x80. */
        run_user_case(&input);
        check_result(&input);
        if (fallback != 2) fail(0x304);
    }
    puts_serial("PACGA-PROBE {\"schema\":\"route-a-pacga-el0-probe-v1\","
                "\"cases\":1024,\"paper_vector\":true,\"gpr\":true,"
                "\"pc_lr_sp\":true,\"nzcv\":true,\"simd\":true,\"fpcr_fpsr\":true,"
                "\"native\":");
    puts_serial(PROBE_NATIVE ? "true" : "false");
    puts_serial(",\"ordinary_fallback\":");
    puts_serial(PROBE_NATIVE ? "false" : "true");
    puts_serial(",\"result_fold\":\""); hex(folded); puts_serial("\"}\n");
    probe_exit(0);
}
