/*
 * Private contract between the Route A PACGA handler and XNU exception entry/exit.
 * This header is intentionally valid in both C and assembler-with-cpp.
 */
#ifndef ROUTE_A_PACGA_ABI_H
#define ROUTE_A_PACGA_ABI_H

#define ROUTE_A_PACGA_RETURN_TAG 0x50414347
#define ROUTE_A_PACGA_CPSR_BYTES 4
#define ROUTE_A_PACGA_RESERVED_BYTES 4
#define ROUTE_A_PACGA_MODE_MASK 0x1f
#define ROUTE_A_PACGA_SVC64_EC 0x15
#define ROUTE_A_PACGA_EC_SHIFT 26
#define ROUTE_A_PACGA_EC_MASK 0x3f

#if CONFIG_ROUTE_A_PACGA_SVC && __ARM_KERNEL_PROTECT__
#error Route A PACGA cannot preserve x18 with ARM_KERNEL_PROTECT
#endif

#endif /* ROUTE_A_PACGA_ABI_H */
