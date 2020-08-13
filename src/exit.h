#pragma once

#define VMEXIT_HANDLER_STACK_SIZE 4096
#define HV_CPUID_DETACH_LEAF 0x42495242
#define HV_CPUID_DETACH_SUBLEAF 0x42495242

#include <linux/types.h>

struct cpu_ctx;
struct hv_exit_state;

u8 hv_exit_vmexit_handler(struct cpu_ctx*, struct hv_exit_state*);
u8 hv_exit_vmexit_failure(struct hv_exit_state*);
