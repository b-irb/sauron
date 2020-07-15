#pragma once

#include <linux/types.h>

#include "arch.h"
#include "ia32.h"

struct vmm_ctx;

struct cpu_ctx {
    struct vmm_ctx* vmm;
    unsigned processor_id;
    bool failed;

    struct hv_arch_cpu_state state;
    u64 resume_sp;
    u64 resume_ip;
    VMXON* vmxon_region;
    phys_addr_t vmxon_region_ptr;
    VMCS* vmcs_region;
    phys_addr_t vmcs_region_ptr;

    CR0 unfixed_cr0;
    CR4 unfixed_cr4;
};

ssize_t hv_cpu_ctx_init(struct cpu_ctx*, struct vmm_ctx*);
void hv_cpu_ctx_destroy(struct cpu_ctx* ctx);
void hv_cpu_init(void*, u64, u64);
