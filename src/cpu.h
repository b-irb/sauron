#pragma once

#include <linux/types.h>

#include "arch.h"
#include "ia32.h"
#include "vmx.h"

struct vmm_ctx;

struct cpu_ctx {
    void* vmexit_handler;
    struct cpu_ctx_stack* vmexit_stack;

    struct vmm_ctx* vmm;
    unsigned processor_id;
    bool failed;

    CR0 unfixed_cr0;
    CR4 unfixed_cr4;

    struct hv_arch_cpu_state state;

    u64 resume_sp;
    u64 resume_ip;

    VMX_MSR_BITMAP* msr_bitmap;
    VMXON* vmxon_region;
    VMCS* vmcs_region;
    phys_addr_t msr_bitmap_ptr;
    phys_addr_t vmxon_region_ptr;
    phys_addr_t vmcs_region_ptr;
};

struct cpu_ctx_stack {
    /* This forms the vmexit handler stack, it must be at the start of the
     * struct. */
    u8 vmexit_handler_stack[VMX_VMEXIT_STACK_SIZE - sizeof(struct cpu_ctx*)];
    struct cpu_ctx* cpu;
};

ssize_t hv_cpu_ctx_init(struct cpu_ctx*, struct vmm_ctx*);
void hv_cpu_ctx_destroy(struct cpu_ctx* ctx);
void hv_cpu_init(void*, u64, u64);
