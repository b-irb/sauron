#pragma once
#include <linux/refcount.h>
#include <linux/types.h>

#include "msr.h"

struct vmx_vmcs_region;
struct vmx_vmxon_region;

struct vmm_cpu_ctx {
    int processor_id;
    struct vmcs_vmcs_region* vmcs_region;
    struct vmx_vmxon_region* vmxon_region;
    /* Physical address of VMCS region. */
    unsigned long vmcs_region_ptr;
    /* Physical address of VMXON region. */
    unsigned long vmxon_region_ptr;
};

struct vmm_global_ctx {
    size_t n_online_cpus;
    size_t n_init_cpus;
    struct vmm_cpu_ctx* each_cpu_ctx;

    union ia32_vmx_basic_msr vmx_capabilities;
};

ssize_t vmm_init_processors(void);
ssize_t vmm_exit_root_all_processors(void);
