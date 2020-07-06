#pragma once
#include <linux/types.h>

#include "ia32.h"

struct vmx_vmcs_region;
struct vmx_vmxon_region;

struct vmm_cpu_ctx {
    int processor_id;
    VMCS* vmcs_region;
    VMXON* vmxon_region;
    /* Physical address of VMCS region. */
    unsigned long vmcs_region_ptr;
    /* Physical address of VMXON region. */
    unsigned long vmxon_region_ptr;

    /* Preserve state of CR0 and CR4 prior to fixing of VMX bits to allow for
     * resetting. */
    CR0 unfixed_control_register0;
    CR4 unfixed_control_register4;
};

struct vmm_global_ctx {
    size_t n_online_cpus;
    size_t n_init_cpus;
    struct vmm_cpu_ctx* each_cpu_ctx;

    IA32_VMX_BASIC_REGISTER vmx_capabilities;
};

ssize_t vmm_init_processors(void);
ssize_t vmm_exit_root_all_processors(void);
