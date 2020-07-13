#pragma once

#include <linux/types.h>

#include "ia32.h"

struct cpu_ctx;

struct vmm_ctx {
    unsigned n_online_cpus;
    unsigned n_init_cpus;
    struct cpu_ctx** each_cpu_ctx;
    IA32_VMX_BASIC_REGISTER vmx_capabilities;
};

struct vmm_ctx* hv_vmm_start_hypervisor(void);
void hv_vmm_stop_hypervisor(struct vmm_ctx*);

void hv_vmm_ctx_destroy(struct vmm_ctx*);
