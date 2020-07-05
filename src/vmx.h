#pragma once

#include <linux/types.h>

/* Maximum size for VMCS related structures is 4096 bytes. */
#define VMXON_REGION_REQUIRED_PAGES 2

struct vmx_vmxon_region {
    u32 vmcs_revision_number;
};

struct vmm_global_ctx;
struct vmm_cpu_ctx;

struct vmx_vmxon_region* vmx_vmxon_region_create(struct vmm_global_ctx*);
void vmx_vmxon_region_destroy(struct vmx_vmxon_region*);
void vmx_set_fixed_bits(struct vmm_cpu_ctx*);
void vmx_reset_fixed_bits(struct vmm_cpu_ctx*);
