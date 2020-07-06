#pragma once

#include <asm/page.h>
#include <linux/types.h>

#include "ia32.h"

/* Maximum size for VMCS related structures is 4096 bytes (1 standard page). */
#define VMXON_REGION_REQUIRED_PAGES 1
#define VMXON_REGION_REQUIRED_BYTES PAGE_SIZE* VMXON_REGION_REQUIRED_PAGES

struct vmm_global_ctx;
struct vmm_cpu_ctx;

VMXON* vmx_vmxon_region_create(struct vmm_global_ctx*);
void vmx_vmxon_region_destroy(VMXON* vmxon_region);
void vmx_set_fixed_bits(struct vmm_cpu_ctx*);
void vmx_reset_fixed_bits(struct vmm_cpu_ctx*);
