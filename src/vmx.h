#pragma once

#include <asm/page.h>
#include <linux/types.h>

#include "ia32.h"

/* Maximum size for VMCS related structures is 4096 bytes (1 standard page). */
#define VMXON_REGION_REQUIRED_PAGES 1
#define VMXON_REGION_REQUIRED_BYTES PAGE_SIZE* VMXON_REGION_REQUIRED_PAGES

struct cpu_ctx;

VMXON* hv_vmx_vmxon_create(struct cpu_ctx*);
void hv_vmx_vmxon_destroy(VMXON*);
void hv_vmx_set_fixed_bits(struct cpu_ctx*);
void hv_vmx_reset_fixed_bits(struct cpu_ctx*);
