#pragma once

#include <asm/page.h>
#include <linux/types.h>

#include "ia32.h"

#define VMCS_REGION_REQUIRED_PAGES 2
#define VMCS_REGION_REQUIRED_BYTES PAGE_SIZE* VMCS_REGION_REQUIRED_PAGES

struct vmm_ctx;
struct cpu_ctx;

VMCS* hv_vmcs_vmcs_alloc(struct cpu_ctx*);
void hv_vmcs_vmcs_destroy(VMCS*);
ssize_t hv_vmcs_vmcs_init(struct cpu_ctx*);
