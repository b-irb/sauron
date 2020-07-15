#pragma once

#include <asm/page.h>
#include <linux/types.h>

#include "ia32.h"

/* Maximum size for VMCS related structures is 4096 bytes (1 standard page). */
#define VMXON_REGION_REQUIRED_PAGES 2
#define VMXON_REGION_REQUIRED_BYTES PAGE_SIZE* VMXON_REGION_REQUIRED_PAGES

struct cpu_ctx;

void hv_vmx_launch_cpu(struct cpu_ctx*);
ssize_t hv_vmx_enter_root(struct cpu_ctx*);
ssize_t hv_vmx_exit_root(struct cpu_ctx*);
VMXON* hv_vmx_vmxon_create(struct cpu_ctx*);
void hv_vmx_vmxon_destroy(VMXON*);
