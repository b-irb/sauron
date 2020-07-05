#include "vmx.h"

#include <asm-generic/errno.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include "utils.h"
#include "vmm.h"

static ssize_t vmx_vmxon_region_init(struct vmx_vmxon_region* vmxon_region,
                                     struct vmm_global_ctx* ctx) {
    /* Write VMCS revision identifier to bits 30:0 to first 4 bytes, bit 31
     * should be cleared. */
    vmxon_region->vmcs_revision_number =
        (u32)ctx->vmx_capabilities.fields.revision_identifier;
    return 0;
}

struct vmx_vmxon_region* vmx_vmxon_region_create(struct vmm_global_ctx* ctx) {
    struct vmx_vmxon_region* vmxon_region;

    /* VMXON region must be allocated in physically contiguous, write-back,
     * memory. The standard kernel memory allocation functions will return
     * pointers to write-back memory, so no explicit PAT change is necessary.
     *
     * Additionally, the VMXON pointer must be 4K aligned and must not set any
     * bits beyond the processors physical address width. */
    if (!(vmxon_region =
              alloc_pages_exact(VMXON_REGION_REQUIRED_PAGES, GFP_KERNEL))) {
        utils_log(err, "processor [%zu]: unable to allocate VMXON region\n",
                  ctx->n_init_cpus);
        return NULL;
    }

    /* Clear allocation in case of dirtied pages. */
    memset(vmxon_region, 0x0, VMXON_REGION_REQUIRED_PAGES);

    if (vmx_vmxon_region_init(vmxon_region, ctx) < 0) {
        utils_log(err, "processor [%zu] unable to initialise VMXON region\n",
                  ctx->n_init_cpus);
        vmx_vmxon_region_destroy(vmxon_region);
        return NULL;
    }

    return vmxon_region;
}

void vmx_vmxon_region_destroy(struct vmx_vmxon_region* vmxon_region) {
    free_pages_exact(vmxon_region, VMXON_REGION_REQUIRED_PAGES);
}
