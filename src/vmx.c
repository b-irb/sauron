#include "vmx.h"

#include <asm-generic/errno.h>
#include <asm/desc.h>
#include <asm/desc_defs.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include "arch.h"
#include "ia32.h"
#include "utils.h"
#include "vmm.h"

void vmx_set_fixed_bits(struct vmm_cpu_ctx* cpu_ctx) {
    CR0 cr0 = {.Flags = read_cr0()};
    CR4 cr4 = {.Flags = __read_cr4()};

    cpu_ctx->unfixed_control_register0 = cr0;
    cpu_ctx->unfixed_control_register4 = cr4;

    /* IA32_VMX_CR0_FIXED0 and IA32_VMX_CR0_FIXED1 indicate how bits in CR0 may
     * be set in VMX operation. If bit X is 1 in IA32_VMX_CR0_FIXED0, then that
     * bit of CR0 is fixed to 1 in VMX operation. If bit X is 0 in
     * IA32_VMX_CR0_FIXED1, then that bit of CR0 is fixed to 0 in VMX operation.
     * It is always the case that, if bit X is 1 in IA32_VMX_CR0_FIXED0, then
     * that bit is also 1 in IA32_VMX_CR0_FIXED1; if bit X is 0 in
     * IA32_VMX_CR0_FIXED1, then that bit is also 0 in IA32_VMX_CR0_FIXED0. */
    cr0.Flags |= __rdmsr(IA32_VMX_CR0_FIXED0);
    cr0.Flags &= __rdmsr(IA32_VMX_CR0_FIXED1);

    /* The IA32_VMX_CR4_FIXED0 and IA32_VMX_CR4_FIXED1 indicate how bits in CR4
     * may be set in VMX operation. If bit X is 1 in IA32_VMX_CR4_FIXED0, then
     * that bit of CR4 is fixed to 1 in VMX operation. If bit X is 0 in
     * IA32_VMX_CR4_FIXED1, then that bit of CR4 is fixed to 0 in VMX operation.
     * It is always the case that, if bit X is 1 in IA32_VMX_CR4_FIXED0, then
     * that bit is also 1 in IA32_VMX_CR4_FIXED1; if bit X is 0 in
     * IA32_VMX_CR4_FIXED1, then that bit is also 0 in IA32_VMX_CR4_FIXED0. */
    cr4.Flags |= __rdmsr(IA32_VMX_CR4_FIXED0);
    cr4.Flags &= __rdmsr(IA32_VMX_CR4_FIXED1);

    write_cr0(cr0.Flags);
    __write_cr4(cr4.Flags);
}

void vmx_reset_fixed_bits(struct vmm_cpu_ctx* cpu_ctx) {
    write_cr0(cpu_ctx->unfixed_control_register0.Flags);
    __write_cr4(cpu_ctx->unfixed_control_register4.Flags);
}

static ssize_t vmx_vmxon_region_init(struct vmx_vmxon_region* vmxon_region,
                                     struct vmm_global_ctx* ctx) {
    /* Write VMCS revision identifier to bits 30:0 to first 4 bytes, bit 31
     * should be cleared. */
    vmxon_region->vmcs_revision_number =
        (u32)ctx->vmx_capabilities.VmcsRevisionId;
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
