#include "vmx.h"

#include <asm-generic/errno.h>
#include <asm/desc.h>
#include <asm/desc_defs.h>
#include <asm/msr.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include "arch.h"
#include "cpu.h"
#include "ia32.h"
#include "utils.h"
#include "vmm.h"

static u64 set_required_bits(u64 cr, u64 fixed0, u64 fixed1) {
    u64 fixed_mask, flexible_mask, fixed_bits, flexible_bits;

    flexible_mask = fixed0 ^ fixed1;
    fixed_mask = cr & ~flexible_mask;

    fixed_bits = (fixed0 | fixed1) & fixed_mask;
    flexible_bits = flexible_mask & cr;

    return fixed_bits | flexible_bits;
}

void hv_vmx_reset_fixed_bits(struct cpu_ctx* cpu) {
    native_write_cr0(cpu->unfixed_cr0.flags);
    native_write_cr4(cpu->unfixed_cr4.flags);
}

void hv_vmx_set_fixed_bits(struct cpu_ctx* cpu) {
    CR0 cr0 = {.flags = native_read_cr0()};
    CR4 cr4 = {.flags = native_read_cr4()};

    cpu->unfixed_cr0 = cr0;
    cpu->unfixed_cr4 = cr4;

    cr0.flags =
        set_required_bits(cr0.flags, native_read_msr(IA32_VMX_CR0_FIXED0),
                          native_read_msr(IA32_VMX_CR0_FIXED0));
    cr4.flags =
        set_required_bits(cr0.flags, native_read_msr(IA32_VMX_CR4_FIXED0),
                          native_read_msr(IA32_VMX_CR4_FIXED1));

    native_write_cr0(cr0.flags);
    native_write_cr4(cr4.flags);
}

void hv_vmx_vmxon_destroy(VMXON* vmxon) {
    free_pages_exact(vmxon, VMXON_REGION_REQUIRED_PAGES);
}

static ssize_t vmxon_init(VMXON* vmxon, struct cpu_ctx* cpu) {
    /* Write VMCS revision identifier to bits 30:0 to first 4 bytes, bit 31
     * should be cleared. */
    vmxon->revision_id = (u32)cpu->vmm->vmx_capabilities.vmcs_revision_id;
    vmxon->must_be_zero = 0;
    return 0;
}

VMXON* vmx_vmxon_region_create(struct cpu_ctx* cpu) {
    VMXON* vmxon_region;

    /* VMXON region must be allocated in physically contiguous, write-back,
     * memory. The standard kernel memory allocation functions will return
     * pointers to write-back memory, so no explicit PAT change is necessary.
     *
     * Additionally, the VMXON pointer must be 4K aligned and must not set any
     * bits beyond the processors physical address width. */
    if (!(vmxon_region =
              alloc_pages_exact(VMXON_REGION_REQUIRED_PAGES, GFP_KERNEL))) {
        hv_utils_cpu_log(err, cpu, "unable to allocate VMXON region\n");
        return NULL;
    }

    /* Clear allocation in case of dirtied pages. */
    memset(vmxon_region, 0x0, VMXON_REGION_REQUIRED_BYTES);

    if (vmxon_init(vmxon_region, cpu) < 0) {
        hv_utils_cpu_log(err, cpu, "unable to initialise VMXON region\n");
        hv_vmx_vmxon_destroy(vmxon_region);
        return NULL;
    }

    return vmxon_region;
}
