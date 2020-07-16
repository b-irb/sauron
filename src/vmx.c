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

static void reset_fixed_bits(struct cpu_ctx* cpu) {
    native_write_cr0(cpu->unfixed_cr0.flags);
    native_write_cr4(cpu->unfixed_cr4.flags);
}

static void set_fixed_bits(struct cpu_ctx* cpu) {
    CR0 cr0 = {.flags = native_read_cr0()};
    CR4 cr4 = {.flags = native_read_cr4()};

    cpu->unfixed_cr0 = cr0;
    cpu->unfixed_cr4 = cr4;

    cr0.flags = hv_utils_set_required_bits(
        cr0.flags, native_read_msr(IA32_VMX_CR0_FIXED0),
        native_read_msr(IA32_VMX_CR0_FIXED1));
    cr4.flags = hv_utils_set_required_bits(
        cr4.flags, native_read_msr(IA32_VMX_CR4_FIXED0),
        native_read_msr(IA32_VMX_CR4_FIXED1));

    native_write_cr0(cr0.flags);
    native_write_cr4(cr4.flags);
}

void hv_vmx_launch_cpu(struct cpu_ctx* cpu) {
    hv_arch_do_vmlaunch();
    /* If execution continues, vmlaunch failed. */
    hv_utils_cpu_log(err, cpu, "vmlaunch failed\n");

    hv_vmx_exit_root(cpu);
    hv_cpu_ctx_destroy(cpu);
    cpu->failed = true;
}

ssize_t hv_vmx_exit_root(struct cpu_ctx* cpu) {
    /*
     *    if (hv_arch_do_vmclear(cpu->vmcs_region_ptr)) {
     *        hv_utils_cpu_log(err, cpu,
     *                         "failed to execute VMCLEAR while exiting VMX
     * root\n"); return -1;
     *    }
     *
     *    hv_arch_do_vmxoff();
     */
    hv_arch_do_vmxoff();
    hv_arch_disable_vmxe();
    reset_fixed_bits(cpu);
    hv_utils_cpu_log(info, cpu, "successfully exited VMX root operation\n");
    return 0;
}

ssize_t hv_vmx_enter_root(struct cpu_ctx* cpu) {
    hv_arch_enable_vmxe();
    hv_utils_cpu_log(debug, cpu, "successfully enabled VMXE\n");
    set_fixed_bits(cpu);

    hv_utils_cpu_log(debug, cpu, "vmxon with addr=%pa[p]\n",
                     &cpu->vmxon_region_ptr);
    if (hv_arch_do_vmxon(cpu->vmxon_region_ptr)) {
        hv_utils_cpu_log(err, cpu, "failed to execute VMXON\n");
        return -1;
    }

    hv_utils_cpu_log(debug, cpu, "vmclear with addr=%pa[p]\n",
                     &cpu->vmcs_region_ptr);
    if (hv_arch_do_vmclear(cpu->vmcs_region_ptr)) {
        hv_utils_cpu_log(info, cpu, "failed to execute VMCLEAR\n");
        return -1;
    }

    hv_utils_cpu_log(debug, cpu, "vmptrld with addr=%pa[p]\n",
                     &cpu->vmcs_region_ptr);

    if (hv_arch_do_vmptrld(cpu->vmcs_region_ptr)) {
        hv_utils_cpu_log(info, cpu, "failed to execute VMPTRLD\n");
        return -1;
    }
    return 0;
}

void hv_vmx_vmxon_destroy(VMXON* vmxon) {
    free_pages_exact(vmxon, VMXON_REGION_REQUIRED_PAGES);
}

VMXON* hv_vmx_vmxon_create(struct cpu_ctx* cpu) {
    VMXON* vmxon_region;

    /* VMXON region must be allocated in physically contiguous, write-back,
     * memory. The standard kernel memory allocation functions will return
     * pointers to write-back memory, so no explicit PAT change is necessary.
     *
     * Additionally, the VMXON pointer must be 4K aligned and must not set any
     * bits beyond the processors physical address width. */
    if (!(vmxon_region =
              alloc_pages_exact(VMXON_REGION_REQUIRED_BYTES, GFP_KERNEL))) {
        hv_utils_cpu_log(err, cpu, "unable to allocate VMXON region\n");
        return NULL;
    }

    /* Clear allocation in case of dirtied pages. */
    memset(vmxon_region, 0x0, VMXON_REGION_REQUIRED_BYTES);

    /* Write VMCS revision identifier to bits 30:0 to first 4 bytes, bit 31
     * should be cleared. */
    vmxon_region->revision_id =
        (u32)cpu->vmm->vmx_capabilities.vmcs_revision_id;
    vmxon_region->must_be_zero = 0;
    return vmxon_region;
}
