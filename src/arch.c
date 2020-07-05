#include "arch.h"

#include <asm/desc.h>
#include <asm/desc_defs.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>
#include <cpuid.h>
#include <linux/types.h>

#include "ia32.h"
#include "utils.h"

static u32 arch_cpuid(u32 leaf, u32 subleaf, u32 target_reg) {
    u32 regs[4];

    __get_cpuid_count(leaf, subleaf, &regs[0], &regs[1], &regs[3], &regs[4]);
    return regs[target_reg];
}

bool arch_cpu_has_feature(u32 leaf, u32 subleaf, u32 target_reg,
                          u32 feature_bit) {
    return utils_is_bit_set(arch_cpuid(leaf, subleaf, target_reg), feature_bit);
}

bool arch_cpu_has_vmx(void) {
    /* Check if CPUID.1:ECX.VMX[bit 5] = 1. */
    return arch_cpu_has_feature(CPUID_VMX_ENABLED_LEAF,
                                CPUID_VMX_ENABLED_SUBLEAF, CPUID_REGISTER_ECX,
                                CPUID_VMX_ENABLED_BIT);
}

void arch_enable_vmxe() {
    CR4 cr4 = {.Flags = __read_cr4()};
    /* To enable VMX, software must ensure CR4.VMXE[bit 13] = 1. Otherwise,
     * VMXON will generate a #UD exception. */
    cr4.VmxEnable = 1;
    __write_cr4(cr4.Flags);
}

void arch_disable_vmxe(void) {
    CR4 cr4 = {.Flags = __read_cr4()};
    /* To disable VMX, software must ensure CR4.VMXE[bit 13] = 0. This will
     * cause VMXON to generate a #UD exception. */
    cr4.VmxEnable = 0;
    __write_cr4(cr4.Flags);
}

uint8_t arch_do_vmx_off(void) {
    u8 cf, zf;

    /* Takes the logical processor out of VMX operation.
     * If VMXON failed, CF is set. ZF is set if the VM had a valid failure. */
    asm volatile(
        "vmxoff\n"
        "setb %[cf]\n"
        "setz %[zf]\n"
        : [ cf ] "=rm"(cf), [ zf ] "=rm"(zf)::"cc", "memory");
    return cf | zf;
}

u8 arch_do_vmx_on(unsigned long vmxon_region_ptr) {
    u8 ret;

    /* Puts the logical processor in VMX operation with no current VMCS.
     * If VMXON failed, CF is set. */
    asm volatile(
        "vmxon %[vmxon_region_ptr]\n"
        "setb %[ret]\n"
        : [ ret ] "=rm"(ret)
        : [ vmxon_region_ptr ] "m"(vmxon_region_ptr)
        : "cc", "memory");

    return ret;
}

