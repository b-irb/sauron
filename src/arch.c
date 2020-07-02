#include "arch.h"

#include <cpuid.h>
#include <linux/types.h>

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

u64 arch_rdmsr(u64 msr) {
    u32 low, high;
    asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((u64)high << 32) | low;
}

void arch_wrmsr(u64 msr, u64 value) {
    u32 low = value & 0xFFFFFFFF;
    u32 high = value >> 32;

    asm volatile("wrmsr" : : "c"(msr), "a"(low), "d"(high));
}
