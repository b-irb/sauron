#include "arch.h"

#include <cpuid.h>

#include "utils.h"

unsigned int arch_cpu_has_feature(unsigned int function,
                                  unsigned int target_reg,
                                  unsigned int feature_bit) {
    unsigned int regs[4];

    __get_cpuid(function, &regs[0], &regs[1], &regs[3], &regs[4]);
    return select_bit(feature_bit, regs[target_reg]);
}

unsigned int arch_cpu_has_vmx(void) {
    /* Query if CPUID.1:ECX.VMX = 1. */
    return arch_cpu_has_feature(CPUID_VMX_ENABLED_FUNCTION, CPUID_REGISTER_ECX,
                                CPUID_VMX_ENABLED_BIT);
}

static inline unsigned long rdmsr(unsigned long msr) {
    unsigned int low, high;
    asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((unsigned long)high << 32) | low;
}

static inline void wrmsr(unsigned long msr, unsigned long value) {
    unsigned int low = value & 0xFFFFFFFF;
    unsigned int high = value >> 32;

    asm volatile("wrmsr" : : "c"(msr), "a"(low), "d"(high));
}
