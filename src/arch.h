#include <linux/types.h>

/* Bit-vector representing whether a specific processor feature is supported or
 * not. */
#define IA32_FEATURE_CONTROL_MSR 0x3a
/* System BIOS can use this bit to provide a setup option for BIOS to disable
 * support for VMX. If this bit is clear, VMXON causes a #GP exception. */
#define IA32_FEATURE_CONTROL_MSR_LOCK_BIT 0x0
/* System BIOS can use this bit to provide a setup option for BIOS to disable
 * support for VMX outside of SMX. If this bit is clear, executino of VMX
 * outside SMX operation causes a #GP exception. */
#define IA32_FEATURE_CONTROL_MSR_VMX_OUTSIDE_SMX_BIT 0x2

/* Version Information: Type, Family, Model, and Stepping ID. */
#define CPUID_VMX_ENABLED_LEAF 0x1
#define CPUID_VMX_ENABLED_SUBLEAF 0x0
/* Virtual Machine Extensions support bit. */
#define CPUID_VMX_ENABLED_BIT 0x5

#define CPUID_REGISTER_EAX 0x0
#define CPUID_REGISTER_EBX 0x1
#define CPUID_REGISTER_ECX 0x2
#define CPUID_REGISTER_EDX 0x3

bool arch_cpu_has_feature(u32, u32, u32, u32);
bool arch_cpu_has_vmx(void);
u64 arch_rdmsr(u64);
void arch_wrmsr(u64, u64);
