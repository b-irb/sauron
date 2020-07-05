#include <linux/types.h>

/* Version Information: Type, Family, Model, and Stepping ID. */
#define CPUID_VMX_ENABLED_LEAF 0x1
#define CPUID_VMX_ENABLED_SUBLEAF 0x0
/* Virtual Machine Extensions support bit. */
#define CPUID_VMX_ENABLED_BIT 0x5

#define CPUID_REGISTER_EAX 0x0
#define CPUID_REGISTER_EBX 0x1
#define CPUID_REGISTER_ECX 0x2
#define CPUID_REGISTER_EDX 0x3

struct vmm_cpu_ctx;

bool arch_cpu_has_feature(u32, u32, u32, u32);
bool arch_cpu_has_vmx(void);
void arch_enable_vmxe(void);
void arch_disable_vmxe(void);
u8 arch_do_vmx_off(void);
u8 arch_do_vmx_on(unsigned long);
