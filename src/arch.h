#define CPUID_VMX_ENABLED_FUNCTION 1
#define CPUID_VMX_ENABLED_BIT 5

#define CPUID_REGISTER_EAX 0
#define CPUID_REGISTER_EBX 1
#define CPUID_REGISTER_ECX 2
#define CPUID_REGISTER_EDX 3

unsigned int arch_cpu_has_feature(unsigned int, unsigned int, unsigned int);
unsigned int arch_cpu_has_vmx(void);
