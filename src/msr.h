#pragma once

#include <linux/types.h>

/* Reporting register of implemented processor features. */
#define IA32_FEATURE_CONTROL_MSR 0x3a
/* Reporting register of basic VMX capabilities. */
#define IA32_VMX_BASIC_MSR 0x480

union ia32_feature_control_msr {
    struct {
        /* System BIOS can use this bit to provide a setup option for BIOS to
         * disable support for VMX. If this bit is clear, VMXON causes a #GP
         * exception. */
        u64 lock : 1;
        /* System BIOS can use this bit to provide a setup option for BIOS to
         * disable support for VMX inside of SMX. If this bit is clear,
         * execution of VMX inside SMX operation causes a #GP exception. */
        u64 enable_vmx_inside_smx : 1;
        /* System BIOS can use this bit to provide a setup option for BIOS to
         * disable support for VMX outside of SMX. If this bit is clear,
         * execution of VMX outside SMX operation causes a #GP exception. */
        u64 enable_vmx_outside_smx : 1;
        /* Additional fields are not implemented here because they differ
         * significantly between processor family and are not immediately
         * hypervisor related. */
        u64 _unlisted : 61;
    } fields;
    u64 value;
};

union ia32_vmx_basic_msr {
    struct {
        /* VMCS revision identifier used by the processor. */
        u64 revision_identifier : 31;
        /* */
        u64 shadow_region : 1;
        /* Number of bytes that software should allocate for VMXON region and
         * other VMCS related structures 0 <= size <= 4096. */
        u64 vmx_structure_size : 13;
        u64 _reserved : 3;
        /* Physical width of the addresses used by the VMXON region, each VMCS,
         * and data structures referenced by pointers in a VMCS.
         * 0 - Addresses are limited to the processor's physical address width.
         * 1 - Addresses are limited to 32 fields. */
        u64 phys_addr_width : 1;
        /* Set if logical supports dual-monitor treatment of system-management
         * interrupts and system-management mode. */
        u64 dual_monitor_smm_support : 1;
        /* Memory type that should be used for the VMCS data structures used by
         * pointers in the VMCS, and for the MSEG header.
         * 0 - Uncachable (UC)
         * 1-5 - Not used
         * 6 - Write Back (WB)
         * 7-15 - Not used */
        u64 memory_type : 4;
        /* Set if processor reports VM-exit instruction-information field on VM
         * exits due to port related instructions. */
        u64 port_vmexit_reporting : 1;
        /* Set if any VMX control that default to 1 may be cleared. */
        u64 mutable_default_values : 1;
        /* Set if software can use VM entry to deliver a hardware exception with
         * or without an error code, regardless of vector. */
        u64 vmentry_hardware_exception : 1;
        u64 _reserved2 : 7;
    } fields;
    u64 value;
};
