#pragma once

#include <linux/ptrace.h>
#include <linux/types.h>

#include "ia32.h"

/* Version Information: Type, Family, Model, and Stepping ID. */
#define CPUID_VMX_ENABLED_LEAF 0x1
#define CPUID_VMX_ENABLED_SUBLEAF 0x0
/* Virtual Machine Extensions support bit. */
#define CPUID_VMX_ENABLED_BIT 0x5

#define CPUID_REGISTER_EAX 0x0
#define CPUID_REGISTER_EBX 0x1
#define CPUID_REGISTER_ECX 0x2
#define CPUID_REGISTER_EDX 0x3

struct cpu_ctx;

struct hv_arch_segment_descriptor {
    SEGMENT_SELECTOR selector;
    SEGMENT_DESCRIPTOR_REGISTER_64 dtr;
    u64 limit;
    VMX_SEGMENT_ACCESS_RIGHTS access_rights;
    u64 base_address;
};

struct hv_arch_cpu_state {
    u64 entry_sp;
    struct pt_regs regs;
    CR0 cr0;
    CR3 cr3;
    CR4 cr4;
    DR7 dr7;

    SEGMENT_DESCRIPTOR_REGISTER_64 gdtr;
    SEGMENT_DESCRIPTOR_REGISTER_64 idtr;
    // SEGMENT_DESCRIPTOR_REGISTER_64 ldtr;
    SEGMENT_SELECTOR seg_cs;
    SEGMENT_SELECTOR seg_ds;
    SEGMENT_SELECTOR seg_es;
    SEGMENT_SELECTOR seg_ss;
    SEGMENT_SELECTOR seg_gs;
    SEGMENT_SELECTOR seg_fs;
    SEGMENT_SELECTOR task_register;
    u64 seg_gs_base;
    u64 seg_fs_base;

    u64 debugctl;
    u64 sysenter_cs;
    u64 sysenter_eip;
    u64 sysenter_esp;
};

bool hv_arch_cpu_has_feature(u32, u32, u32, u32);
bool hv_arch_cpu_has_vmx(void);
void hv_arch_enable_vmxe(void);
void hv_arch_disable_vmxe(void);
u8 hv_arch_do_vmxoff(void);
u8 hv_arch_do_vmxon(phys_addr_t);
u8 hv_arch_do_vmptrld(phys_addr_t);
u8 hv_arch_do_vmclear(phys_addr_t);
u8 hv_arch_do_vmwrite(unsigned long, unsigned long);
u8 hv_arch_do_vmlaunch(void);
u64 hv_arch_do_lsl(u16);
u64 hv_arch_do_lar(u16);
u64 hv_arch_read_dr7(void);

void hv_arch_capture_cpu_state(struct cpu_ctx*);
void hv_arch_read_seg_descriptor(struct hv_arch_segment_descriptor*,
                                 const SEGMENT_DESCRIPTOR_REGISTER_64,
                                 const SEGMENT_SELECTOR);

u16 hv_arch_read_cs(void);
u16 hv_arch_read_ss(void);
u16 hv_arch_read_ds(void);
u16 hv_arch_read_es(void);
u16 hv_arch_read_fs(void);
u16 hv_arch_read_gs(void);
u16 hv_arch_read_tr(void);
