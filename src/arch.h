#pragma once

#include <linux/types.h>

#include "ia32.h"

#define CPUID_PHYS_ADDR_WIDTH_LEAF 0x80000008
/* Virtual Machine Extensions support bit. */
#define CPUID_VMX_ENABLED_BIT 0x5

struct cpu_ctx;

struct hv_arch_segment_descriptor {
    SEGMENT_SELECTOR selector;
    u64 limit;
    VMX_SEGMENT_ACCESS_RIGHTS access_rights;
    u64 base_address;
};

struct hv_arch_cpu_state {
    CR0 cr0;
    CR3 cr3;
    CR4 cr4;
    DR7 dr7;

    SEGMENT_DESCRIPTOR_REGISTER_64 gdtr;
    SEGMENT_DESCRIPTOR_REGISTER_64 idtr;
    struct hv_arch_segment_descriptor seg_cs;
    struct hv_arch_segment_descriptor seg_ds;
    struct hv_arch_segment_descriptor seg_es;
    struct hv_arch_segment_descriptor seg_ss;
    struct hv_arch_segment_descriptor seg_gs;
    struct hv_arch_segment_descriptor seg_fs;
    struct hv_arch_segment_descriptor task_register;
    struct hv_arch_segment_descriptor ldtr;
    u64 seg_gs_base;
    u64 seg_fs_base;

    u64 debugctl;
    u64 sysenter_cs;
    u64 sysenter_eip;
    u64 sysenter_esp;
};

u32 hv_arch_cpuid(u32, u32, u32);
bool hv_arch_cpu_has_feature(u32, u32, u32, u32);
bool hv_arch_cpu_has_vmx(void);
void hv_arch_enable_vmxe(void);
void hv_arch_disable_vmxe(void);
void hv_arch_invd(void);
u8 hv_arch_vmxoff(void);
u8 hv_arch_vmxon(phys_addr_t);
u8 hv_arch_vmptrld(phys_addr_t);
u8 hv_arch_vmclear(phys_addr_t);
u8 hv_arch_vmwrite(unsigned long, unsigned long);
u64 hv_arch_vmread(u64);
u8 hv_arch_vmlaunch(void);
u64 hv_arch_lsl(u16);
u64 hv_arch_lar(u16);
void hv_arch_sdlt(SEGMENT_SELECTOR*);
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
