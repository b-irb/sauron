#include "arch.h"

#include <asm/desc.h>
#include <asm/desc_defs.h>
#include <asm/io.h>
#include <asm/processor-flags.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/special_insns.h>
#include <cpuid.h>
#include <linux/sched/task_stack.h>
#include <linux/types.h>

#include "cpu.h"
#include "ia32.h"
#include "utils.h"

static u32 arch_cpuid(u32 leaf, u32 subleaf, u32 target_reg) {
    u32 regs[4];

    __get_cpuid_count(leaf, subleaf, &regs[0], &regs[1], &regs[3], &regs[4]);
    return regs[target_reg];
}

static bool cpu_has_feature(u32 leaf, u32 subleaf, u32 target_reg,
                            u32 feature_bit) {
    return hv_utils_is_bit_set(arch_cpuid(leaf, subleaf, target_reg),
                               feature_bit);
}

bool hv_arch_cpu_has_vmx(void) {
    /* Check if CPUID.1:ECX.VMX[bit 5] = 1. */
    return cpu_has_feature(CPUID_VMX_ENABLED_LEAF, CPUID_VMX_ENABLED_SUBLEAF,
                           CPUID_REGISTER_ECX, CPUID_VMX_ENABLED_BIT);
}

void hv_arch_enable_vmxe() {
    CR4 cr4 = {.flags = native_read_cr4()};
    /* To enable VMX, software must ensure CR4.VMXE[bit 13] = 1. Otherwise,
     * VMXON will generate a #UD exception. */
    cr4.vmx_enable = 1;
    native_write_cr4(cr4.flags);
}

void hv_arch_disable_vmxe(void) {
    CR4 cr4 = {.flags = native_read_cr4()};
    /* To disable VMX, software must ensure CR4.VMXE[bit 13] = 0. This will
     * cause VMXON to generate a #UD exception. */
    cr4.vmx_enable = 0;
    native_write_cr4(cr4.flags);
}

u8 hv_arch_do_vmwrite(unsigned long field, unsigned long value) {
    u8 ret;
    asm volatile(
        "vmwrite %[value], %[field]\n"
        "setb %[ret]\n"
        : [ ret ] "=rm"(ret)
        : [ value ] "r"(value), [ field ] "rm"(field)
        : "cc", "memory");
    return ret;
}

u8 hv_arch_do_vmclear(phys_addr_t vmcs_region_ptr) {
    u8 ret;
    asm volatile(
        "vmclear %[vmcs_region_ptr]\n"
        "setb %[ret]\n"
        : [ ret ] "=rm"(ret)
        : [ vmcs_region_ptr ] "m"(vmcs_region_ptr)
        : "cc", "memory");
    return ret;
}

u8 hv_arch_do_vmptrld(phys_addr_t vmcs_region_ptr) {
    u8 ret;
    asm volatile(
        "vmptrld %[vmcs_region_ptr]\n"
        "setb %[ret]\n"
        : [ ret ] "=rm"(ret)
        : [ vmcs_region_ptr ] "m"(vmcs_region_ptr)
        : "cc", "memory");
    return ret;
}

u8 hv_arch_do_vmxoff(void) {
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

u8 hv_arch_do_vmxon(phys_addr_t vmxon_region_ptr) {
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

u8 hv_arch_do_vmlaunch(void) {
    u8 err;
    asm volatile(
        "vmlaunch\n"
        "setb %[err]\n"
        : [ err ] "=rm"(err)::"cc", "memory");
    return err;
}

u64 hv_arch_do_lar(u16 selector) {
    u64 access_rights;
    asm volatile("lar %[access_rights], %[selector]\n"
                 : [ access_rights ] "=r"(access_rights)
                 : [ selector ] "r"(selector)
                 : "cc");
    return access_rights;
}

u64 hv_arch_do_lsl(u16 selector) {
    u64 limit;
    asm volatile("lsl %[limit], %[selector]\n"
                 : [ limit ] "=r"(limit)
                 : [ selector ] "r"(selector)
                 : "cc");
    return limit;
}

u64 hv_arch_read_dr7(void) {
    u64 out;
    asm volatile("mov %[out], %%dr7\n" : [ out ] "=r"(out));
    return out;
}

void hv_arch_capture_cpu_state(struct cpu_ctx* cpu_ctx) {
    cpu_ctx->state.regs = *task_pt_regs(get_current());
    cpu_ctx->state.cr0.flags = native_read_cr0();
    cpu_ctx->state.cr3.flags = __native_read_cr3();
    cpu_ctx->state.cr4.flags = native_read_cr4();
    cpu_ctx->state.dr7.flags = hv_arch_read_dr7();

    native_store_gdt((struct desc_ptr*)&cpu_ctx->state.gdtr);
    store_idt((struct desc_ptr*)&cpu_ctx->state.idtr);
    /*store_ldt((struct desc_ptr*)&cpu_ctx->state.ldtr);*/

    cpu_ctx->state.seg_cs.flags = hv_arch_read_cs();
    cpu_ctx->state.seg_ds.flags = hv_arch_read_ds();
    cpu_ctx->state.seg_es.flags = hv_arch_read_es();
    cpu_ctx->state.seg_ss.flags = hv_arch_read_ss();
    cpu_ctx->state.seg_gs.flags = hv_arch_read_gs();
    cpu_ctx->state.seg_fs.flags = hv_arch_read_fs();
    cpu_ctx->state.task_register.flags = hv_arch_read_tr();

    cpu_ctx->state.seg_gs_base = native_read_msr(IA32_GS_BASE);
    cpu_ctx->state.seg_fs_base = native_read_msr(IA32_FS_BASE);

    cpu_ctx->state.debugctl = native_read_msr(IA32_DEBUGCTL);
    cpu_ctx->state.sysenter_cs = native_read_msr(IA32_SYSENTER_CS);
    cpu_ctx->state.sysenter_eip = native_read_msr(IA32_SYSENTER_EIP);
    cpu_ctx->state.sysenter_esp = native_read_msr(IA32_SYSENTER_ESP);
}

void hv_arch_read_seg_descriptor(
    struct hv_arch_segment_descriptor* processed_descriptor,
    const SEGMENT_DESCRIPTOR_REGISTER_64 dtr, const SEGMENT_SELECTOR selector) {
    SEGMENT_DESCRIPTOR_64 descriptor;
    /* A segment selector is a 16-bit identifier for a segment. The segment
     * selector has a 13-bit field at a 3-bit offset. In order to calculate the
     * descriptor table index, we mask the offset then shift.
     *
     * (selector & 0xd) >> 3
     *
     * Then, to index into a descriptor table we add the base address of the
     * descriptor table, and the selector offset multiplied by the size of each
     * selector (8 bytes).
     *
     * base_address + (descriptor_idx << 3)
     * base_address + (((selector & 0xd) >> 3) << 3)
     * base_address + (selector & 0xd)
     * */
    if (!selector.flags || selector.table) {
        /* We do not attempt to load a descriptor from the current LDT or load a
         * NULL segment selector, we instead return an unusable VMX segment. */
        processed_descriptor->access_rights.unusable = 1;
        return;
    }

    descriptor =
        *(SEGMENT_DESCRIPTOR_64*)(dtr.base_address + (selector.flags & 0xd));

    memset(processed_descriptor, 0x0,
           sizeof(struct hv_arch_segment_descriptor));

    processed_descriptor->selector = selector;
    processed_descriptor->dtr = dtr;
    processed_descriptor->limit = hv_arch_do_lsl(selector.flags);
    processed_descriptor->access_rights.flags = hv_arch_do_lar(selector.flags);

    processed_descriptor->base_address =
        descriptor.base_address_low | (descriptor.base_address_middle << 16) |
        (descriptor.base_address_high << 24);

    if (!descriptor.system) {
        /* System descriptors are expanded to 16 byte descriptors which can hold
         * 64-bit addresses, we must include the upper address segment. */
        processed_descriptor->base_address |= (u64)descriptor.base_address_upper
                                              << 32L;
    }

    /* Attempts to use a VMX segment with the unusable bit (bit 16) will fault.
     * We explicitly enable each segment for VMX mode to allow vmlaunch to
     * successfully execute. The segments should already be usable: cs, ds, ss,
     * es so a circumstance where the segments are unusable and software
     * attempts to access the segments is already faulty. If software were to
     * behave this way in this condition, a fault would still occur though it
     * will be for slightly different reasons. */
    processed_descriptor->access_rights.unusable = 0;
}

u16 hv_arch_read_tr(void) {
    u16 out;
    asm volatile("str %[out]\n" : [ out ] "=rm"(out));
    return out;
}

#define DEFINE_READ_SEG_REG(reg)                                      \
    u16 hv_arch_read_##reg(void) {                                    \
        u16 out;                                                      \
        asm volatile("mov %%" #reg ", %[out]\n" : [ out ] "=r"(out)); \
        return out;                                                   \
    }

DEFINE_READ_SEG_REG(cs)
DEFINE_READ_SEG_REG(ss)
DEFINE_READ_SEG_REG(ds)
DEFINE_READ_SEG_REG(es)
DEFINE_READ_SEG_REG(fs)
DEFINE_READ_SEG_REG(gs)
