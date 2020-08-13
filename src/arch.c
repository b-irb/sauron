#include "arch.h"

#include <asm/desc.h>
#include <asm/desc_defs.h>
#include <asm/io.h>
#include <asm/paravirt.h>
#include <asm/processor-flags.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/special_insns.h>
#include <asm/tlbflush.h>
#include <linux/sched/task_stack.h>
#include <linux/types.h>

#include "cpu.h"
#include "ia32.h"
#include "utils.h"

#define OUTPUT_SEG_DESC(SEG, desc) \
    hv_utils_cpu_log(                                                       \
        debug,                                                               \
        TOSTRING(                                                           \
            SEG) " selector=%x, base=%pK, limit=%llx, access_rights=%x, unusable=%d\n", \
        desc.selector.flags, (void*)desc.base_address, desc.limit,                 \
        desc.access_rights.flags, desc.access_rights.unusable);

#define PARSE_SELECTOR(cpu, selector)                                         \
    hv_arch_read_seg_descriptor(&cpu->state.seg_##selector, cpu->state.gdtr,  \
                                (SEGMENT_SELECTOR)hv_arch_read_##selector()); \
    OUTPUT_SEG_DESC(selector, cpu->state.seg_##selector)

bool hv_arch_cpu_has_vmx(void) {
    /* Check if CPUID.1:ECX.VMX[bit 5] = 1. */
    return hv_utils_is_bit_set(cpuid_ecx(CPUID_VERSION_INFORMATION),
                               CPUID_VMX_ENABLED_BIT);
}

void hv_arch_enable_vmxe(void) {
    /* To enable VMX, software must ensure CR4.VMXE[bit 13] = 1. Otherwise,
     * VMXON will generate a #UD exception. */
    cr4_set_bits(X86_CR4_VMXE);
}

void hv_arch_disable_vmxe(void) {
    /* To disable VMX, software must ensure CR4.VMXE[bit 13] = 0. This will
     * cause VMXON to generate a #UD exception. */
    cr4_clear_bits(X86_CR4_VMXE);
}

void hv_arch_invd(void) { asm volatile("invd\n"); }

u8 hv_arch_vmwrite(unsigned long field, unsigned long value) {
    u8 ret;
    asm volatile(
        "vmwrite %[value], %[field]\n"
        "setb %[ret]\n"
        : [ ret ] "=rm"(ret)
        : [ value ] "r"(value), [ field ] "rm"(field)
        : "cc", "memory");
    return ret;
}

u64 hv_arch_vmread(u64 field) {
    u64 value;
    asm volatile("vmread %[field], %[value]\n"
                 : [ value ] "=r"(value)
                 : [ field ] "r"(field)
                 : "cc", "memory");
    return value;
}

u8 hv_arch_vmclear(phys_addr_t vmcs_region_ptr) {
    u8 ret;
    asm volatile(
        "vmclear %[vmcs_region_ptr]\n"
        "setb %[ret]\n"
        : [ ret ] "=rm"(ret)
        : [ vmcs_region_ptr ] "m"(vmcs_region_ptr)
        : "cc", "memory");
    return ret;
}

u8 hv_arch_vmptrld(phys_addr_t vmcs_region_ptr) {
    u8 ret;
    asm volatile(
        "vmptrld %[vmcs_region_ptr]\n"
        "setb %[ret]\n"
        : [ ret ] "=rm"(ret)
        : [ vmcs_region_ptr ] "m"(vmcs_region_ptr)
        : "cc", "memory");
    return ret;
}

u8 hv_arch_vmxoff(void) {
    u8 cf = 0;
    u8 zf = 0;
    /* Takes the logical processor out of VMX operation. If VMXON failed with an
     * invalid VMCS, CF is set. Otherwise, ZF is set and the error field in the
     * VMCS is set. */
    asm volatile(
        "vmxoff\n"
        "setb %[cf]\n"
        "setz %[zf]\n"
        : [ cf ] "=rm"(cf), [ zf ] "=rm"(zf)::"cc", "memory");

    if (zf) {
        hv_utils_cpu_log(err, "VMXOFF failed with VMCS error %llx\n",
                         hv_arch_vmread(VMCS_VM_INSTRUCTION_ERROR));
        return 1;
    }
    return cf | zf;
}

u8 hv_arch_vmxon(phys_addr_t vmxon_region_ptr) {
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

u8 hv_arch_vmlaunch(void) {
    u8 err;
    asm volatile(
        "vmlaunch\n"
        "setb %[err]\n"
        : [ err ] "=rm"(err)::"cc", "memory");
    return err;
}

u64 hv_arch_lar(u16 selector) {
    u64 access_rights;
    asm volatile("lar %[access_rights], %[selector]\n"
                 : [ access_rights ] "=r"(access_rights)
                 : [ selector ] "r"(selector)
                 : "cc");
    return access_rights;
}

u64 hv_arch_lsl(u16 selector) {
    u64 limit;
    asm volatile("lsl %[limit], %[selector]\n"
                 : [ limit ] "=r"(limit)
                 : [ selector ] "r"(selector)
                 : "cc");
    return limit;
}

u64 hv_arch_read_dr7(void) {
    u64 out;
    asm volatile("mov %%dr7, %[out]\n" : [ out ] "=r"(out));
    return out;
}

void hv_arch_sdlt(SEGMENT_SELECTOR* out) {
    asm volatile("sldt %[out]\n" : [ out ] "=m"(out));
}

void hv_arch_capture_cpu_state(struct cpu_ctx* cpu) {
    SEGMENT_SELECTOR ldtr;

    cpu->state.cr0.flags = native_read_cr0();
    cpu->state.cr3.flags = __read_cr3();
    cpu->state.cr4.flags = native_read_cr4();
    cpu->state.dr7.flags = hv_arch_read_dr7();

    hv_utils_cpu_log(debug, "CR0=%llx, CR3=%llx, CR4=%llx\n",
                     cpu->state.cr0.flags, cpu->state.cr3.flags,
                     cpu->state.cr4.flags);

    native_store_gdt((struct desc_ptr*)&cpu->state.gdtr);
    hv_utils_cpu_log(debug, "GDT base=%llx, limit=%x\n",
                     cpu->state.gdtr.base_address, cpu->state.gdtr.limit);

    store_idt((struct desc_ptr*)&cpu->state.idtr);
    hv_utils_cpu_log(debug, "IDT base=%llx, limit=%x\n",
                     cpu->state.idtr.base_address, cpu->state.idtr.limit);

    hv_arch_sdlt(&ldtr);
    hv_arch_read_seg_descriptor(&cpu->state.ldtr, cpu->state.gdtr, ldtr);
    OUTPUT_SEG_DESC(LDT, cpu->state.ldtr);

    PARSE_SELECTOR(cpu, cs)
    PARSE_SELECTOR(cpu, ds)
    PARSE_SELECTOR(cpu, es)
    PARSE_SELECTOR(cpu, ss)
    PARSE_SELECTOR(cpu, gs)
    PARSE_SELECTOR(cpu, fs)
    hv_arch_read_seg_descriptor(&cpu->state.task_register, cpu->state.gdtr,
                                (SEGMENT_SELECTOR)hv_arch_read_tr());
    OUTPUT_SEG_DESC(tr, cpu->state.task_register)

    cpu->state.seg_gs_base = native_read_msr(IA32_GS_BASE);
    cpu->state.seg_fs_base = native_read_msr(IA32_FS_BASE);

    hv_utils_cpu_log(debug, "GS_BASE=%llx, FS_BASE=%llx\n",
                     cpu->state.seg_gs_base, cpu->state.seg_fs_base);

    cpu->state.debugctl = native_read_msr(IA32_DEBUGCTL);
    cpu->state.sysenter_cs = native_read_msr(IA32_SYSENTER_CS);
    cpu->state.sysenter_eip = native_read_msr(IA32_SYSENTER_EIP);
    cpu->state.sysenter_esp = native_read_msr(IA32_SYSENTER_ESP);

    hv_utils_cpu_log(debug,
                     "SYSENTER_CS=%llx, SYSENTER_EIP=%llx, SYSENTER_ESP=%llx\n",
                     cpu->state.sysenter_cs, cpu->state.sysenter_eip,
                     cpu->state.sysenter_esp);
}

void hv_arch_read_seg_descriptor(
    struct hv_arch_segment_descriptor* processed_descriptor,
    const SEGMENT_DESCRIPTOR_REGISTER_64 dtr, const SEGMENT_SELECTOR selector) {
    SEGMENT_DESCRIPTOR_64 descriptor;

    if (!selector.flags) {
        /* A NULL selector will attempt to index the first entry of the GDT
         * which is invalid and therefore unusable. */
        processed_descriptor->access_rights.unusable = 1;
        return;
    }

    descriptor =
        *(SEGMENT_DESCRIPTOR_64*)(dtr.base_address + (selector.index << 3));

    memset(processed_descriptor, 0x0,
           sizeof(struct hv_arch_segment_descriptor));

    /* Clear RPL and TI flags for VMCS host state fields to be valid. */
    processed_descriptor->selector.flags = selector.flags & ~0x7;
    processed_descriptor->limit = hv_arch_lsl(selector.flags);

    /* LAR does not yield the correct result, I am unsure why. Hence, I load
     * the access rights manually. */
    processed_descriptor->access_rights.type = descriptor.type;
    processed_descriptor->access_rights.descriptor_type =
        descriptor.descriptor_type;
    processed_descriptor->access_rights.descriptor_privilege_level =
        descriptor.descriptor_privilege_level;
    processed_descriptor->access_rights.present = descriptor.present;
    processed_descriptor->access_rights.available_bit = descriptor.system;
    processed_descriptor->access_rights.long_mode = descriptor.long_mode;
    processed_descriptor->access_rights.default_big = descriptor.default_big;
    processed_descriptor->access_rights.granularity = descriptor.granularity;

    processed_descriptor->base_address =
        descriptor.base_address_low | (descriptor.base_address_middle << 16) |
        (descriptor.base_address_high << 24);

    if (!descriptor.descriptor_type &&
        (descriptor.type == SEGMENT_DESCRIPTOR_TYPE_LDT ||
         descriptor.type == SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE ||
         descriptor.type == SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY)) {
        /* System descriptors are expanded to 16 byte descriptors which can hold
         * 64-bit addresses, we must include the upper address segment. */
        processed_descriptor->base_address |= (u64)descriptor.base_address_upper
                                              << 32UL;
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
