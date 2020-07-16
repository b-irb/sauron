#include "vmcs.h"

#include <asm/desc.h>
#include <asm/processor.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "arch.h"
#include "cpu.h"
#include "ia32.h"
#include "utils.h"
#include "vmm.h"

#define APPLY_CTLS_POLICY(name, cpu, ctls, domain)                     \
    name.flags =                                                       \
        native_read_msr((cpu->vmm->vmx_capabilities.vmx_controls == 1) \
                            ? IA32_VMX_TRUE_##domain##_CTLS            \
                            : IA32_VMX_##domain##_CTLS);               \
    ctls.flags = hv_utils_set_required_bits(                           \
        ctls.flags, name.allowed_0_settings, name.allowed_1_settings);

void hv_vmcs_vmcs_destroy(VMCS* vmcs) {
    free_pages_exact(vmcs, VMCS_REGION_REQUIRED_PAGES);
}

VMCS* hv_vmcs_vmcs_create(struct cpu_ctx* cpu) {
    VMCS* vmcs_region;

    if (!(vmcs_region =
              alloc_pages_exact(VMCS_REGION_REQUIRED_BYTES, GFP_KERNEL))) {
        hv_utils_cpu_log(err, cpu, "unable to allocate VMCS region\n");
        return NULL;
    }

    memset(vmcs_region, 0x0, VMCS_REGION_REQUIRED_BYTES);

    vmcs_region->revision_id = (u32)cpu->vmm->vmx_capabilities.vmcs_revision_id;
    vmcs_region->shadow_vmcs_indicator = 0;
    return vmcs_region;
}

#define SETUP_REGION_SEGMENT_SELECTOR_NO_BASE(region, _selector, descriptor) \
    err |= hv_arch_do_vmwrite(VMCS_##region##_##_selector##_SELECTOR,        \
                              descriptor.selector.flags);                    \
    err |= hv_arch_do_vmwrite(VMCS_##region##_##_selector##_LIMIT,           \
                              descriptor.limit);                             \
    err |= hv_arch_do_vmwrite(VMCS_##region##_##_selector##_ACCESS_RIGHTS,   \
                              descriptor.access_rights.flags);

#define SETUP_REGION_SEGMENT_SELECTOR_BASE(region, selector, descriptor) \
    err |= hv_arch_do_vmwrite(VMCS_##region##_##selector##_BASE,         \
                              descriptor.base_address);

#define SETUP_REGION_SEGMENT_SELECTOR(region, selector, descriptor)     \
    SETUP_REGION_SEGMENT_SELECTOR_NO_BASE(region, selector, descriptor) \
    SETUP_REGION_SEGMENT_SELECTOR_BASE(region, selector, descriptor)

#define SETUP_GUEST_SEGMENT_SELECTOR(selector, descriptor) \
    SETUP_REGION_SEGMENT_SELECTOR(GUEST, selector, descriptor)

#define SETUP_GUEST_SEGMENT_SELECTOR_NO_BASE(selector, descriptor) \
    SETUP_REGION_SEGMENT_SELECTOR_NO_BASE(GUEST, selector, descriptor)

#define SETUP_GUEST_SEGMENT_SELECTOR(selector, descriptor) \
    SETUP_REGION_SEGMENT_SELECTOR(GUEST, selector, descriptor)

#define SETUP_GUEST_SEGMENT_SELECTOR_NO_BASE(selector, descriptor) \
    SETUP_REGION_SEGMENT_SELECTOR_NO_BASE(GUEST, selector, descriptor)

#define SETUP_HOST_SEGMENT_SELECTOR(_selector, descriptor)      \
    err |= hv_arch_do_vmwrite(VMCS_HOST_##_selector##_SELECTOR, \
                              descriptor.selector.flags);

static ssize_t vmcs_host_state_area_init(struct cpu_ctx* cpu) {
    struct hv_arch_cpu_state state = cpu->state;
    ssize_t err = 0;

    err |= hv_arch_do_vmwrite(VMCS_HOST_CR0, state.cr0.flags);
    err |= hv_arch_do_vmwrite(VMCS_HOST_CR3, state.cr3.flags);
    err |= hv_arch_do_vmwrite(VMCS_HOST_CR4, state.cr4.flags);

    err |= hv_arch_do_vmwrite(VMCS_HOST_RIP, (u64)cpu->vmexit_handler);
    err |= hv_arch_do_vmwrite(VMCS_HOST_RSP, (u64)&cpu->vmexit_stack->cpu);

    SETUP_HOST_SEGMENT_SELECTOR(CS, state.seg_cs);
    SETUP_HOST_SEGMENT_SELECTOR(DS, state.seg_ds);
    SETUP_HOST_SEGMENT_SELECTOR(ES, state.seg_es);
    SETUP_HOST_SEGMENT_SELECTOR(SS, state.seg_ss);
    SETUP_HOST_SEGMENT_SELECTOR(FS, state.seg_fs);
    SETUP_HOST_SEGMENT_SELECTOR(GS, state.seg_gs);
    SETUP_HOST_SEGMENT_SELECTOR(TR, state.task_register);

    err |= hv_arch_do_vmwrite(VMCS_HOST_FS_BASE, state.seg_fs_base);
    err |= hv_arch_do_vmwrite(VMCS_HOST_GS_BASE, state.seg_gs_base);
    err |=
        hv_arch_do_vmwrite(VMCS_HOST_TR_BASE, state.task_register.base_address);

    err |= hv_arch_do_vmwrite(VMCS_HOST_GDTR_BASE, state.gdtr.base_address);
    err |= hv_arch_do_vmwrite(VMCS_HOST_IDTR_BASE, state.idtr.base_address);

    err |= hv_arch_do_vmwrite(VMCS_HOST_SYSENTER_CS, state.sysenter_cs);
    err |= hv_arch_do_vmwrite(VMCS_HOST_SYSENTER_EIP, state.sysenter_eip);
    err |= hv_arch_do_vmwrite(VMCS_HOST_SYSENTER_ESP, state.sysenter_esp);

    return err;
}

static ssize_t vmcs_guest_state_area_init(struct cpu_ctx* cpu) {
    struct hv_arch_cpu_state state = cpu->state;
    ssize_t err = 0;

    /* Guest Register State */

    err |= hv_arch_do_vmwrite(VMCS_GUEST_CR0, state.cr0.flags);
    err |= hv_arch_do_vmwrite(VMCS_GUEST_CR3, state.cr3.flags);
    err |= hv_arch_do_vmwrite(VMCS_GUEST_CR4, state.cr4.flags);
    err |= hv_arch_do_vmwrite(VMCS_GUEST_DR7, state.dr7.flags);

    err |= hv_arch_do_vmwrite(VMCS_GUEST_RIP, cpu->resume_ip);
    err |= hv_arch_do_vmwrite(VMCS_GUEST_RSP, cpu->resume_sp);
    /* RFLAGS is overwritten in VMX guest entry on vmlaunch. */
    err |= hv_arch_do_vmwrite(VMCS_GUEST_RFLAGS, 0);

    SETUP_GUEST_SEGMENT_SELECTOR(CS, state.seg_cs);
    SETUP_GUEST_SEGMENT_SELECTOR(DS, state.seg_ds);
    SETUP_GUEST_SEGMENT_SELECTOR(ES, state.seg_es);
    SETUP_GUEST_SEGMENT_SELECTOR(SS, state.seg_ss);
    SETUP_GUEST_SEGMENT_SELECTOR(LDTR, state.ldtr);
    SETUP_GUEST_SEGMENT_SELECTOR(TR, state.task_register);

    SETUP_GUEST_SEGMENT_SELECTOR_NO_BASE(FS, state.seg_fs);
    SETUP_GUEST_SEGMENT_SELECTOR_NO_BASE(GS, state.seg_gs);
    err |= hv_arch_do_vmwrite(VMCS_GUEST_FS_BASE, state.seg_fs_base);
    err |= hv_arch_do_vmwrite(VMCS_GUEST_GS_BASE, state.seg_gs_base);

    err |= hv_arch_do_vmwrite(VMCS_GUEST_GDTR_BASE, state.gdtr.base_address);
    err |= hv_arch_do_vmwrite(VMCS_GUEST_GDTR_LIMIT, state.gdtr.limit);
    err |= hv_arch_do_vmwrite(VMCS_GUEST_IDTR_BASE, state.idtr.base_address);
    err |= hv_arch_do_vmwrite(VMCS_GUEST_IDTR_LIMIT, state.idtr.limit);

    err |= hv_arch_do_vmwrite(VMCS_GUEST_DEBUGCTL, state.debugctl);
    err |= hv_arch_do_vmwrite(VMCS_GUEST_SYSENTER_CS, state.sysenter_cs);
    err |= hv_arch_do_vmwrite(VMCS_GUEST_SYSENTER_EIP, state.sysenter_eip);
    err |= hv_arch_do_vmwrite(VMCS_GUEST_SYSENTER_ESP, state.sysenter_esp);

    /* Guest Non-Register State */

    /* Activity state identifies the logical processors activity state. When a
     * logical processor is executing instructions normally, it is in active
     * state. Execution of certain instructions and the occurrence of certain
     * events may cause a logical processor to transition to an inactivestate in
     * which is ceases to execute instructions.
     *
     * 0: Active. The logical processor is executing instructions normally.
     */
    err |= hv_arch_do_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0);
    /* Interruptability state denotes what events are blocked for certain
     * periods of time.
     *
     * 0: Blocking by STI. Execution of STI with RFLAGS.IF = 0 blocks maskable
     * interrupts on the instruction boundary following its execution. Setting
     * this bit indicates that this blocking is in effect. */
    err |= hv_arch_do_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);
    /* Pending debug exceptions contains information about debug exceptions. It
     * is set to 0 because there are no pending debug exception information. */
    err |= hv_arch_do_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);
    /* VMCS link pointer points to an additional VMCS which is accessed with
     * vmread and vmwrite if "VMCS shadowing" VM-execution control is 1. The
     * link pointer should be set to ~0UL to avoid VM-entry failures. */
    err |= hv_arch_do_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0UL);
    return err;
}

static ssize_t setup_pinbased_controls(struct cpu_ctx* cpu) {
    IA32_VMX_TRUE_CTLS_REGISTER policy;
    IA32_VMX_PINBASED_CTLS_REGISTER ctls = {.flags = 0};
    APPLY_CTLS_POLICY(policy, cpu, ctls, PINBASED);
    return hv_arch_do_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS,
                              ctls.flags);
}

static ssize_t setup_secondary_procbased_controls(struct cpu_ctx* cpu) {
    const IA32_VMX_TRUE_CTLS_REGISTER policy = {
        .flags = native_read_msr(IA32_VMX_PROCBASED_CTLS2)};
    IA32_VMX_PROCBASED_CTLS2_REGISTER ctls = {.flags = 0};
    /* If this control is 1, Intel Processor Trace suppresses from PIPs an
     * indication that the processor was in VMX non-root operation and omits
     * a VMCS packet from any PSB+ produced in VMX non-root operation. */
    ctls.conceal_vmx_from_pt = 1;

    ctls.flags = hv_utils_set_required_bits(
        ctls.flags, policy.allowed_0_settings, policy.allowed_1_settings);
    return hv_arch_do_vmwrite(
        VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, ctls.flags);
}

static ssize_t setup_procbased_controls(struct cpu_ctx* cpu) {
    IA32_VMX_TRUE_CTLS_REGISTER policy;
    IA32_VMX_PROCBASED_CTLS_REGISTER ctls = {.flags = 0};
    /* This control determines whether the secondary processor-based VM
     * execution controls are used. If this control is 0, the logical processor
     * operates as if all the secondary processor-based VM-execution controls
     * were also 0. */
    ctls.activate_secondary_controls = 1;
    /* This control determines whether MSR bitmaps are used to control execution
     * of the RDMSR and WRMSR instructions. For this control, "0" means "do not
     * use MSR bitmaps" and "1" means "use MSR bitmaps". If the MSR bitmaps are
     * not used, all executions of the RDMSR and WRMSR instructions cause VM
     * exists. */
    ctls.use_msr_bitmaps = 1;

    APPLY_CTLS_POLICY(policy, cpu, ctls, PROCBASED);

    if (!ctls.use_msr_bitmaps || !ctls.activate_secondary_controls) {
        hv_utils_cpu_log(
            err, cpu, "unable to set all processor based controls in the VMCS");
        return -1;
    }
    return hv_arch_do_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                              ctls.flags);
}

static ssize_t setup_vmentry_controls(struct cpu_ctx* cpu) {
    IA32_VMX_TRUE_CTLS_REGISTER policy;
    ssize_t err = 0;
    IA32_VMX_ENTRY_CTLS_REGISTER ctls = {.flags = 0};
    /* On processors that support Intel 64 architecture, this control determines
     * whether the logical processor is in IA-32e mode after VM entry. Its value
     * is loaded into IA32_EFER.LMA as part of VM entry. This control must be 0
     * on processors that do not support Intel 64 architecture.*/
    ctls.ia32e_mode_guest = 1;
    /* If this control is 1, Intel Processor Trace does not produce a paging
     * information packet (PIP) on a VM entry or a VMCS packet on a VM entry
     * that returns from SMM. */
    ctls.conceal_vmx_from_pt = 1;

    APPLY_CTLS_POLICY(policy, cpu, ctls, ENTRY);
    err |= hv_arch_do_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, ctls.flags);
    /* his field contains the number of MSRs to be loaded on VM entry. It is
     * recommended that this count not exceed 512. Otherwise, unpredictable
     * processor behavior (including a machine check) may result during VM
     * entry. */
    err |= hv_arch_do_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
    /* This field provides details about the event to be injected through the
     * guest IDT. */
    err |=
        hv_arch_do_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);
    return err;
}

static ssize_t setup_vmexit_controls(struct cpu_ctx* cpu) {
    IA32_VMX_TRUE_CTLS_REGISTER policy;
    ssize_t err = 0;
    IA32_VMX_EXIT_CTLS_REGISTER ctls = {.flags = 0};
    /* On processors that support Intel 64 architecture, this control determines
     * whether a logical processor is in 64-bit mode after the next VM exit. Its
     * value is loaded into CS.L, IA32_EFER.LME, and IA32_EFER.LMA on every VM
     * exit. This control must be 0 on processors that do not support Intel 64
     * architecture. */
    ctls.host_address_space_size = 1;
    /* If this control is 1, Intel Processor Trace does not produce a paging
     * information packet (PIP) on a VM exit or a VMCS packet on an SMM VM exit.
     */
    ctls.conceal_vmx_from_pt = 1;

    APPLY_CTLS_POLICY(policy, cpu, ctls, EXIT);
    err |= hv_arch_do_vmwrite(VMCS_CTRL_VMEXIT_CONTROLS, ctls.flags);
    /* This field specifies the number of MSRs to be stored on VM exit. It is
     * recommended that this count not exceed 512. Otherwise, unpredictable
     * processor behavior (including a machine check) may result during VM exit.
     */
    err |= hv_arch_do_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
    /* This field contains the number of MSRs to be loaded on VM exit. It is
     * recommended that this count not exceed 512. Otherwise, unpredictable
     * processor behavior (including a machine check) may result during VM exit.
     */
    err |= hv_arch_do_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);
    return err;
}

static ssize_t vmcs_control_fields_init(struct cpu_ctx* cpu) {
    ssize_t err = 0;
    /* VM-EXECUTION CONTROL FIELDS */

    /* Pin Based VM-Execution Controls: The pin-based VM-execution controls
     * constitute a 32-bit vector that governs the handling of asynchronous
     * events. */
    err |= setup_pinbased_controls(cpu);
    err |= setup_procbased_controls(cpu);
    err |= setup_secondary_procbased_controls(cpu);
    /* The exception bitmap is a 32-bit field that contains one bit for each
     * exception. When an exception occurs, its vector is used to select a bit
     * in this field. If the bit is 1, the exception causes a VM exit. If the
     * bit is 0, the exception is delivered normally through the IDT, using the
     * descriptor corresponding to the exception’s vector. */
    err |= hv_arch_do_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, 0);
    /* Whether a page fault (exception with vector 14) causes a VM exit is
     * determined by bit 14 in the exception bitmap as well as the error code
     * produced by the page fault and two 32-bit fields in the VMCS (the
     * page-fault error-code mask and page-fault error-code match). */
    err |= hv_arch_do_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
    err |= hv_arch_do_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);
    /* VM-execution control fields include guest/host masks and read shadows for
     * the CR0 and CR4 registers. These fields control executions of
     * instructions that access those registers (including CLTS, LMSW, MOV CR,
     * and SMSW). They are 64 bits on processors that support Intel 64
     * architecture and 32 bits on processors that do not.In general, bits set
     * to 1 in a guest/host mask correspond to bits “owned” by the host:
     * - Guest attempts to set them (using CLTS, LMSW, or MOV to CR) to values
     * differing from the corresponding bits in the corresponding read shadow
     * cause VM exits.
     * - Guest reads (using MOV from CR or SMSW) return values for these bits
     * from the corresponding read shadow.
     *
     * Bits cleared to 0 correspond to bits “owned” by the guest; guest attempts
     * to modify them succeed and guest reads return values for these bits from
     * the control register itself. */
    err |= hv_arch_do_vmwrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
    err |= hv_arch_do_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, cpu->state.cr0.flags);
    err |= hv_arch_do_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0);
    err |= hv_arch_do_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, cpu->state.cr4.flags);
    /* The VM-execution control fields include a set of 4 CR3-target values and
     * a CR3-target count. The CR3-target values each have 64 bits on processors
     * that support Intel 64 architecture and 32 bits on processors that do not.
     * The CR3-target count has 32 bits on all processors.
     *
     * An execution of MOV to
     * CR3 in VMX non-root operation does not cause a VM exit if its source
     * operand matches one of these values. If the CR3-target count is n, only
     * the first n CR3-target values are considered; if the CR3-target count is
     * 0, MOV to CR3 always causes a VM exit.
     *
     * There are no limitations on the values that can be written for the
     * CR3-target values. VM entry fails (see Section 26.2) if the CR3-target
     * count is greater than 4. */
    err |= hv_arch_do_vmwrite(VMCS_CTRL_CR3_TARGET_COUNT, 0);
    /* On processors that support the 1-setting of the “use MSR bitmaps”
     * VM-execution control, the VM-execution control fields include the 64-bit
     * physical address of four contiguous MSR bitmaps, which are each 1-KByte
     * in size. This field does not exist on processors that do not support the
     * 1-setting of that control. The four bitmaps are:
     *
     * Read bitmap for low MSRs (located at the MSR-bitmap address). This
     * contains one bit for each MSR address in the range 00000000H to
     * 00001FFFH. The bit determines whether an execution of RDMSR applied to
     * that MSR causes a VM exit.
     *
     * Read bitmap for high MSRs (located at the MSR-bitmap address plus 1024).
     * This contains one bit for each MSR address in the range C0000000H
     * toC0001FFFH. The bit determines whether an execution of RDMSR applied to
     * that MSR causes a VM exit.
     *
     * Write bitmap for low MSRs (located at the MSR-bitmap address plus 2048).
     * This contains one bit for each MSR address in the range 00000000H to
     * 00001FFFH. The bit determines whether an execution of WRMSR applied to
     * that MSR causes a VM exit.
     *
     * Write bitmap for high MSRs (located at the MSR-bitmap address plus 3072).
     * This contains one bit for each MSR address in the range C0000000H
     * toC0001FFFH. The bit determines
     * whether an execution of WRMSR applied to that MSR causes a VM exit. */
    err |=
        hv_arch_do_vmwrite(VMCS_CTRL_MSR_BITMAP_ADDRESS, cpu->msr_bitmap_ptr);
    err |= setup_vmexit_controls(cpu);
    err |= setup_vmentry_controls(cpu);
    return err;
}

ssize_t hv_vmcs_vmcs_init(struct cpu_ctx* cpu) {
    ssize_t err = 0;

    if ((err = vmcs_guest_state_area_init(cpu))) {
        hv_utils_cpu_log(err, cpu, "failed to setup VMCS guest state\n");
        return err;
    }
    if ((err = vmcs_host_state_area_init(cpu))) {
        hv_utils_cpu_log(err, cpu, "failed to setup VMCS host state\n");
        return err;
    }

    if ((err = vmcs_control_fields_init(cpu))) {
        hv_utils_cpu_log(err, cpu, "failed to setup VMCS control fields\n");
        return err;
    }
    return err;
}
