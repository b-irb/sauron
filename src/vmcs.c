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

static u64 set_required_bits(u64 controls, u64 fixed0, u64 fixed1) {
    controls &= fixed1;
    controls |= fixed0;
    return controls;
}

#define APPLY_CTLS_POLICY(name, cpu, ctls, domain)                      \
    name.flags =                                                        \
        native_read_msr((cpu->vmm->vmx_capabilities.vmx_controls == 1)  \
                            ? IA32_VMX_TRUE_##domain##_CTLS             \
                            : IA32_VMX_##domain##_CTLS);                \
    ctls.flags = set_required_bits(ctls.flags, name.allowed_0_settings, \
                                   name.allowed_1_settings);

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
    /* RFLAGS is overwritten in VMX
     * guest entry on vmlaunch. */
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
    err |= hv_arch_do_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL);
    return err;
}

static ssize_t setup_pinbased_controls(struct cpu_ctx* cpu) {
    IA32_VMX_TRUE_CTLS_REGISTER policy;
    IA32_VMX_PINBASED_CTLS_REGISTER ctls = {.flags = 0};

    APPLY_CTLS_POLICY(policy, cpu, ctls, PINBASED)
    return hv_arch_do_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS,
                              ctls.flags);
}

static ssize_t setup_procbased_controls(struct cpu_ctx* cpu) {
    IA32_VMX_TRUE_CTLS_REGISTER policy;
    IA32_VMX_PROCBASED_CTLS_REGISTER ctls = {.flags = 0};

    ctls.use_msr_bitmaps = 1;
    ctls.activate_secondary_controls = 1;

    APPLY_CTLS_POLICY(policy, cpu, ctls, PROCBASED)

    if (!ctls.use_msr_bitmaps || !ctls.activate_secondary_controls) {
        hv_utils_cpu_log(
            err, cpu, "unable to set all processor based controls in the VMCS");
        return -1;
    }
    return hv_arch_do_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                              ctls.flags);
}

static ssize_t setup_secondary_procbased_controls(struct cpu_ctx* cpu) {
    IA32_VMX_TRUE_CTLS_REGISTER policy = {
        .flags = native_read_msr(IA32_VMX_PROCBASED_CTLS2)};
    IA32_VMX_PROCBASED_CTLS2_REGISTER ctls = {.flags = 0};

    ctls.enable_rdtscp = 1;
    ctls.enable_invpcid = 1;
    ctls.enable_xsaves = 1;
    ctls.conceal_vmx_from_pt = 1;

    ctls.flags = set_required_bits(ctls.flags, policy.allowed_0_settings,
                                   policy.allowed_1_settings);
    return hv_arch_do_vmwrite(
        VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, ctls.flags);
}

static ssize_t setup_vmexit_controls(struct cpu_ctx* cpu) {
    IA32_VMX_TRUE_CTLS_REGISTER policy;
    ssize_t err = 0;
    IA32_VMX_EXIT_CTLS_REGISTER ctls = {.flags = 0};

    ctls.host_address_space_size = 1;
    ctls.conceal_vmx_from_pt = 1;

    APPLY_CTLS_POLICY(policy, cpu, ctls, EXIT)
    err |= hv_arch_do_vmwrite(VMCS_CTRL_VMEXIT_CONTROLS, ctls.flags);

    err |= hv_arch_do_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
    err |= hv_arch_do_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);
    return err;
}

static ssize_t setup_vmentry_controls(struct cpu_ctx* cpu) {
    IA32_VMX_TRUE_CTLS_REGISTER policy;
    ssize_t err = 0;
    IA32_VMX_ENTRY_CTLS_REGISTER ctls = {.flags = 0};

    ctls.ia32e_mode_guest = 1;
    ctls.conceal_vmx_from_pt = 1;

    APPLY_CTLS_POLICY(policy, cpu, ctls, ENTRY)
    err |= hv_arch_do_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, ctls.flags);
    err |=
        hv_arch_do_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);
    err |= hv_arch_do_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
    return err;
}

static ssize_t vmcs_control_fields_init(struct cpu_ctx* cpu) {
    ssize_t err = 0;
    err |= setup_pinbased_controls(cpu);
    err |= setup_procbased_controls(cpu);
    err |= setup_secondary_procbased_controls(cpu);
    err |= setup_vmexit_controls(cpu);
    err |= setup_vmentry_controls(cpu);

    err |= hv_arch_do_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, 0);

    err |= hv_arch_do_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
    err |= hv_arch_do_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);

    err |= hv_arch_do_vmwrite(VMCS_CTRL_CR3_TARGET_COUNT, 0);

    err |= hv_arch_do_vmwrite(VMCS_CTRL_MSR_BITMAP_ADDRESS,
                              (u64)cpu->msr_bitmap_ptr);

    err |= hv_arch_do_vmwrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
    err |= hv_arch_do_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, cpu->state.cr0.flags);
    err |= hv_arch_do_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0);
    err |= hv_arch_do_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, cpu->state.cr4.flags);

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
