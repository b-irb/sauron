#include "vmcs.h"

#include <asm/desc.h>
#include <asm/io.h>
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
        hv_utils_cpu_log(err, "unable to allocate VMCS region\n");
        return NULL;
    }

    memset(vmcs_region, 0x0, VMCS_REGION_REQUIRED_BYTES);

    vmcs_region->revision_id = (u32)cpu->vmm->vmx_capabilities.vmcs_revision_id;
    vmcs_region->shadow_vmcs_indicator = 0;
    return vmcs_region;
}

#define SETUP_REGION_SEGMENT_SELECTOR_NO_BASE(region, _selector, descriptor) \
    err |= hv_arch_vmwrite(VMCS_##region##_##_selector##_SELECTOR,           \
                           descriptor.selector.flags);                       \
    err |= hv_arch_vmwrite(VMCS_##region##_##_selector##_LIMIT,              \
                           descriptor.limit);                                \
    err |= hv_arch_vmwrite(VMCS_##region##_##_selector##_ACCESS_RIGHTS,      \
                           descriptor.access_rights.flags);

#define SETUP_REGION_SEGMENT_SELECTOR_BASE(region, selector, descriptor) \
    err |= hv_arch_vmwrite(VMCS_##region##_##selector##_BASE,            \
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

#define SETUP_HOST_SEGMENT_SELECTOR(_selector, descriptor)   \
    err |= hv_arch_vmwrite(VMCS_HOST_##_selector##_SELECTOR, \
                           descriptor.selector.flags);

static ssize_t validate_vmcs_host_state(void) {
    ssize_t err = 0;
    SEGMENT_SELECTOR selector;
    const IA32_EFER_REGISTER efer = {.flags = native_read_msr(IA32_EFER)};
    const IA32_VMX_EXIT_CTLS_REGISTER vmexit_ctls = {
        .flags = hv_arch_vmread(VMCS_CTRL_VMEXIT_CONTROLS)};
    const IA32_VMX_ENTRY_CTLS_REGISTER vmentry_ctls = {
        .flags = hv_arch_vmread(VMCS_CTRL_VMENTRY_CONTROLS)};
    const CR0 cr0 = {.flags = hv_arch_vmread(VMCS_HOST_CR0)};
    const CR4 cr4 = {.flags = hv_arch_vmread(VMCS_HOST_CR4)};
    const CR3 cr3 = {.flags = hv_arch_vmread(VMCS_HOST_CR3)};
    /* Checks on Host Control Reigsters, MSRs, and SSP */

    /* Assume CR0 and CR4 have been fixed using IA32_CR(0,4)_FIXED(0,1) MSRs. */

    /* If bit 23 in the CR4 field (corresponding to CET) is 1, bit 16 in the CR0
     * field (WP) must also be 1. */
    if ((cr4.flags & (1 << 23)) && !cr0.write_protect) {
        hv_utils_cpu_log(
            err, "VMCS HOST: CET is enabled (CR4) but WP is disabled (CR0)\n");
        err = -1;
    }

    /* On processors that support Intel 64 architecture, the CR3 field must be
     * such that bits 63:32 beyond the processor’s physical-address width must
     * be 0. */
    if (cr3.flags >> (cpuid_eax(CPUID_PHYS_ADDR_WIDTH_LEAF) & 0xff)) {
        hv_utils_cpu_log(err,
                         "VMCS HOST: CR3 has bits set beyond the processor's "
                         "physical-address width\n");
        err = -1;
    }

    /* On processors that support Intel 64 architecture, the IA32_SYSENTER_ESP
     * field and the IA32_SYSENTER_EIP field must each contain a canonical
     * address. */
    if (!hv_utils_is_canonical(hv_arch_vmread(VMCS_HOST_SYSENTER_CS))) {
        hv_utils_cpu_log(
            err,
            "VMCS HOST: IA32_SYSENTER_CS does not have canonical address\n");
        err = -1;
    }

    if (!hv_utils_is_canonical(hv_arch_vmread(VMCS_HOST_SYSENTER_ESP))) {
        hv_utils_cpu_log(
            err,
            "VMCS HOST: IA32_SYSENTER_ESP does not have canonical address\n");
        err = -1;
    }

    /* If the "load IA32_PERF_GLOBAL_CTRL" VM-exit control is 1, bits reserved
     * in the IA32_PERF_GLOBAL_CTRL MSR must be 0 in the field for that
     * register. */
    /*
     *if (vmexit_ctls.load_ia32_perf_global_ctrl &&
     *    !((IA32_PERF_GLOBAL_CTRL_REGISTER)hv_arch_vmread(
     *          VMCS_HOST_PERF_GLOBAL_CTRL))
     *         .en_fixed_ctrn) {
     *    hv_utils_cpu_log(
     *        err,
     *        "VMCS HOST: load IA32_PERF_GLOBAL_CTRL VM-exit control is 1, bits
     *" "reserved in the IA32_PERF_GLOBAL_CTRL MSR must be 0 in the field " "for
     *that register\n"); err = -1;
     *}
     */

    /* If the "load IA32_PAT" VM-exit control is 1, the value of the field for
     * the IA32_PAT MSR must be one that could be written by WRMSR without fault
     * at CPL 0. Specifically, each of the 8 bytes in the field must have one of
     * the values 0 (UC), 1 (WC), 4 (WT), 5 (WP), 6 (WB), or 7 (UC-). */
    if (vmexit_ctls.load_ia32_pat &&
        !(hv_arch_vmread(VMCS_HOST_PAT) & 0xf8f8f8f8f8f8f8f8)) {
        hv_utils_cpu_log(err,
                         "VMCS HOST: IA32_PAT MSR field value will cause fault "
                         "at CPL0 upon WRMSR\n");
        err = -1;
    }

    /* TODO: verify IA32_EFER, CET state, IA32_PKRS */

    /* Checks on Host Segment and Descriptor-Table Registers */

    selector.flags = hv_arch_vmread(VMCS_HOST_CS_SELECTOR) |
                     hv_arch_vmread(VMCS_HOST_SS_SELECTOR) |
                     hv_arch_vmread(VMCS_HOST_DS_SELECTOR) |
                     hv_arch_vmread(VMCS_HOST_ES_SELECTOR) |
                     hv_arch_vmread(VMCS_HOST_FS_SELECTOR) |
                     hv_arch_vmread(VMCS_HOST_GS_SELECTOR) |
                     hv_arch_vmread(VMCS_HOST_TR_SELECTOR);
    if (selector.request_privilege_level || selector.table) {
        hv_utils_cpu_log(
            err, "VMCS HOST: selector fields cannot have RPL or TI bits set\n");
        err = -1;
    }

    if (!hv_arch_vmread(VMCS_HOST_CS_SELECTOR) ||
        !hv_arch_vmread(VMCS_HOST_TR_SELECTOR)) {
        hv_utils_cpu_log(
            err, "VMCS HOST: selector fields: SS and TR, cannot be null\n");
        err = -1;
    }

    if (!vmexit_ctls.host_address_space_size &&
        !hv_arch_vmread(VMCS_HOST_SS_SELECTOR)) {
        hv_utils_cpu_log(
            err,
            "VMCS HOST: the selector field SS cannot be null if \"host "
            "address-space size\" VM-exit control is disabled\n");
        err = -1;
    }

    if (!(hv_utils_is_canonical(hv_arch_vmread(VMCS_HOST_FS_BASE)) &&
          hv_utils_is_canonical(hv_arch_vmread(VMCS_HOST_GS_BASE)) &&
          hv_utils_is_canonical(hv_arch_vmread(VMCS_HOST_GDTR_BASE)) &&
          hv_utils_is_canonical(hv_arch_vmread(VMCS_HOST_IDTR_BASE)) &&
          hv_utils_is_canonical(hv_arch_vmread(VMCS_HOST_TR_BASE)))) {
        hv_utils_cpu_log(err,
                         "VMCS HOST: base address fields for FS, GS, GDTR, "
                         "IDTR, and TR must contain canonical addresses\n");
        err = -1;
    }

    if (!efer.ia32e_mode_active && (vmentry_ctls.ia32e_mode_guest ||
                                    vmexit_ctls.host_address_space_size)) {
        hv_utils_cpu_log(
            err,
            "VMCS HOST: if IA32_EFER.LMA is cleared, VM-entry IA-32e guest and "
            "host address space entry controls must also be cleared\n");
        err = -1;
    }

    if (efer.ia32e_mode_active && !vmexit_ctls.host_address_space_size) {
        hv_utils_cpu_log(
            err,
            "VMCS HOST: if the logical processor is in IA-32e mode at "
            "VM-entry, the host address space control must be set\n");
        err = -1;
    }

    /* TODO host address space control field consistency checks */
    /*
     *if (!vmentry_ctls.host_address_space_size &&
     *    (vmentry_ctls.ia32e_mode_guest || cr4.pcid_enable ||
     *     hv_arch_vmread(VMCS_HOST_RIP) >> 32)) {
     *    hv_utils_cpu_log(
     *        err,
     *        "VMCS HOST: if host address space control is clear, ia-32e mode "
     *        "guest must be clear, PCIDE in CR4 must be clear, and the upper 32
     *" "bits of RIP field must be clear\n"); err = -1;
     *}
     */
    return err;
}

#define _check_base_addr(segm)                                                \
    if (!state->seg_##segm.access_rights.unusable &&                          \
        state->seg_##segm.base_address >> 32) {                               \
        hv_utils_cpu_log(                                                     \
            err, "VMCS GUEST: upper 32 bits of " TOSTRING(                    \
                     segm) " base address must be 0 if segment is usable\n"); \
        err = -1;                                                             \
    }

#define _check_ar_type(segm)                                                \
    if (!state->seg_##segm.access_rights.unusable) {                        \
        if ((state->seg_##segm.access_rights.type & 0x1) != 1) {            \
            hv_utils_cpu_log(                                               \
                err,                                                        \
                "VMCS GUEST: if " TOSTRING(                                 \
                    segm) " is usable the access rights type must be 1\n"); \
            err = -1;                                                       \
        } else if ((state->seg_##segm.access_rights.type >> 2) & 0x1 &&     \
                   (state->seg_##segm.access_rights.type & 0x1) == 0) {     \
            hv_utils_cpu_log(err,                                         \
                             "VMCS GUEST: if " TOSTRING(segm) " is usable and is a code " \
                             "segment, it must be readable\n"); \
            err = -1;                                                       \
        }                                                                   \
    }

#define _check_ar_system(segm)                                                \
    if (!state->seg_##segm.access_rights.unusable &&                          \
        !state->seg_##segm.access_rights.descriptor_type) {                   \
        hv_utils_cpu_log(err,                                                 \
                         "VMCS GUEST: " TOSTRING(                             \
                             segm) " is usable but table flag is cleared\n"); \
        err = -1;                                                             \
    }

static ssize_t validate_vmcs_guest_state(struct hv_arch_cpu_state* state) {
    ssize_t err = 0;
    const IA32_VMX_PROCBASED_CTLS2_REGISTER proc2_ctls = {
        .flags = hv_arch_vmread(
            VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS)};
    const CR0 cr0 = {.flags = hv_arch_vmread(VMCS_GUEST_CR0)};
    const CR4 cr4 = {.flags = hv_arch_vmread(VMCS_GUEST_CR4)};

    /* Assume CR0 and CR4 have been fixed using IA32_CR(0,4)_FIXED(0,1) MSRs. */

    if (cr0.paging_enable && !cr0.protection_enable) {
        hv_utils_cpu_log(
            err,
            "VMCS GUEST: if bit 31 in the CR0 field (corresponding to PG) is "
            "1, bit 0 in that field (PE) must also be 1\n");
        err = -1;
    }

    if ((cr4.flags >> 23) & 0x1 && !cr0.write_protect) {
        hv_utils_cpu_log(
            err,
            "VMCS GUEST: if bit 23 in the CR4 field (corresponding to CET) is "
            "1, bit 16 in the CR0 field (WP) must also be 1\n");
        err = -1;
    }

    /* TODO debug controls, x64 support, IA32_PERF_GLOBAL_CTRL, IA32_PAT,
     * IA32_EFER, IA32_BNDCFGS, IA32_RTIT_CTL, CET, PKRS */

    /* Checks on Guest Segment Registers */

    if (state->task_register.selector.table) {
        hv_utils_cpu_log(err, "VMCS GUEST: TI flag in TR must be 0\n");
        err = -1;
    }

    if (!state->ldtr.access_rights.unusable && state->ldtr.selector.table) {
        hv_utils_cpu_log(err,
                         "VMCS GUEST: if LDTR is usable, TI flag must be 0\n");
        err = -1;
    }

    if (!proc2_ctls.unrestricted_guest &&
        /* ignore virtual-8086 mode */ (
            state->seg_ss.selector.request_privilege_level !=
            state->seg_cs.selector.request_privilege_level)) {
        hv_utils_cpu_log(
            err,
            "VMCS GUEST: if guest not in virtual-8086 mode and unrestricted "
            "guest is enabled, SS and CS, RPL must be equal\n");
        err = -1;
    }

    if (!hv_utils_is_canonical(state->task_register.base_address) ||
        !hv_utils_is_canonical(state->seg_fs_base) ||
        !hv_utils_is_canonical(state->seg_gs_base)) {
        hv_utils_cpu_log(
            err,
            "VMCS GUEST: TR, FS, and GS, base addresses must be canonical\n");
        err = -1;
    }

    if (!state->ldtr.access_rights.unusable &&
        !hv_utils_is_canonical(state->ldtr.base_address)) {
        hv_utils_cpu_log(
            err,
            "VMCS GUEST: if LDTR is usable, base address must be canonical\n");
        err = -1;
    }

    if (state->seg_cs.base_address >> 32) {
        hv_utils_cpu_log(
            err, "VMCS GUEST: upper 32 bits of CS base address must be 0\n");
        err = -1;
    }

    _check_base_addr(ss);
    _check_base_addr(ds);
    _check_base_addr(es);

    if (!(state->seg_cs.access_rights.type == 9 ||
          state->seg_cs.access_rights.type == 11 ||
          state->seg_cs.access_rights.type == 13 ||
          state->seg_cs.access_rights.type == 15)) {
        if (proc2_ctls.unrestricted_guest &&
            state->seg_cs.access_rights.type != 3) {
            hv_utils_cpu_log(
                err,
                "VMCS GUEST: if unrestricted guest VM-execution control is "
                "set, CS must have an access rights type of 3, 9, 11, 13, or "
                "15 (actual value "
                "%u)\n",
                state->seg_cs.access_rights.type);
        } else {
            hv_utils_cpu_log(
                err,
                "VMCS GUEST: if unrestricted guest VM-execution control is not "
                "set, CS must have an access rights type of 9, 11, 13, or 15 "
                "(actual value %u)\n",
                state->seg_cs.access_rights.type);
        }
        err = -1;
    }

    if (!state->seg_ss.access_rights.unusable &&
        !(state->seg_ss.access_rights.type == 3 ||
          state->seg_ss.access_rights.type == 7)) {
        hv_utils_cpu_log(err,
                         "VMCS GUEST: if SS is usable, the type must be 3 or 7 "
                         "(actual %u)\n",
                         state->seg_ss.access_rights.type);
        err = -1;
    }

    _check_ar_type(ds);
    _check_ar_type(es);
    _check_ar_type(fs);
    _check_ar_type(gs);

    _check_ar_system(ss);
    _check_ar_system(ds);
    _check_ar_system(es);
    _check_ar_system(fs);
    _check_ar_system(gs);

    if (!state->seg_cs.access_rights.descriptor_type) {
        hv_utils_cpu_log(err, "VMCS GUEST: CS must have the table flag set\n");
        err = -1;
    }

    return err;
}

static ssize_t validate_vmcs(struct hv_arch_cpu_state* state) {
    ssize_t err = 0;
    hv_utils_cpu_log(debug, "validating VMCS\n");
    err |= validate_vmcs_host_state();
    err |= validate_vmcs_guest_state(state);
    return err;
}

static ssize_t vmcs_host_state_area_init(struct cpu_ctx* cpu) {
    struct hv_arch_cpu_state state = cpu->state;
    ssize_t err = 0;

    /* Processor state is loaded from these fields on every VM-exit. */

    err |= hv_arch_vmwrite(VMCS_HOST_CR0, state.cr0.flags);
    err |= hv_arch_vmwrite(VMCS_HOST_CR4, state.cr4.flags);
    err |= hv_arch_vmwrite(VMCS_HOST_CR3, state.cr3.flags);

    err |= hv_arch_vmwrite(VMCS_HOST_RIP, (u64)cpu->vmexit_handler);
    err |= hv_arch_vmwrite(VMCS_HOST_RSP, (u64)&cpu->vmexit_stack->cpu);

    SETUP_HOST_SEGMENT_SELECTOR(CS, state.seg_cs);
    SETUP_HOST_SEGMENT_SELECTOR(DS, state.seg_ds);
    SETUP_HOST_SEGMENT_SELECTOR(ES, state.seg_es);
    SETUP_HOST_SEGMENT_SELECTOR(SS, state.seg_ss);
    SETUP_HOST_SEGMENT_SELECTOR(FS, state.seg_fs);
    SETUP_HOST_SEGMENT_SELECTOR(GS, state.seg_gs);
    SETUP_HOST_SEGMENT_SELECTOR(TR, state.task_register);

    err |= hv_arch_vmwrite(VMCS_HOST_FS_BASE, state.seg_fs_base);
    err |= hv_arch_vmwrite(VMCS_HOST_GS_BASE, state.seg_gs_base);

    err |= hv_arch_vmwrite(VMCS_HOST_TR_BASE, state.task_register.base_address);

    err |= hv_arch_vmwrite(VMCS_HOST_GDTR_BASE, state.gdtr.base_address);
    err |= hv_arch_vmwrite(VMCS_HOST_IDTR_BASE, state.idtr.base_address);

    err |= hv_arch_vmwrite(VMCS_HOST_SYSENTER_CS, state.sysenter_cs);
    err |= hv_arch_vmwrite(VMCS_HOST_SYSENTER_EIP, state.sysenter_eip);
    err |= hv_arch_vmwrite(VMCS_HOST_SYSENTER_ESP, state.sysenter_esp);

    return err;
}

static ssize_t vmcs_guest_state_area_init(struct cpu_ctx* cpu) {
    struct hv_arch_cpu_state state = cpu->state;
    ssize_t err = 0;

    /* Guest Register State */

    err |= hv_arch_vmwrite(VMCS_GUEST_CR0, state.cr0.flags);
    err |= hv_arch_vmwrite(VMCS_GUEST_CR3, state.cr3.flags);
    err |= hv_arch_vmwrite(VMCS_GUEST_CR4, state.cr4.flags);
    err |= hv_arch_vmwrite(VMCS_GUEST_DR7, state.dr7.flags);

    err |= hv_arch_vmwrite(VMCS_GUEST_RIP, cpu->resume_ip);
    err |= hv_arch_vmwrite(VMCS_GUEST_RSP, cpu->resume_sp);
    /* RFLAGS is overwritten in VMX guest entry on VMLAUNCH so we use a
     * valid RFLAGS placeholder value. */
    err |= hv_arch_vmwrite(VMCS_GUEST_RFLAGS, cpu->resume_flags);

    SETUP_GUEST_SEGMENT_SELECTOR(CS, state.seg_cs);
    SETUP_GUEST_SEGMENT_SELECTOR(DS, state.seg_ds);
    SETUP_GUEST_SEGMENT_SELECTOR(ES, state.seg_es);
    SETUP_GUEST_SEGMENT_SELECTOR(SS, state.seg_ss);
    SETUP_GUEST_SEGMENT_SELECTOR(LDTR, state.ldtr);
    SETUP_GUEST_SEGMENT_SELECTOR(TR, state.task_register);

    SETUP_GUEST_SEGMENT_SELECTOR_NO_BASE(FS, state.seg_fs);
    SETUP_GUEST_SEGMENT_SELECTOR_NO_BASE(GS, state.seg_gs);
    err |= hv_arch_vmwrite(VMCS_GUEST_FS_BASE, state.seg_fs_base);
    err |= hv_arch_vmwrite(VMCS_GUEST_GS_BASE, state.seg_gs_base);

    err |= hv_arch_vmwrite(VMCS_GUEST_GDTR_BASE, state.gdtr.base_address);
    err |= hv_arch_vmwrite(VMCS_GUEST_GDTR_LIMIT, state.gdtr.limit);
    err |= hv_arch_vmwrite(VMCS_GUEST_IDTR_BASE, state.idtr.base_address);
    err |= hv_arch_vmwrite(VMCS_GUEST_IDTR_LIMIT, state.idtr.limit);

    err |= hv_arch_vmwrite(VMCS_GUEST_DEBUGCTL, state.debugctl);
    err |= hv_arch_vmwrite(VMCS_GUEST_SYSENTER_CS, state.sysenter_cs);
    err |= hv_arch_vmwrite(VMCS_GUEST_SYSENTER_EIP, state.sysenter_eip);
    err |= hv_arch_vmwrite(VMCS_GUEST_SYSENTER_ESP, state.sysenter_esp);

    /* Guest Non-Register State */

    /* Activity state identifies the logical processors activity state. When
     * a logical processor is executing instructions normally, it is in
     * active state. Execution of certain instructions and the occurrence of
     * certain events may cause a logical processor to transition to an
     * inactivestate in which is ceases to execute instructions.
     *
     * 0: Active. The logical processor is executing instructions normally.
     */
    err |= hv_arch_vmwrite(VMCS_GUEST_ACTIVITY_STATE, vmx_active);
    /* Interruptability state denotes what events are blocked for certain
     * periods of time.
     *
     * 0: Blocking by STI. Execution of STI with RFLAGS.IF = 0 blocks
     * maskable interrupts on the instruction boundary following its
     * execution. Setting this bit indicates that this blocking is in
     * effect. */
    err |= hv_arch_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);
    /* Pending debug exceptions contains information about debug exceptions.
     * It is set to 0 because there are no pending debug exception
     * information. */
    err |= hv_arch_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);
    /* VMCS link pointer points to an additional VMCS which is accessed with
     * vmread and vmwrite if "VMCS shadowing" VM-execution control is 1. The
     * link pointer should be set to ~0UL to avoid VM-entry failures. */
    err |= hv_arch_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL);
    return err;
}

static ssize_t setup_pinbased_controls(struct cpu_ctx* cpu) {
    /* The pin-based VM-execution controls constitute a 32-bit vector that
     * governs the handling of asynchronous events in VMX non-root operation. */
    IA32_VMX_TRUE_CTLS_REGISTER policy;
    IA32_VMX_PINBASED_CTLS_REGISTER ctls = {};

    APPLY_CTLS_POLICY(policy, cpu, ctls, PINBASED)
    return hv_arch_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS,
                           ctls.flags);
}

static ssize_t setup_procbased_controls(struct cpu_ctx* cpu) {
    /* The processor-based VM-execution controls constitute two 32-bit vectors
     * that govern the handling of synchronous events, mainly those caused by
     * the execution of specific instructions in VMX non-root operation. */
    IA32_VMX_TRUE_CTLS_REGISTER policy;
    IA32_VMX_PROCBASED_CTLS_REGISTER ctls = {};

    /* Use MSR bitmaps to control execution of RDMSR and WRMSR instructions. */
    ctls.use_msr_bitmaps = 1;
    ctls.activate_secondary_controls = 1;

    APPLY_CTLS_POLICY(policy, cpu, ctls, PROCBASED)

    if (!ctls.use_msr_bitmaps || !ctls.activate_secondary_controls) {
        hv_utils_cpu_log(err,
                         "unable to set required processor-based VM execution "
                         "controls in the VMCS");
        return -1;
    }
    return hv_arch_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                           ctls.flags);
}

static ssize_t setup_secondary_procbased_controls(struct cpu_ctx* cpu) {
    /* The secondary processor-based VM-execution controls constitute two 32-bit
     * vectors that govern the handling of synchronous events, mainly those
     * caused by the execution of specific instructions in VMX non-root
     * operation. */
    IA32_VMX_TRUE_CTLS_REGISTER policy = {
        .flags = native_read_msr(IA32_VMX_PROCBASED_CTLS2)};
    IA32_VMX_PROCBASED_CTLS2_REGISTER ctls = {};

    /* Enable RDTSCP to not cause an invalid-opcode exception (#UD). */
    ctls.enable_rdtscp = 1;
    /* Enable INVPCID to not cause an invalid-opcode exception (#UD). */
    ctls.enable_invpcid = 1;
    /* Intel Processor Trace suppresses from PIPs an indication that the
     * processor was in VMX non-root operation and omits a VMCS packet from any
     * PSB+ produced in VMX non-root operation. */
    ctls.conceal_vmx_from_pt = 1;
    /* The Linux kernel will use xsave/xrstor to save/restore processor state
     * during a context switch (i.e. task scheduling or signal triggering). If
     * the control is disabled and the processor does support XSAVE extensions,
     * the kernel _will_ attempt to use them during these events which will
     * invariably cause a #UD - an instant crash.
     *
     * Additional Notes:
     * It appears nested KVM QEMU (-enable-kvm) and VirtualBox will modify
     * IA32_VMX_PROCBASED_CTLS2 to forcibly disable the enable_xsaves control
     * field. However, if the processor model you are emulating
     * supports XSAVE then the next task switch after VMLAUNCH will cause a #UD.
     * Currently, I am not aware of any fixes without investigating the
     * hypervisor sources themselves.
     *
     * However, VMware works. */
    ctls.enable_xsaves = 1;

    ctls.flags = set_required_bits(ctls.flags, policy.allowed_0_settings,
                                   policy.allowed_1_settings);
    return hv_arch_vmwrite(
        VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, ctls.flags);
}

static ssize_t setup_vmexit_controls(struct cpu_ctx* cpu) {
    /* The VM-exit controls constitute a 32-bit vector that governs the basic
     * operation of VM exits. */
    IA32_VMX_TRUE_CTLS_REGISTER policy;
    ssize_t err = 0;
    IA32_VMX_EXIT_CTLS_REGISTER ctls = {};

    /* Place the logical processor in 64-bit mode after the next VM exit. Its
     * value is loaded into CS.L, IA32_EFER.LME, and IA32_EFER.LMA on every VM
     * exit. */
    ctls.host_address_space_size = 1;
    /* Intel Processor Trace does not produce a paging information packet (PIP)
     * on a VM exit or a VMCS packet on an SMM VM exit. */
    ctls.conceal_vmx_from_pt = 1;

    APPLY_CTLS_POLICY(policy, cpu, ctls, EXIT)
    err |= hv_arch_vmwrite(VMCS_CTRL_VMEXIT_CONTROLS, ctls.flags);

    /* Specified number of MSRs to be stored on VM exit. */
    err |= hv_arch_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
    /* Specified number of MSRs to be loaded on VM exit. */
    err |= hv_arch_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);
    return err;
}

static ssize_t setup_vmentry_controls(struct cpu_ctx* cpu) {
    /* The VM-entry controls constitute a 32-bit vector that governs the basic
     * operation of VM entries. */
    IA32_VMX_TRUE_CTLS_REGISTER policy;
    ssize_t err = 0;
    IA32_VMX_ENTRY_CTLS_REGISTER ctls = {};

    /* Place the logical processor in IA-32e mode after VM entry. Its value
     * is loaded into IA32_EFER.LMA as part of VM entry. */
    ctls.ia32e_mode_guest = 1;
    /* Intel Processor Trace does not produce a paging information packet (PIP)
     * on a VM entry or a VMCS packet on a VM entry that returns from SMM. */
    ctls.conceal_vmx_from_pt = 1;

    APPLY_CTLS_POLICY(policy, cpu, ctls, ENTRY)
    err |= hv_arch_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, ctls.flags);

    /* Specified number of MSRs to be loaded on VM entry. */
    err |= hv_arch_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
    /* Do not deliver interrupt through guest IDT after VM-entry. */
    err |= hv_arch_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);
    return err;
}

static ssize_t vmcs_control_fields_init(struct cpu_ctx* cpu) {
    ssize_t err = 0;
    err |= setup_pinbased_controls(cpu);
    err |= setup_procbased_controls(cpu);
    err |= setup_secondary_procbased_controls(cpu);
    err |= setup_vmexit_controls(cpu);
    err |= setup_vmentry_controls(cpu);

    /* The exception bitmap is a 32-bit field that contains one bit for each
     * exception. When an exception occurs, its vector is used to select a bit
     * in this field. If the bit is 1, the exception causes a VM exit. If the
     * bit is 0, the exception is delivered normally through the IDT, using the
     * descriptor corresponding to the exception’s vector. */
    err |= hv_arch_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, 0);
    /* VM-exit on all page-faults allowed through the exception bitmap. */
    err |= hv_arch_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
    err |= hv_arch_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);

    /* If the CR3-target count is 0, MOV to CR3 always causes a VM exit. */
    err |= hv_arch_vmwrite(VMCS_CTRL_CR3_TARGET_COUNT, 0);

    /* On processors that support the 1-setting of the “use MSR bitmaps”
     * VM-execution control, the VM-execution control fields include the 64-bit
     * physical address of four contiguous MSR bitmaps, which are each 1-KByte
     * in size. */
    err |= hv_arch_vmwrite(VMCS_CTRL_MSR_BITMAP_ADDRESS,
                           (u64)virt_to_phys(cpu->msr_bitmap));

    /* These fields control executions of instructions that access those
     * registers (including CLTS, LMSW, MOV CR, and SMSW).
     *
     * In general, bits set to 1 in a guest/host mask correspond to bits “owned”
     * by the host:
     * - Guest attempts to set them (using CLTS, LMSW, or MOV to CR) to values
     * differing from the corresponding bits in the corresponding read shadow
     * cause VM exits.
     * - Guest reads (using MOV from CR or SMSW) return values for these bits
     * from the corresponding read shadow.
     *
     * Bits cleared to 0 correspond to bits “owned” by the guest; guest attempts
     * to modify them succeed and guest reads return values for these bits from
     * the control register itself. */
    err |= hv_arch_vmwrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
    err |= hv_arch_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, cpu->state.cr0.flags);
    err |= hv_arch_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0);
    err |= hv_arch_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, cpu->state.cr4.flags);

    return err;
}

ssize_t hv_vmcs_vmcs_init(struct cpu_ctx* cpu) {
    ssize_t err = 0;

    if ((err = vmcs_guest_state_area_init(cpu))) {
        hv_utils_cpu_log(err, "failed to setup VMCS guest state\n");
        return err;
    }
    if ((err = vmcs_host_state_area_init(cpu))) {
        hv_utils_cpu_log(err, "failed to setup VMCS host state\n");
        return err;
    }

    if ((err = vmcs_control_fields_init(cpu))) {
        hv_utils_cpu_log(err, "failed to setup VMCS control fields\n");
        return err;
    }

    /* VMCS should be loaded onto processor. */
    if ((err = validate_vmcs(&cpu->state))) {
        hv_utils_cpu_log(err, "VMCS is invalid\n");
        return err;
    }
    hv_utils_cpu_log(debug, "VMCS successfully validated\n");
    return err;
}
