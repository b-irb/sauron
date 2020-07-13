#include "vmcs.h"

#include <asm/desc.h>
#include <asm/processor.h>
#include <linux/sched.h>
#include <linux/types.h>

#include "arch.h"
#include "cpu.h"
#include "ia32.h"
#include "utils.h"
#include "vmm.h"

void hv_vmcs_vmcs_destroy(VMCS* vmcs) {
    free_pages_exact(vmcs, VMCS_REGION_REQUIRED_PAGES);
}

VMCS* hv_vmcs_vmcs_alloc(struct cpu_ctx* cpu) {
    VMCS* vmcs_region;

    if (!(vmcs_region =
              alloc_pages_exact(VMCS_REGION_REQUIRED_PAGES, GFP_KERNEL))) {
        hv_utils_cpu_log(err, cpu, "unable to allocate VMCS region\n");
        return NULL;
    }

    memset(vmcs_region, 0x0, VMCS_REGION_REQUIRED_BYTES);
    return vmcs_region;
}

#define SETUP_REGION_SEGMENT_SELECTOR_NO_BASE(region, selector, value)    \
    hv_arch_read_seg_descriptor(&seg_desc, gdtr, value);                  \
    err |= hv_arch_do_vmwrite(VMCS_##region##_##selector##_SELECTOR,      \
                              value.flags);                               \
    err |= hv_arch_do_vmwrite(VMCS_##region##_##selector##_LIMIT,         \
                              seg_desc.limit);                            \
    err |= hv_arch_do_vmwrite(VMCS_##region##_##selector##_ACCESS_RIGHTS, \
                              seg_desc.access_rights.flags);

#define SETUP_REGION_SEGMENT_SELECTOR_BASE(region, selector, value) \
    hv_arch_read_seg_descriptor(&seg_desc, gdtr, value);            \
    err |= hv_arch_do_vmwrite(VMCS_##region##_##selector##_BASE,    \
                              seg_desc.base_address);

#define SETUP_REGION_SEGMENT_SELECTOR(region, selector, value)     \
    SETUP_REGION_SEGMENT_SELECTOR_NO_BASE(region, selector, value) \
    SETUP_REGION_SEGMENT_SELECTOR_BASE(region, selector, value)

#define SETUP_GUEST_SEGMENT_SELECTOR(selector, value) \
    SETUP_REGION_SEGMENT_SELECTOR(GUEST, selector, value)
#define SETUP_GUEST_SEGMENT_SELECTOR_NO_BASE(selector, value) \
    SETUP_REGION_SEGMENT_SELECTOR_NO_BASE(GUEST, selector, value)

static ssize_t vmcs_host_state_area_init(struct cpu_ctx* cpu) {
    ssize_t err = 0;
    return err;
}

static ssize_t vmcs_guest_state_area_init(struct cpu_ctx* cpu) {
    struct hv_arch_segment_descriptor seg_desc;
    struct hv_arch_cpu_state state = cpu->state;
    SEGMENT_DESCRIPTOR_REGISTER_64 gdtr = state.gdtr;
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
    SETUP_GUEST_SEGMENT_SELECTOR(TR, state.task_register);

    SETUP_GUEST_SEGMENT_SELECTOR_NO_BASE(FS, state.seg_cs);
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

    /*
     *if ((err = vmcs_vm_exec_ctrl_fields_init(cpu_ctx))) {
     *    utils_cpu_log(err, "failed to setup VMCS VM execution control
     *fields\n", cpu_ctx); return err;
     *}
     *if ((err = vmcs_vm_exit_ctrl_fields_init(cpu_ctx))) {
     *    utils_cpu_log(err, "failed to setup VMCS VM exit control fields\n",
     *                  cpu_ctx);
     *    return err;
     *}
     *if ((err = vmcs_vm_entry_ctrl_fields_init(cpu_ctx))) {
     *    utils_cpu_log(err, "failed to setup VMCS VM entry control fields\n",
     *                  cpu_ctx);
     *    return err;
     *}
     *if ((err = vmcs_vm_exit_info_fields_init(cpu_ctx))) {
     *    utils_cpu_log(err, "failed to setup VMCS VM exit info fields\n",
     *                  cpu_ctx);
     *    return err;
     *}
     */

    return err;
}
