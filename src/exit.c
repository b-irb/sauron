#include "exit.h"

#include <asm/fpu/internal.h>
#include <asm/paravirt.h>
#include <linux/types.h>

#include "arch.h"
#include "cpu.h"
#include "ia32.h"
#include "utils.h"
#include "vmx.h"
#include "vmxasm.h"

enum EXIT_RESULT { OK = 0, ERR = 1, DETACH = 2 };

static enum EXIT_RESULT detach_hypervisor(struct cpu_ctx* cpu,
                                          struct hv_exit_state* exit_state) {
    hv_utils_cpu_log(info, "VM-exit: detaching hypervisor from processor\n");

    cpu->resume_ip = hv_arch_vmread(VMCS_GUEST_RIP) +
                     hv_arch_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH);
    cpu->resume_sp = hv_arch_vmread(VMCS_GUEST_RSP);
    cpu->resume_flags = hv_arch_vmread(VMCS_GUEST_RFLAGS);

    write_cr3(hv_arch_vmread(VMCS_GUEST_CR3));

    if (hv_vmx_exit_root(cpu)) {
        hv_utils_cpu_log(crit, "VM-exit: failed to exit root operation\n");
    }

    return OK;
}

enum EXIT_RESULT handle_cpuid(struct cpu_ctx* cpu,
                              struct hv_exit_state* exit_state) {
    /* Avoid UB where the upper 32 bits are untouched. */
    unsigned int cpuid[4];
    unsigned int leaf = LOWER_DWORD(exit_state->rax);
    unsigned int subleaf = LOWER_DWORD(exit_state->rcx);

    if (leaf == HV_CPUID_DETACH_LEAF && subleaf == HV_CPUID_DETACH_SUBLEAF) {
        return DETACH;
    }

    cpuid_count(leaf, subleaf, &cpuid[0], &cpuid[1], &cpuid[2], &cpuid[3]);

    /* Report to guest that VMX is not supported. */
    if (leaf == CPUID_VERSION_INFORMATION) {
        hv_utils_cpu_log(debug,
                         "VM-exit: intercepting CPUID leaf=%x, subleaf=%x to "
                         "report no VMX\n",
                         leaf, subleaf);

        cpuid[2] &= ~(1UL << CPUID_VMX_ENABLED_BIT);
    }

    exit_state->rax = cpuid[0];
    exit_state->rbx = cpuid[1];
    exit_state->rcx = cpuid[2];
    exit_state->rdx = cpuid[3];
    return OK;
}

enum EXIT_RESULT handle_unknown_vmexit(VMX_VMEXIT_REASON reason) {
    hv_utils_cpu_log(info, "VM-exit: unknown exit reason: %x\n",
                     reason.basic_exit_reason);
    return ERR;
}

u8 hv_exit_vmexit_handler(struct cpu_ctx* cpu,
                          struct hv_exit_state* exit_state) {
    enum EXIT_RESULT state = OK;
    const VMX_VMEXIT_REASON vmexit_reason = {
        .flags = hv_arch_vmread(VMCS_EXIT_REASON)};

    switch (vmexit_reason.basic_exit_reason) {
        case VMX_EXIT_REASON_ERROR_INVALID_GUEST_STATE:
            hv_utils_cpu_log(info, "VM-entry: invalid guest state\n");
            state = ERR;
            break;
        case VMX_EXIT_REASON_ERROR_MSR_LOAD:
            hv_utils_cpu_log(info, "VM-entry: failed to load MSRs\n");
            state = ERR;
            break;

        /* Unconditional VM-exits. */
        case VMX_EXIT_REASON_EXTERNAL_INTERRUPT:
        /* Hardware task-switches are unsupported in 64-bit long-mode. This
         * should never cause a VM-exit. */
        case VMX_EXIT_REASON_TASK_SWITCH:
        case VMX_EXIT_REASON_TRIPLE_FAULT:
        case VMX_EXIT_REASON_INIT_SIGNAL:
        case VMX_EXIT_REASON_EXECUTE_VMCALL:
        case VMX_EXIT_REASON_EXECUTE_VMCLEAR:
        case VMX_EXIT_REASON_EXECUTE_VMLAUNCH:
        case VMX_EXIT_REASON_EXECUTE_VMPTRLD:
        case VMX_EXIT_REASON_EXECUTE_VMPTRST:
        case VMX_EXIT_REASON_EXECUTE_VMREAD:
        case VMX_EXIT_REASON_EXECUTE_VMRESUME:
        case VMX_EXIT_REASON_EXECUTE_VMWRITE:
        case VMX_EXIT_REASON_EXECUTE_VMXOFF:
        case VMX_EXIT_REASON_EXECUTE_INVEPT:
        case VMX_EXIT_REASON_EXECUTE_VMFUNC:
        case VMX_EXIT_REASON_EXECUTE_INVVPID:
        case VMX_EXIT_REASON_EXECUTE_GETSEC:
            break;
        case VMX_EXIT_REASON_EXECUTE_CPUID:
            state = handle_cpuid(cpu, exit_state);
            break;
        case VMX_EXIT_REASON_EXECUTE_INVD:
            wbinvd();
            break;
        case VMX_EXIT_REASON_EXECUTE_XSETBV:
            xsetbv(LOWER_DWORD(exit_state->rcx),
                   (exit_state->rdx << 32) | LOWER_DWORD(exit_state->rax));
            break;
        default:
            state = handle_unknown_vmexit(vmexit_reason);
    }

    switch (state) {
        case OK:
            hv_arch_vmwrite(VMCS_GUEST_RIP,
                            hv_arch_vmread(VMCS_GUEST_RIP) +
                                hv_arch_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH));
            break;
        case ERR:
            hv_utils_cpu_log(err, "VM-exit: an error occured\n");
            break;
        case DETACH:
            detach_hypervisor(cpu, exit_state);
            break;
    }
    return state;
}

u8 hv_exit_vmexit_failure(struct hv_exit_state* exit_state) { return 0; }
