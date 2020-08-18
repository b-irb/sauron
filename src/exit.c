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

static void advance_guest(void) {
    hv_arch_vmwrite(VMCS_GUEST_RIP,
                    hv_arch_vmread(VMCS_GUEST_RIP) +
                        hv_arch_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH));
}

static void detach_hypervisor(struct cpu_ctx* cpu,
                              struct hv_exit_state* exit_state) {
    u64 guest_cr3 = hv_arch_vmread(VMCS_GUEST_CR3);
    hv_utils_cpu_log(info, "VM-exit: detaching hypervisor from processor\n");

    advance_guest();
    cpu->resume_ip = hv_arch_vmread(VMCS_GUEST_RIP);
    cpu->resume_sp = hv_arch_vmread(VMCS_GUEST_RSP);
    cpu->resume_flags = hv_arch_vmread(VMCS_GUEST_RFLAGS);

    if (hv_vmx_exit_root(cpu)) {
        hv_utils_cpu_log(crit, "VM-exit: failed to exit root operation\n");
        /* If this occurs, we're totally fucked. */
    }

    /* Replace %rax with pointer to exit_state to retrieve structure locations
     * in assembly routine. */
    exit_state->rax = (u64)cpu;
    /* We may be invoked from a user-mode process which requires us to restore
     * CR3. */
    write_cr3(guest_cr3);
    hv_detach_hypervisor(exit_state);
}

static ssize_t handle_cpuid(struct cpu_ctx* cpu,
                            struct hv_exit_state* exit_state) {
    /* Avoid UB where the upper 32 bits are untouched. */
    unsigned int cpuid[4];
    unsigned int leaf = LOWER_DWORD(exit_state->rax);
    unsigned int subleaf = LOWER_DWORD(exit_state->rcx);

    if (leaf == HV_CPUID_DETACH_LEAF && subleaf == HV_CPUID_DETACH_SUBLEAF) {
        /* Detach hypervisor and return to guest. This function will never
         * return. */
        detach_hypervisor(cpu, exit_state);
    }

    cpuid_count(leaf, subleaf, &cpuid[0], &cpuid[1], &cpuid[2], &cpuid[3]);

    /* Report to guest that VMX is not supported. */
    if (leaf == CPUID_VERSION_INFORMATION) {
        hv_utils_cpu_log(info,
                         "VM-exit: intercepting CPUID leaf=%x, subleaf=%x to "
                         "report no VMX\n",
                         leaf, subleaf);

        cpuid[2] &= ~(1UL << CPUID_VMX_ENABLED_BIT);
    }

    exit_state->rax = cpuid[0];
    exit_state->rbx = cpuid[1];
    exit_state->rcx = cpuid[2];
    exit_state->rdx = cpuid[3];
    return 0;
}

static ssize_t handle_unknown_vmexit(VMX_VMEXIT_REASON reason) {
    hv_utils_cpu_log(info, "VM-exit: unknown exit reason: %x\n",
                     reason.basic_exit_reason);
    return -1;
}

u8 hv_exit_vmexit_handler(struct cpu_ctx* cpu,
                          struct hv_exit_state* exit_state) {
    ssize_t err = 0;
    const VMX_VMEXIT_REASON vmexit_reason = {
        .flags = hv_arch_vmread(VMCS_EXIT_REASON)};

    switch (vmexit_reason.basic_exit_reason) {
        case VMX_EXIT_REASON_ERROR_INVALID_GUEST_STATE:
            hv_utils_cpu_log(err, "VM-entry: invalid guest state\n");
            err = -1;
            break;
        case VMX_EXIT_REASON_ERROR_MSR_LOAD:
            hv_utils_cpu_log(err, "VM-entry: failed to load MSRs\n");
            err = -1;
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
            err = handle_cpuid(cpu, exit_state);
            break;
        case VMX_EXIT_REASON_EXECUTE_INVD:
            wbinvd();
            break;
        case VMX_EXIT_REASON_EXECUTE_XSETBV:
            xsetbv(LOWER_DWORD(exit_state->rcx),
                   (exit_state->rdx << 32) | LOWER_DWORD(exit_state->rax));
            break;
        default:
            err = handle_unknown_vmexit(vmexit_reason);
    }

    if (err) {
        hv_utils_cpu_log(err, "VM-exit: an error occured\n");
    } else {
        advance_guest();
    }
    return err;
}

u8 hv_exit_vmexit_failure(struct hv_exit_state* exit_state) { return 0; }
