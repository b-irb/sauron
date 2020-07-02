#include "vmm.h"

#include <asm-generic/errno.h>
#include <linux/printk.h>
#include <linux/types.h>

#include "arch.h"
#include "utils.h"

ssize_t vmm_initialise_processors(void) {
    u64 feature_control_msr = 0;

    /* Check to see if the processor has implemented virtual machine extensions
     * (VMX). */
    if (!arch_cpu_has_vmx()) {
        utils_log(err, "CPU does not support VMX\n");
        return -ENOSYS;
    }
    utils_log(debug, "CPU supports VMX\n");

    feature_control_msr = arch_rdmsr(IA32_FEATURE_CONTROL_MSR);

    /* BIOS can disable VMX which causes VMXON to generate a #GP fault. The MSR
     * cannot be modified until a power-up reset condition. */
    if (utils_is_bit_set(feature_control_msr,
                         IA32_FEATURE_CONTROL_MSR_LOCK_BIT)) {
        utils_log(err, "BIOS has disabled support for VMX\n");
        return -ENOSYS;
    }
    utils_log(debug, "BIOS has enabled support for VMX\n");

    /* BIOS can disable VMX outside of SMX which causes VMXON to generate a #GP
     * fault. */
    if (utils_is_bit_set(feature_control_msr,
                         IA32_FEATURE_CONTROL_MSR_VMX_OUTSIDE_SMX_BIT)) {
        utils_log(err, "BIOS has disabled VMX support outside SMX\n");
        return -ENOSYS;
    }
    utils_log(debug, "BIOS has enabled VMX support outside SMX\n");

    return 0;
}

ssize_t vmm_exit_root_all_processors(void) { return 0; }
