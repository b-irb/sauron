#include "vmm.h"

#include <asm-generic/errno.h>
#include <asm/io.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/types.h>

#include "arch.h"
#include "cpu.h"
#include "ia32.h"
#include "utils.h"
#include "vmcs.h"
#include "vmx.h"
#include "vmxasm.h"

static bool is_system_hyperviseable(void) {
    IA32_FEATURE_CONTROL_REGISTER feature_control;

    /* Does the processor have implemented virtual machine extensions? */
    if (!hv_arch_cpu_has_vmx()) {
        hv_utils_log(err, "CPU does not support VMX\n");
        return false;
    }

    feature_control.flags = native_read_msr(IA32_FEATURE_CONTROL);

    /* BIOS can disable VMX which causes VMXON to generate a #GP fault. The MSR
     * cannot be modified until a power-up reset condition. */
    if (!feature_control.lock_bit) {
        hv_utils_log(err, "BIOS has disabled support for VMX\n");
        return false;
    }

    /* BIOS can disable VMX outside of SMX which causes VMXON to generate a #GP
     * fault. */
    if (!feature_control.enable_vmx_outside_smx) {
        hv_utils_log(err, "BIOS has disabled VMX support outside SMX\n");
        return false;
    }
    return true;
}

static struct vmm_ctx* vmm_ctx_create(void) {
    struct vmm_ctx* vmm;

    if (!(vmm = kzalloc(sizeof(*vmm), GFP_KERNEL))) {
        hv_utils_log(err, "unable to allocate memory for VMM context\n");
        return NULL;
    }

    vmm->n_online_cpus = num_online_cpus();
    vmm->n_init_cpus = 0;
    vmm->vmx_capabilities.flags = native_read_msr(IA32_VMX_BASIC);

    if (!(vmm->each_cpu_ctx = kzalloc(
              vmm->n_online_cpus * sizeof(*vmm->each_cpu_ctx), GFP_KERNEL))) {
        hv_utils_log(
            err, "unable to allocate memory for logical processor contexts\n");
        kfree(vmm);
        return NULL;
    }
    return vmm;
}

static void stop_cpu_shim(void* info) {
    hv_cpu_ctx_destroy(
        &((struct vmm_ctx*)info)->each_cpu_ctx[smp_processor_id()]);
}

void hv_vmm_ctx_destroy(struct vmm_ctx* vmm) {
    on_each_cpu(stop_cpu_shim, vmm, 1);
    kfree(vmm->each_cpu_ctx);
    kfree(vmm);
}

void hv_vmm_stop_hypervisor(struct vmm_ctx* vmm) { hv_vmm_ctx_destroy(vmm); }

struct vmm_ctx* hv_vmm_start_hypervisor(void) {
    struct vmm_ctx* vmm;
    struct cpu_ctx* cpu;
    int i;

    if (!is_system_hyperviseable()) {
        hv_utils_log(err,
                     "all required features for hypervisor operation were not "
                     "detected\n");
        return NULL;
    }
    hv_utils_log(info,
                 "detected all required features for hypervisor operation\n");

    if (!(vmm = vmm_ctx_create())) {
        hv_utils_log(err, "unable to create VMM context\n");
        return NULL;
    }

    on_each_cpu(hv_cpu_init_entry, vmm, 1);
    /* VMLAUNCH guest resume entry point */

    for (i = 0; i < vmm->n_online_cpus; ++i) {
        cpu = &vmm->each_cpu_ctx[i];
        vmm->n_init_cpus += !cpu->failed;
    }
    return vmm;
}

