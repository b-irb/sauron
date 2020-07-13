#include "cpu.h"

#include <linux/io.h>
#include <linux/mm.h>
#include <linux/types.h>

#include "arch.h"
#include "utils.h"
#include "vmcs.h"
#include "vmm.h"
#include "vmx.h"

void hv_cpu_ctx_destroy(struct cpu_ctx* ctx) {
    hv_vmx_vmxon_destroy(ctx->vmxon_region);
    hv_vmcs_vmcs_destroy(ctx->vmcs_region);
}

ssize_t hv_cpu_ctx_init(struct cpu_ctx* cpu, struct vmm_ctx* vmm) {
    cpu->vmm = vmm;

    if (!(cpu->vmxon_region = hv_vmx_vmxon_create(cpu))) {
        hv_utils_log(err, "unable to create VMXON region\n");
        return -ENOMEM;
    }

    if (!(cpu->vmcs_region = hv_vmcs_vmcs_alloc(cpu))) {
        hv_utils_log(err, "unable to allocate VMCS region\n");
        hv_vmx_vmxon_destroy(cpu->vmxon_region);
        return -ENOMEM;
    }

    cpu->vmcs_region_ptr = virt_to_phys(cpu->vmcs_region);
    cpu->vmxon_region_ptr = virt_to_phys(cpu->vmxon_region);
    cpu->failed = false;
    return 0;
}

void hv_vmm_cpu_init(void* info, u64 ip, u64 sp) {
    struct vmm_ctx* vmm = info;
    const unsigned processor_id = smp_processor_id();
    struct cpu_ctx* cpu = vmm->each_cpu_ctx[processor_id];

    cpu->processor_id = processor_id;

    if (hv_vmx_enter_root(cpu) < 0) {
        hv_utils_cpu_log(err, cpu, "failed to enter VMX root\n");
        return;
    }

    hv_arch_capture_cpu_state(cpu);
    cpu->resume_sp = sp;
    cpu->resume_ip = ip;

    if (hv_vmcs_vmcs_init(cpu) < 0) {
        hv_utils_cpu_log(err, cpu, "failed to setup the VMCS\n");
        hv_vmx_exit_root(cpu);
        hv_vmx_vmxon_destroy(cpu->vmxon_region);
        return;
    }

    /* hv_vmx_launch_processor does not return if vmlaunch is successfully
     * executed. */
    hv_vmx_launch_processor(cpu);
    hv_utils_cpu_log(err, cpu, "vmlaunch failed\n");

    hv_vmx_exit_root(cpu);
    hv_cpu_ctx_destroy(cpu);
    cpu->failed = true;
}
