#include "cpu.h"

#include <asm/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "arch.h"
#include "exit.h"
#include "utils.h"
#include "vmcs.h"
#include "vmm.h"
#include "vmx.h"
#include "vmxasm.h"

void hv_cpu_ctx_destroy(struct cpu_ctx* cpu) {
    free_pages_exact(cpu->vmexit_stack, VMX_VMEXIT_STACK_SIZE);
    hv_vmx_vmxon_destroy(cpu->vmxon_region);
    hv_vmcs_vmcs_destroy(cpu->vmcs_region);
}

ssize_t hv_cpu_ctx_init(struct cpu_ctx* cpu, struct vmm_ctx* vmm) {
    cpu->vmm = vmm;

    if (!(cpu->msr_bitmap = alloc_pages_exact(PAGE_SIZE, GFP_KERNEL))) {
        hv_utils_cpu_log(err, cpu, "unable to allocate MSR bitmap\n");
        goto msr_err;
    }
    memset(cpu->msr_bitmap, 0x0, PAGE_SIZE);

    if (!(cpu->vmexit_stack =
              alloc_pages_exact(VMX_VMEXIT_STACK_SIZE, GFP_KERNEL))) {
        hv_utils_cpu_log(err, cpu, "unable to allocate VMEXIT stack\n");
        goto stack_err;
    }
    cpu->vmexit_stack->cpu = cpu;

    if (!(cpu->vmxon_region = hv_vmx_vmxon_create(cpu))) {
        hv_utils_cpu_log(err, cpu, "unable to create VMXON region\n");
        goto vmxon_err;
    }

    if (!(cpu->vmcs_region = hv_vmcs_vmcs_create(cpu))) {
        hv_utils_cpu_log(err, cpu, "unable to allocate VMCS region\n");
        goto vmcs_err;
    }

    /* Our stack includes the cpu_ctx structure for easy accessibility from
     * within the handler. */
    cpu->vmexit_handler = &hv_exit_vmexit_entry;
    cpu->msr_bitmap_ptr = virt_to_phys(cpu->msr_bitmap);
    cpu->vmcs_region_ptr = virt_to_phys(cpu->vmcs_region);
    cpu->vmxon_region_ptr = virt_to_phys(cpu->vmxon_region);
    cpu->failed = false;
    return 0;

vmcs_err:
    hv_vmx_vmxon_destroy(cpu->vmxon_region);
vmxon_err:
    free_pages_exact(cpu->msr_bitmap, PAGE_SIZE);
stack_err:
    kfree(cpu->msr_bitmap);
msr_err:
    return -ENOMEM;
}

void hv_cpu_init(void* info, u64 ip, u64 sp) {
    struct vmm_ctx* vmm = info;
    const unsigned processor_id = smp_processor_id();
    struct cpu_ctx* cpu = &vmm->each_cpu_ctx[processor_id];

    cpu->processor_id = processor_id;

    hv_utils_cpu_log(info, cpu, "guest will resume to %pSR with sp=%llx\n",
                     (void*)ip, sp);

    if (hv_vmx_enter_root(cpu) < 0) {
        hv_utils_cpu_log(err, cpu, "failed to enter VMX root\n");
        goto error;
    }
    hv_utils_cpu_log(info, cpu, "successfully entered VMX root\n");

    hv_arch_capture_cpu_state(cpu);
    cpu->resume_sp = sp;
    cpu->resume_ip = ip;

    if (hv_vmcs_vmcs_init(cpu) < 0) {
        hv_utils_cpu_log(err, cpu, "failed to setup the VMCS\n");
        hv_vmx_exit_root(cpu);
        hv_vmx_vmxon_destroy(cpu->vmxon_region);
        return;
    }
    hv_utils_cpu_log(info, cpu, "successfully setup the VMCS\n");
    hv_utils_cpu_log(info, cpu, "executing VMLAUNCH\n");

    /* hv_vmx_launch_cpu does not return if vmlaunch is successfully
     * executed. */
    /*hv_vmx_launch_cpu(cpu);*/
    return;
error:
    hv_vmx_exit_root(cpu);
    cpu->failed = true;
}
