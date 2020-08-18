#include "cpu.h"

#include <asm/io.h>
#include <asm/processor.h>
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

void hv_cpu_shutdown(void) {
    unsigned int placeholder[4];
    /* Signal hypervisor to detach. */
    cpuid_count(HV_CPUID_DETACH_LEAF, HV_CPUID_DETACH_SUBLEAF, &placeholder[0],
                &placeholder[1], &placeholder[2], &placeholder[3]);
}

void hv_cpu_ctx_destroy(struct cpu_ctx* cpu) {
    free_pages_exact(cpu->msr_bitmap, PAGE_SIZE);
    free_pages_exact(cpu->vmexit_stack, VMX_VMEXIT_STACK_SIZE);
    hv_vmx_vmxon_destroy(cpu->vmxon_region);
    hv_vmcs_vmcs_destroy(cpu->vmcs_region);
}

static ssize_t cpu_ctx_init(struct cpu_ctx* cpu, struct vmm_ctx* vmm) {
    phys_addr_t addr;

    cpu->vmm = vmm;

    if (!(cpu->msr_bitmap = alloc_pages_exact(PAGE_SIZE, GFP_KERNEL))) {
        hv_utils_cpu_log(err, "unable to allocate MSR bitmap\n");
        goto msr_err;
    }
    memset(cpu->msr_bitmap, 0x0, PAGE_SIZE);

    addr = virt_to_phys(cpu->msr_bitmap);
    hv_utils_cpu_log(debug, "MSR bitmap allocated at VA=%pK, PA=%pa[p]\n",
                     cpu->msr_bitmap, &addr);

    if (!(cpu->vmexit_stack =
              alloc_pages_exact(VMX_VMEXIT_STACK_SIZE, GFP_KERNEL))) {
        hv_utils_cpu_log(err, "unable to allocate VM-exit stack\n");
        goto stack_err;
    }
    hv_utils_cpu_log(debug, "VM-exit handler stack allocated at %pK\n",
                     cpu->vmexit_stack);
    cpu->vmexit_stack->cpu = cpu;

    if (!(cpu->vmxon_region = hv_vmx_vmxon_create(cpu))) {
        hv_utils_cpu_log(err, "unable to create VMXON region\n");
        goto vmxon_err;
    }
    addr = virt_to_phys(cpu->vmxon_region);
    hv_utils_cpu_log(debug, "VMXON region allocated at VA=%pK, PA=%pa[p]\n",
                     cpu->vmxon_region, &addr);

    if (!(cpu->vmcs_region = hv_vmcs_vmcs_create(cpu))) {
        hv_utils_cpu_log(err, "unable to allocate VMCS region\n");
        goto vmcs_err;
    }
    addr = virt_to_phys(cpu->vmcs_region);
    hv_utils_cpu_log(debug, "VMCS region allocated at VA=%pK, PA=%pa[p]\n",
                     cpu->vmcs_region, &addr);

    /* Our stack includes the cpu_ctx structure for easy accessibility from
     * within the VM-exit handler. */
    cpu->vmexit_handler = &hv_exit_vmexit_entry;
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

void hv_cpu_init(void* info, u64 ip, u64 sp, u64 flags) {
    struct vmm_ctx* vmm = info;
    const unsigned processor_id = smp_processor_id();
    struct cpu_ctx* cpu = &vmm->each_cpu_ctx[processor_id];

    cpu->processor_id = processor_id;

    hv_utils_cpu_log(debug, "processor context allocated at %pK\n", cpu);

    if (cpu_ctx_init(cpu, vmm) < 0) {
        hv_utils_cpu_log(err, "failed to initialise processor context\n");
        goto ctx_err;
    }

    hv_utils_cpu_log(info, "guest will resume to %pSR with sp=%llx\n",
                     (void*)ip, sp);

    if (hv_vmx_enter_root(cpu) < 0) {
        hv_utils_cpu_log(err, "failed to enter VMX root\n");
        goto error;
    }
    hv_utils_cpu_log(info, "successfully entered VMX root\n");

    hv_arch_capture_cpu_state(cpu);
    cpu->resume_sp = sp;
    cpu->resume_ip = ip;
    cpu->resume_flags = flags;

    if (hv_vmcs_vmcs_init(cpu) < 0) {
        hv_utils_cpu_log(err, "failed to setup the VMCS\n");
        goto vmcs_err;
    }
    hv_utils_cpu_log(info, "successfully setup the VMCS\n");
    hv_utils_cpu_log(info, "executing VMLAUNCH (VM-exit handler at %pK)\n",
                     cpu->vmexit_handler);

    /* This does not return if VMLAUNCH is successfully executed. */
    hv_vmx_launch_cpu(cpu);
    hv_utils_cpu_log(err, "failed to enable hypervisor\n");
vmcs_err:
    hv_vmx_exit_root(cpu);
error:
    hv_cpu_ctx_destroy(cpu);
ctx_err:
    cpu->failed = true;
    return;
}
