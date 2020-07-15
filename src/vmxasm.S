#include <linux/linkage.h>
#include <asm/export.h>

.extern hv_cpu_init

// https://github.com/asamy/ksm/blob/e7e24931c9df26c33d6e2a0ea9a44c78d3ced7a6/vmx.S#L59
// RSP is read from VMCS.
.macro store_cpu_state
	pushq %rbp
	subq $8, %rsp
	pushq %rax
	pushq %rbx
	pushq %rcx
	pushq %rdx
	pushq %rsi
	pushq %rdi
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	pushfq
.endm

.macro restore_cpu_state
	popfq
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %r11
	popq %r10
	popq %r9
	popq %r8
	popq %rdi
	popq %rsi
	popq %rdx
	popq %rcx
	popq %rbx
	popq %rax
	addq $8, %rsp
	popq %rbp
.endm

.text

SYM_FUNC_START(hv_cpu_init_entry)
	store_cpu_state

	// %rdi contains the vmm_gloabl_ctx structure
	// vmlaunch entry point
	lea hv_vmx_guest_resume(%rip), %rsi
	// vmlaunch entry sp
	movq %rsp, %rdx
	// x64 alloc shadow stack
	subq $0x20, %rsp
	// hv_cpu_init does not return if vmlaunch is executed successfully.
	// If vmlaunch fails to execute, hv_cpu_init_entry returns with an
	// error indication.
	call hv_cpu_init
	// x64 dealloc shadow stack
	addq $0x20, %rsp

	restore_cpu_state
	ret
SYM_FUNC_END(hv_cpu_init_entry)
EXPORT_SYMBOL(hv_cpu_init_entry)

SYM_FUNC_START(hv_vmx_guest_resume)
	restore_cpu_state
	ret
SYM_FUNC_END(hv_vmx_guest_resume)
EXPORT_SYMBOL(hv_vmx_guest_resume)
