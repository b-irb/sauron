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
.endm

.macro restore_cpu_state
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
// Per-CPU hypervisor initialisation entry point
SYM_FUNC_START(hv_cpu_init_entry)
	pushfq
	store_cpu_state
	movabs $.vmx_guest_resume, %rsi
	movq %rsp, %rdx
	movq 0x80(%rsp), %rcx
	// %rdi contains the VMM context structure (struct vmm_ctx).
	// %rsi contains the address to jump to after VMLAUNCH.
	// %rdx contains the original sp for VMX guest.
	// %rcx contains the original flags for VMX guest.
	subq $0x20, %rsp
	call hv_cpu_init
	addq $0x20, %rsp
	jmp .vmx_guest_resume
.vmx_guest_resume:
	// If VMLAUNCH fails to execute, hv_cpu_init_entry returns with an
	// error indication with ((struct cpu_ctx*)cpu)->failed. Otherwise,
	// the failed indicator is not set.
	restore_cpu_state
	popfq
	ret
SYM_FUNC_END(hv_cpu_init_entry)
EXPORT_SYMBOL(hv_cpu_init_entry)

// VM-exit entry point
SYM_FUNC_START(hv_exit_vmexit_entry)
	store_cpu_state
	movq 0x80(%rsp), %rdi
	movq %rsp, %rsi
	// %rdi contains the cpu_ctx pointer at the top of the stack
	// which store_cpu_state moves by 0x80 bytes.
	// %rsi contains a pointer to a hv_exit_state instance.
	subq $0x20, %rsp
	call hv_exit_vmexit_handler
	addq $0x20, %rsp

	test %al, %al
	jnz .failure

	restore_cpu_state
	VMRESUME
	// If VMRESUME does not succeed then attempt to handle error.
	jmp .failure
.failure:
	// TODO implement VMRESUME error handler
	jmp .critical_failure
.critical_failure:
	hlt
	jmp .critical_failure
SYM_FUNC_END(hv_exit_vmexit_entry)
EXPORT_SYMBOL(hv_exit_vmexit_entry)

SYM_FUNC_START(hv_detach_hypervisor)
	mov %rdi, %rsp
	restore_cpu_state
	// %rax contains a pointer to the hv_exit_state structure
	// at the top of the stack.
	// cli
	// RFLAGS
	push 0x1a8(%rax)
	popfq
	// Stack pointer
	mov 0x198(%rax), %rsp
	// Instruction pointer
	push 0x1a0(%rax)
	// Clear %rax to not leak kernel pointer.
	xor %rax, %rax
	ret
SYM_FUNC_END(hv_detach_hypervisor)
EXPORT_SYMBOL(hv_detach_hypervisor)
