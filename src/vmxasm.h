#pragma once

#include <linux/types.h>

extern void hv_cpu_init_entry(void*);
extern void* hv_exit_vmexit_entry;

struct hv_exit_state {
    u64 r15;
    u64 r14;
    u64 r13;
    u64 r12;
    u64 r11;
    u64 r10;
    u64 r9;
    u64 r8;
    u64 rdi;
    u64 rsi;
    u64 rdx;
    u64 rcx;
    u64 rbx;
    u64 rax;
    /* RSP must be read from the VMCS within the vmexit handler. */
    u64 _padding;
    u64 rbp;
} __attribute__((aligned(16)));
