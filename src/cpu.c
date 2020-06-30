#include "cpu.h"

unsigned long rdmsr(uint64_t msr) {
    unsigned int low, high;

    asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((unsigned long)high << 32) | low;
}

void wrmsr(unsigned long msr, unsigned long value) {
    unsigned int low = value & 0xFFFFFFFF;
    unsigned int high = value >> 32;

    asm volatile("wrmsr" : : "c"(msr), "a"(low), "d"(high));
}
