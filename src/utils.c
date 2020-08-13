#include "utils.h"

#include <linux/types.h>

bool hv_utils_is_bit_set(u64 vector, u64 position) {
    return (bool)(vector & (1 << position));
}

static u64 get_canonical(u64 addr) { return ((int64_t)addr << 16) >> 16; }

bool hv_utils_is_canonical(u64 addr) { return get_canonical(addr) == addr; }
