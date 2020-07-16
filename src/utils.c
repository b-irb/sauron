#include "utils.h"

#include <linux/types.h>

u64 hv_utils_set_required_bits(u64 vector, u64 fixed0, u64 fixed1) {
    u64 fixed_mask, flexible_mask, fixed_bits, flexible_bits;

    flexible_mask = fixed0 ^ fixed1;
    fixed_mask = vector & ~flexible_mask;

    fixed_bits = (fixed0 | fixed1) & fixed_mask;
    flexible_bits = flexible_mask & vector;
    return fixed_bits | flexible_bits;
}

bool hv_utils_is_bit_set(u64 position, u64 vector) {
    return (bool)(vector & (1 << position));
}
