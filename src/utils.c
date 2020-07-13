#include "utils.h"

#include <linux/types.h>

bool hv_utils_is_bit_set(u64 position, u64 vector) {
    return (bool)(vector & (1 << position));
}
