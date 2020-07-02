#include <linux/types.h>

bool utils_is_bit_set(u64 position, u64 bit_vector) {
    return (bool)(bit_vector & (1 << position));
}
