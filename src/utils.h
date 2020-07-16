#include <linux/printk.h>
#include <linux/types.h>

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define hv_utils_log(level, msg, ...) pr_##level(msg, ##__VA_ARGS__);
#define hv_utils_cpu_log(level, cpu, msg, ...)                     \
    hv_utils_log(level, "processor [%u]: " msg, cpu->processor_id, \
                 ##__VA_ARGS__);

u64 hv_utils_set_required_bits(u64, u64, u64);
bool hv_utils_is_bit_set(u64, u64);
