#include <linux/printk.h>
#include <linux/smp.h>
#include <linux/types.h>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define hv_utils_log(level, msg, ...) pr_##level(msg, ##__VA_ARGS__);

#define hv_utils_cpu_log(level, msg, ...)                           \
    hv_utils_log(level, "processor [%u]: " msg, smp_processor_id(), \
                 ##__VA_ARGS__);

#define UPPER_DWORD(x) (u32)((x) >> 32)
#define LOWER_DWORD(x) (u32)((x)&0xffffffff)

bool hv_utils_is_bit_set(u64, u64);
bool hv_utils_is_canonical(u64);
