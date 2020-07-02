#include <linux/printk.h>
#include <linux/types.h>

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define utils_log(level, msg, ...) pr_info(msg, ##__VA_ARGS__);

bool utils_is_bit_set(u64, u64);
