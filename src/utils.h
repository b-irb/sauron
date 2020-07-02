#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/printk.h>
#include <linux/types.h>

#define utils_log(level, msg) pr_##level(msg);

bool utils_is_bit_set(u64, u64);
