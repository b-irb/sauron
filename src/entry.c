#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>

#include "arch.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("birb007");
MODULE_DESCRIPTION("Simple Hypervisor");

static int __init sauron_init(void) {
    pr_info("initialising...\n");
    if (!arch_cpu_has_vmx()) {
        pr_info("VMX unsupported\n");
        return -1;
    }
    return 0;
}

static void __exit sauron_exit(void) {
    pr_info("exiting...\n");
    return;
}

module_init(sauron_init);
module_exit(sauron_exit);
