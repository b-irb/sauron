#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include "utils.h"
#include "vmm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("birb007");
MODULE_DESCRIPTION("Simple Intel VT-x hypervisor for Linux.");

static int opt_enable_hypervisor_no;
static int hv_is_enabled;
static struct vmm_ctx* vmm;

static ssize_t hv_enable(void) {
    if (hv_is_enabled) {
        return 0;
    }

    hv_utils_log(info, "enabling hypervisor\n");
    if (!(vmm = hv_vmm_start_hypervisor())) {
        hv_utils_log(err, "hypervisor failed\n");
        return -1;
    }
    hv_is_enabled = 1;
    return 0;
}

static ssize_t hv_disable(void) {
    if (!hv_is_enabled) {
        return 0;
    }

    hv_utils_log(info, "disabling hypervisor\n");
    hv_vmm_stop_hypervisor(vmm);
    hv_is_enabled = 0;
    return 0;
}

static ssize_t opt_enable_hypervisor_show(struct kobject* kobj,
                                          struct kobj_attribute* attr,
                                          char* buf) {
    return sprintf(buf, "%d\n", opt_enable_hypervisor_no);
}

static ssize_t opt_enable_hypervisor_set(struct kobject* kobj,
                                         struct kobj_attribute* attr,
                                         const char* buf, size_t count) {
    int ret;
    if ((ret = kstrtoint(buf, 10, &opt_enable_hypervisor_no)) < 0) {
        return ret;
    }

    switch (opt_enable_hypervisor_no) {
        case 0:
            ret = hv_disable();
            break;
        case 1:
            ret = hv_enable();
            break;
        default:
            hv_utils_log(err, "invalid action\n");
            ret = -EINVAL;
    }

    if (ret < 0) {
        hv_utils_log(err, "failed to execute specified action\n");
    }
    return count;
}

static struct kobj_attribute do_action =
    __ATTR(action, 0664, opt_enable_hypervisor_show, opt_enable_hypervisor_set);

static struct attribute* attrs[] = {&do_action.attr, NULL};

static struct attribute_group attr_group = {.attrs = attrs};

static struct kobject* sauron_kobj;

static int __init sauron_init(void) {
    int ret = 0;

    /* Create kernel object for sysfs interface. */
    if (!(sauron_kobj = kobject_create_and_add("sauron", kernel_kobj))) {
        hv_utils_log(err, "failed to create kernel object\n");
        return -ENOMEM;
    }

    if ((ret = sysfs_create_group(sauron_kobj, &attr_group))) {
        /* Decrement refcount for kobj leaving scope. */
        kobject_put(sauron_kobj);
    }

    /* Ensure the hypervisor is not signalled as enabled to avoid NULL ptr
     * accesses (should be unnecessary). */
    hv_is_enabled = 0;
    return ret;
}

static void __exit sauron_exit(void) {
    /* Release reference to kobj, should dealloc. */
    kobject_put(sauron_kobj);

    /* Attempt to detach hypervisor. */
    hv_disable();
}

module_init(sauron_init);
module_exit(sauron_exit);
