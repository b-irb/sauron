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
MODULE_DESCRIPTION("Simple hypervisor");

static int operation;
static int is_attached;

static ssize_t detach(void) {
    if (!is_attached) {
        return 0;
    }

    utils_log(info, "exiting VMX root mode\n");
    return vmm_exit_root_all_processors();
}

static ssize_t attach(void) {
    if (is_attached) {
        return 0;
    }

    utils_log(info, "entering VMX root mode\n");
    return vmm_init_processors();
}

static ssize_t operation_show(struct kobject* kobj, struct kobj_attribute* attr,
                              char* buf) {
    return sprintf(buf, "%d\n", operation);
}

static ssize_t operation_set(struct kobject* kobj, struct kobj_attribute* attr,
                             const char* buf, size_t count) {
    int retn;
    if ((retn = kstrtoint(buf, 10, &operation)) < 0) {
        return retn;
    }

    switch (operation) {
        case 0:
            retn = detach();
            break;
        case 1:
            retn = attach();
            break;
        default:
            retn = -EINVAL;
    }

    if (retn < 0) {
        utils_log(err, "failed to execute\n");
    }
    return count;
}

static struct kobj_attribute do_operation =
    __ATTR(operation, 0664, operation_show, operation_set);

static struct attribute* attrs[] = {&do_operation.attr, NULL};

static struct attribute_group attr_group = {.attrs = attrs};

static struct kobject* sauron_kobj;

static int __init sauron_init(void) {
    int retn = 0;

    /* create kernel object for sysfs*/
    if (!(sauron_kobj = kobject_create_and_add("sauron", kernel_kobj))) {
        utils_log(err, "unable to create kernel object\n");
        return -ENOMEM;
    }

    retn = sysfs_create_group(sauron_kobj, &attr_group);
    if (retn) {
        /* drop reference for kobj leaving scope */
        kobject_put(sauron_kobj);
    }

    return retn;
    /*
     *if (!arch_cpu_has_vmx()) {
     *    pr_info("VMX unsupported\n");
     *    return -1;
     *}
     *return 0;
     */
}

static void __exit sauron_exit(void) {
    /* release reference to kobj, should dealloc */
    kobject_put(sauron_kobj);
    return;
}

module_init(sauron_init);
module_exit(sauron_exit);
