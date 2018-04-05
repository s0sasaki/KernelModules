
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include "irqcount_ioctl.h"

MODULE_LICENSE("Dual BSD/GPL");

#define IRQ_NUM 19

static int irqcount_devs = 1; 
static int irqcount_major = 0;
static int irqcount_minor = 0;
static struct cdev irqcount_cdev;  
static struct class *irqcount_class = NULL;
static dev_t irqcount_dev;

struct user_data {
    rwlock_t lock;
    struct file *file;
    struct list_head list;
    wait_queue_head_t wait;
    int val;
};

struct user_data head;

long irqcount_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct user_data *udata = filp->private_data;
    int retval = 0;
    int val;
    struct ioctl_cmd data;
    memset(&data, 0, sizeof(data));
    switch (cmd) {
        case IOCTL_VALSET:
            if (!capable(CAP_SYS_ADMIN)) {
                retval = -EPERM;
                goto done;
            }
            if (!access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd))) {
                retval = -EFAULT;
                goto done;
            }
            if ( copy_from_user(&data, (int __user *)arg, sizeof(data)) ) {
                retval = -EFAULT;
                goto done;
            }
            write_lock(&udata->lock);
            udata->val = data.val;
            write_unlock(&udata->lock);
            break;
        case IOCTL_VALGET:
            if (!access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd))) {
                retval = -EFAULT;
                goto done;
            }
            read_lock(&udata->lock);
            val = udata->val;
            read_unlock(&udata->lock);
            data.val = val;
            if ( copy_to_user((int __user *)arg, &data, sizeof(data)) ) {
                retval = -EFAULT;
                goto done;
            }
            break;
        default:
            retval = -ENOTTY;
            break;
    }

done:
    return (retval);
}

int irqcount_close(struct inode *inode, struct file *filp)
{
    struct user_data *udata = filp->private_data;
    if (udata) {
        list_del(&udata->list);
        kfree(udata);
    }
    return 0;  
}

int irqcount_open(struct inode *inode, struct file *filp)
{
    struct user_data *udata;
    udata = kmalloc(sizeof(struct user_data), GFP_KERNEL);
    if (udata == NULL) {
        return -ENOMEM;
    }
    rwlock_init(&udata->lock);
    udata->val = 0;
    list_add(&udata->list, &head.list);
    filp->private_data = udata;
    return 0; 
}

struct file_operations irqcount_fops = {
    .owner = THIS_MODULE,
    .open = irqcount_open,
    .release = irqcount_close,
    .unlocked_ioctl = irqcount_ioctl,
};

static irqreturn_t sample_intr(int irq, void *dev_id)
{
    struct list_head *listptr;
    struct user_data *entry;
    list_for_each(listptr, &head.list) {
        entry = list_entry(listptr, struct user_data, list);
        entry->val += 1;
    }
    return IRQ_NONE;
}

static int irqcount_init(void)
{
    dev_t dev = MKDEV(irqcount_major, 0);
    int alloc_ret = 0;
    int major;
    int cdev_err = 0;
    struct device *class_dev = NULL;
    alloc_ret = alloc_chrdev_region(&dev, 0, irqcount_devs, "irqcount");
    if (alloc_ret)
        goto error;
    irqcount_major = major = MAJOR(dev);
    cdev_init(&irqcount_cdev, &irqcount_fops);
    irqcount_cdev.owner = THIS_MODULE;
    irqcount_cdev.ops = &irqcount_fops;
    cdev_err = cdev_add(&irqcount_cdev, MKDEV(irqcount_major, irqcount_minor), 1);
    if (cdev_err) 
        goto error;
    irqcount_class = class_create(THIS_MODULE, "irqcount");
    if (IS_ERR(irqcount_class)) {
        goto error;
    }
    irqcount_dev = MKDEV(irqcount_major, irqcount_minor);
    class_dev = device_create(
                    irqcount_class, 
                    NULL, 
                    irqcount_dev,
                    NULL, 
                    "irqcount%d",
                    irqcount_minor);
    if (request_irq(IRQ_NUM, 
                sample_intr, 
                IRQF_SHARED, 
                "sample_intr", 
                (void *)sample_intr)) {
    }
    printk(KERN_ALERT "irqcount driver(major %d) installed.\n", major);
    memset(&head, 0, sizeof(head));
    INIT_LIST_HEAD(&head.list); 
    return 0;

error:
    if (cdev_err == 0)
        cdev_del(&irqcount_cdev);
    if (alloc_ret == 0)
        unregister_chrdev_region(dev, irqcount_devs);
    return -1;
}

static void irqcount_exit(void)
{
    dev_t dev = MKDEV(irqcount_major, 0);
    device_destroy(irqcount_class, irqcount_dev);
    class_destroy(irqcount_class);
    cdev_del(&irqcount_cdev);
    unregister_chrdev_region(dev, irqcount_devs);
    free_irq(IRQ_NUM, (void *)sample_intr);
    printk(KERN_ALERT "irqcount driver removed.\n");
}

module_init(irqcount_init);
module_exit(irqcount_exit);

