/* (c) 2009 Jungo Ltd. All Rights Reserved. Jungo Confidential */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include "cdc_encap.h"
#include <linux/err.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/kdev_t.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
static struct class *encap_class;

//#define lr_debug_open
#define JUDGE_HARDWARE_ENDIAN_IN_CDC_ENCAP_READ_AND_WRITE_FUCTION

#ifdef  JUDGE_HARDWARE_ENDIAN_IN_CDC_ENCAP_READ_AND_WRITE_FUCTION
#define BigEndian cpu_to_be16
#define LittleEndian cpu_to_le16

 /*add here to modify the endian on your mathine by lirui  2011.11.22  BigEndian or LittleEndian */
#define Hardware_Endian BigEndian
#endif

static ssize_t cdc_encap_read(struct file *filp, char __user *buf, size_t size,
	loff_t *z)
{
	struct cdc_encap *encap = filp->private_data;
	void *data = NULL;
	int status;

	if (encap->dying)
		return -ENODEV;

	if (size) {
		data = kmalloc(size, GFP_KERNEL);
		if (data == NULL)
			return -ENOMEM;
	}

	encap->rsp_ready = 0;

#ifdef lr_debug_open
    printk(" cdc_encap_read encap->udev->devnum=%lx,cpu_to_le16(encap->iface_num)=%lx\n",encap->udev->devnum,cpu_to_le16(encap->iface_num));
    printk(" cdc_encap_read usb_rcvctrlpipe(encap->udev, 0)=%lx\n",usb_rcvctrlpipe(encap->udev, 0));
#endif

#ifdef JUDGE_HARDWARE_ENDIAN_IN_CDC_ENCAP_READ_AND_WRITE_FUCTION
	status = usb_control_msg(encap->udev, usb_rcvctrlpipe(encap->udev, 0),
		CDC_ENCAP_REQ_GET_RESPONSE, CDC_ENCAP_REQT_IN, 0,
		Hardware_Endian(encap->iface_num), data, size,
		msecs_to_jiffies(CDC_ENCAP_TIMEOUT_MS));
#else
	status = usb_control_msg(encap->udev, usb_rcvctrlpipe(encap->udev, 0),
		CDC_ENCAP_REQ_GET_RESPONSE, CDC_ENCAP_REQT_IN, 0,
		cpu_to_le16(encap->iface_num), data, size,
		msecs_to_jiffies(CDC_ENCAP_TIMEOUT_MS));
#endif

#ifdef lr_debug_open
    printk(" cdc_encap_read status=%lx\n",status);
#endif
	
	if (status <= 0 || size == 0)
		goto out;

	if (copy_to_user(buf, data, status))
		status = -EACCES;
out:
	if (data)
		kfree(data);
	return status;
}

static ssize_t cdc_encap_write(struct file *filp, const char __user *buf,
	size_t size, loff_t *z)
{
	struct cdc_encap *encap = filp->private_data;
	void *data = NULL;
	int status;

	if (encap->dying)
		return -ENODEV;

	if (size) {
		data = kmalloc(size, GFP_KERNEL);
		if (data == NULL)
			return -ENOMEM;

		if (copy_from_user(data, buf, size)) {
			status = -EACCES;
			goto out;
		}
	}

	#ifdef lr_debug_open
    printk("before  cdc_encap_write status=%lx\n",status);
	#endif

#ifdef JUDGE_HARDWARE_ENDIAN_IN_CDC_ENCAP_READ_AND_WRITE_FUCTION	
	status = usb_control_msg(encap->udev, usb_sndctrlpipe(encap->udev, 0),
		CDC_ENCAP_REQ_SEND_COMMAND, CDC_ENCAP_REQT_OUT, 0,
		Hardware_Endian(encap->iface_num), data, size,
		msecs_to_jiffies(CDC_ENCAP_TIMEOUT_MS));
#else

	status = usb_control_msg(encap->udev, usb_sndctrlpipe(encap->udev, 0),
		CDC_ENCAP_REQ_SEND_COMMAND, CDC_ENCAP_REQT_OUT, 0,
		cpu_to_le16(encap->iface_num), data, size,
		msecs_to_jiffies(CDC_ENCAP_TIMEOUT_MS));
#endif
	#ifdef lr_debug_open
    printk("\n after cdc_encap_write status=%lx,encap->iface_num=%lx,cpu_to_le16(encap->iface_num)=%lx\n",status,encap->iface_num,cpu_to_le16(encap->iface_num));
	#endif

	
out:
	if (data)
		kfree(data);
	return status;
}

static unsigned int cdc_encap_poll(struct file *filp, poll_table *wait)
{
	struct cdc_encap *encap = filp->private_data;
	unsigned int mask = POLLOUT | POLLWRNORM;

	if (encap->dying)
		return -ENODEV;

	poll_wait(filp, &encap->readq, wait);

	if (encap->rsp_ready)
		mask |= POLLIN | POLLRDNORM;

	return mask;
}

static int cdc_encap_open(struct inode *i, struct file *filp)
{
        struct cdc_encap *encap = container_of(i->i_cdev, struct cdc_encap,
            cdev);

	if (encap->dying)
		return -ENODEV;

	if (down_trylock(&encap->sem) != 0) {
		dev_dbg(&encap->udev->dev, "encap is already open\n");
		return -EBUSY;
	}

	filp->private_data = encap;

	dev_dbg(&encap->udev->dev, "cdc_encap_open\n");
	
		#ifdef lr_debug_open
    printk("enter cdc_encap_open ok\n");
		#endif
		
	return 0;
}

static void cdc_encap_delete(struct cdc_encap *encap)
{
	cdev_del(&encap->cdev);
	unregister_chrdev_region(encap->devno, 1);
	kfree(encap);
}

static int cdc_encap_release(struct inode *i, struct file *filp)
{
	struct cdc_encap *encap = filp->private_data;

	dev_dbg(&encap->udev->dev, "cdc_encap_release\n");
	
	if (encap->dying) {
		cdc_encap_delete(encap);
		return -ENODEV;
	}

	up(&encap->sem);

	return 0;
}
#ifdef IP_ETHERNET_SUPPORT
unsigned int lte_data_format =0;
#endif
#define CDC_ENCAP_MAGIC_NUM             0xCC
#define CDC_ENCAP_IOCTL_SUSPEND_ACK     0x82
#define CDC_ENCAP_IOCTL_ERAD_DIALMODE  _IOR(CDC_ENCAP_MAGIC_NUM,0x83,int)
static int cdc_encap_ioctl(struct inode *node, struct file *filp, 
	unsigned int cmd, unsigned long arg)
{
	int err = 0;
	struct cdc_encap *encap = filp->private_data;
	
	#ifdef lr_debug_open
    printk("enter cdc_encap_ioctl!\n");
	#endif
	
	if (_IOC_TYPE(cmd) != CDC_ENCAP_MAGIC_NUM)
		return -EFAULT;
    
	switch (cmd) {
	//case CDC_ENCAP_IOCTL_SUSPEND_ACK:
		//encap->suspend_in_progress = 0;
		//complete(&encap->suspend_completion);
		//break;
        case CDC_ENCAP_IOCTL_ERAD_DIALMODE:
            copy_to_user((char *)arg, (char *)&(encap->ecm_ndis_dial_mode), sizeof(int));
            break;
	default:
		err = -EINVAL;
	}
	return err;
}

static struct file_operations cdc_encap_fops = {
	.owner =	THIS_MODULE,
	.read =		cdc_encap_read,
	.write =	cdc_encap_write,
	.poll =		cdc_encap_poll,
	.unlocked_ioctl =           cdc_encap_ioctl,
	.open =		cdc_encap_open,
	.release =	cdc_encap_release
};

int cdc_encap_init(char *dev_id, struct usb_interface *intf,
	unsigned char subclass, struct cdc_encap **encap_p)
{
	int error;
	struct cdc_encap *encap;
	char *dev_name_prefix = (subclass == USB_CDC_SUBCLASS_ETHERNET) ? 
		CDC_ENCAP_ECM_NAME_PREFIX : CDC_ENCAP_NAME_PREFIX;

	encap = kmalloc(sizeof(*encap) + strlen(dev_id) +
		strlen(dev_name_prefix), GFP_KERNEL);
	if (!encap)
	{
		return -ENOMEM;
	}
	memset(encap, 0, sizeof(*encap));
	sprintf(encap->name, "%s%s", dev_name_prefix, dev_id);
	cdev_init(&encap->cdev, &cdc_encap_fops);
	encap->cdev.owner = THIS_MODULE;

	init_waitqueue_head(&encap->readq);
	//init_MUTEX(&encap->sem);
	 sema_init(&encap->sem,1);

	encap->udev = interface_to_usbdev(intf);
	encap->iface_num = intf->cur_altsetting->desc.bInterfaceNumber;

	error = alloc_chrdev_region(&encap->devno, 0, 1, encap->name);
	if (error)
	{
		goto error1;
	}
	error = cdev_add(&encap->cdev, encap->devno, 1);
	if (error)
	{
		goto error2;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	encap->dev = device_create(encap_class, &intf->dev, encap->devno,
		encap->name);
#else
	encap->dev = device_create(encap_class, &intf->dev, encap->devno,
		NULL, encap->name);
#endif
	if (IS_ERR(encap->dev)) {
		error = PTR_ERR(encap->dev);
		goto error3;
	}

	*encap_p = encap;

	dev_dbg(&encap->udev->dev, "cdc_encap_init %s\n", encap->name);

	return 0;

error3:
	cdev_del(&encap->cdev);
error2:
	unregister_chrdev_region(encap->devno, 1);
error1:
	kfree(encap);
	return error;

}
EXPORT_SYMBOL_GPL(cdc_encap_init);

void cdc_encap_uninit(struct cdc_encap *encap)
{
	dev_dbg(&encap->udev->dev, "cdc_encap_uninit %s\n", encap->name);

	device_destroy(encap_class, encap->devno);

        encap->dying = 1;

	if (down_trylock(&encap->sem) != 0) {
		dev_dbg(&encap->udev->dev, "uninit called before release\n");
		return;
	}

	cdc_encap_delete(encap);
}
EXPORT_SYMBOL_GPL(cdc_encap_uninit);

void cdc_encap_response_avail(struct cdc_encap *encap)
{
	dev_dbg(&encap->udev->dev, "cdc_encap_response_avail\n");

	encap->rsp_ready = 1;
	wake_up_interruptible(&encap->readq);
}
EXPORT_SYMBOL_GPL(cdc_encap_response_avail);

static int __init cdc_encap_module_init(void)
{
	encap_class = class_create(THIS_MODULE, CDC_ENCAP_CLASS_NAME);
	if (IS_ERR(encap_class))
		return PTR_ERR(encap_class);

	return 0;
}
module_init(cdc_encap_module_init);

static void __exit cdc_encap_exit(void)
{
	class_destroy(encap_class);
}
module_exit(cdc_encap_exit);

MODULE_AUTHOR("Jungo");
MODULE_DESCRIPTION("USB CDC encapsulated command");
MODULE_LICENSE("GPL");
