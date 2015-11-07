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

#ifndef __CDC_ENCAP_H__
#define __CDC_ENCAP_H__

#include <linux/device.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/usb.h>
#include <linux/usb/cdc.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif

struct cdc_encap {
	dev_t			devno;
	struct cdev		cdev;
	struct device		*dev;
	struct usb_device	*udev;
	int			iface_num;
	struct semaphore	sem;
	wait_queue_head_t	readq;
	int			rsp_ready;
	volatile int		dying;
       int ecm_ndis_dial_mode;
	char			name[1];	/* array size depends on dev_id
						and name prefix */
};

extern int cdc_encap_init(char *dev_id, struct usb_interface *intf,
	unsigned char subclass, struct cdc_encap **encap_p);

extern void cdc_encap_uninit(struct cdc_encap *encap);

extern void cdc_encap_response_avail(struct cdc_encap *encap);

#define CDC_ENCAP_TIMEOUT_MS		5000
#define CDC_ENCAP_REQT_OUT		0x21
#define CDC_ENCAP_REQ_SEND_COMMAND	0x00
#define CDC_ENCAP_REQT_IN		0xa1
#define CDC_ENCAP_REQ_GET_RESPONSE	0x01
#define CDC_ENCAP_NAME_PREFIX		"cdcctl_"
#define CDC_ENCAP_ECM_NAME_PREFIX	"cdcecm_"
#define CDC_ENCAP_CLASS_NAME		"cdcctl"

#endif
