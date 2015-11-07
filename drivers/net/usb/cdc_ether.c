/*
 * CDC Ethernet based networking peripherals
 * Copyright (C) 2003-2005 by David Brownell
 * Copyright (C) 2006 by Ole Andre Vadla Ravnas (ActiveSync)
 *
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

// #define	DEBUG			// error path messages, extra info
// #define	VERBOSE			// more; success messages

#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/workqueue.h>
#include <linux/mii.h>
#include <linux/usb.h>
#include <linux/inetdevice.h>
//#include <linux/usb/cdc.h>

#define CONFIG_CDC_ENCAP_COMMAND

#ifdef CONFIG_CDC_ENCAP_COMMAND
#include "cdc_encap.h"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
//#include <drivers/usb/net/usbnet.h>
#include "usbnet.h"
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#include <drivers/net/usb/usbnet.h>
#else
#include <linux/usb/usbnet.h>
#endif

#define ETH_TYPE_ARP  0x0806
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86DD
#define ETH_LENGTH_OF_ADDRESS 6

typedef struct _qc_eth_hdr
{
    unsigned char  dst_mac_address[ETH_LENGTH_OF_ADDRESS];
    unsigned char  src_mac_address[ETH_LENGTH_OF_ADDRESS];
    __be16  ether_type;
} qc_eth_hdr, *pqc_eth_hdr;

typedef struct _lte_arp_header
{
   __be16   hardware_type;
   __be16  protocol_type;
   unsigned char   hlen;        // length of HA  (6)
   unsigned char   plen;        // length of IP  (4)
   __be16   operation;
   unsigned char   sender_ha[ETH_LENGTH_OF_ADDRESS];  // 6
   unsigned char   sender_ip[4];
   unsigned char   target_ha[ETH_LENGTH_OF_ADDRESS];  // 6
   unsigned char   target_ip[4];
} lte_arp_header, *plte_arp_header;

static const u8 LTE_DST_MAC_ADDR[8] = {0x02,0x50,0xF3,0x00,0x00,0x00,0x08,0x00};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
#define USB_DEVICE_AND_INTERFACE_INFO(vend, prod, cl, sc, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_INT_INFO \
		| USB_DEVICE_ID_MATCH_DEVICE, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bInterfaceClass = (cl), \
	.bInterfaceSubClass = (sc), \
	.bInterfaceProtocol = (pr)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static inline int usb_endpoint_xfer_int(
				const struct usb_endpoint_descriptor *epd)
{
	return ((epd->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) ==
		USB_ENDPOINT_XFER_INT);
}

static inline int usb_endpoint_dir_in(const struct usb_endpoint_descriptor *epd)
{
	return ((epd->bEndpointAddress & USB_ENDPOINT_DIR_MASK) == USB_DIR_IN);
}

static inline int usb_endpoint_is_int_in(
				const struct usb_endpoint_descriptor *epd)
{
	return (usb_endpoint_xfer_int(epd) && usb_endpoint_dir_in(epd));
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
#include <linux/ctype.h>
static u8 nibble(unsigned char c)
{
	if (likely(isdigit(c)))
		return c - '0';
	c = toupper(c);
	if (likely(isxdigit(c)))
		return 10 + c - 'A';
	return 0;
}

static struct sk_buff *lte_tx_fixup(struct usbnet *dev, struct sk_buff *skb,gfp_t flags);

static int usbnet_get_ethernet_addr(struct usbnet *dev, int iMACAddress)
{
	int 		tmp, i;
	unsigned char	buf [13];

	tmp = usb_string(dev->udev, iMACAddress, buf, sizeof buf);
	if (tmp != 12) {
		dev_dbg(&dev->udev->dev,
			"bad MAC string %d fetch, %d\n", iMACAddress, tmp);
		if (tmp >= 0)
			tmp = -EINVAL;
		return tmp;
	}
	for (i = tmp = 0; i < 6; i++, tmp += 2)
		dev->net->dev_addr [i] =
			(nibble(buf [tmp]) << 4) + nibble(buf [tmp + 1]);
	return 0;
}
#endif
void usb_lte_arp_response(struct usbnet *dev,char*  EthPkt, unsigned long  Length ,gfp_t flags);

//#if defined(CONFIG_USB_NET_RNDIS_HOST) || defined(CONFIG_USB_NET_RNDIS_HOST_MODULE)
#if 1
static int is_rndis(struct usb_interface_descriptor *desc)
{
	return desc->bInterfaceClass == USB_CLASS_COMM
		&& desc->bInterfaceSubClass == 2
		&& desc->bInterfaceProtocol == 0xff;
}

static int is_activesync(struct usb_interface_descriptor *desc)
{
	return desc->bInterfaceClass == USB_CLASS_MISC
		&& desc->bInterfaceSubClass == 1
		&& desc->bInterfaceProtocol == 1;
}

static int is_wireless_rndis(struct usb_interface_descriptor *desc)
{
	return desc->bInterfaceClass == USB_CLASS_WIRELESS_CONTROLLER
		&& desc->bInterfaceSubClass == 1
		&& desc->bInterfaceProtocol == 3;
}

#else

#define is_rndis(desc)		0
#define is_activesync(desc)	0
#define is_wireless_rndis(desc)	0

#endif

/*
 * probes control interface, claims data interface, collects the bulk
 * endpoints, activates data interface (if needed), maybe sets MTU.
 * all pure cdc, except for certain firmware workarounds, and knowing
 * that rndis uses one different rule.
 */
int usbnet_generic_cdc_bind(struct usbnet *dev, struct usb_interface *intf)
{
	u8				*buf = intf->cur_altsetting->extra;
	int				len = intf->cur_altsetting->extralen;
	struct usb_interface_descriptor	*d;
	struct cdc_state		*info = (void *) &dev->data;
	int				status;
	int				rndis;
	struct usb_driver		*driver = driver_of(intf);

	if (sizeof dev->data < sizeof *info)
		return -EDOM;

	/* expect strict spec conformance for the descriptors, but
	 * cope with firmware which stores them in the wrong place
	 */
	if (len == 0 && dev->udev->actconfig->extralen) {
		/* Motorola SB4100 (and others: Brad Hards says it's
		 * from a Broadcom design) put CDC descriptors here
		 */
		buf = dev->udev->actconfig->extra;
		len = dev->udev->actconfig->extralen;
		if (len)
			dev_dbg(&intf->dev,
				"CDC descriptors on config\n");
	}

	/* Maybe CDC descriptors are after the endpoint?  This bug has
	 * been seen on some 2Wire Inc RNDIS-ish products.
	 */
	if (len == 0) {
		struct usb_host_endpoint	*hep;

		hep = intf->cur_altsetting->endpoint;
		if (hep) {
			buf = hep->extra;
			len = hep->extralen;
		}
		if (len)
			dev_dbg(&intf->dev,
				"CDC descriptors on endpoint\n");
	}

	/* this assumes that if there's a non-RNDIS vendor variant
	 * of cdc-acm, it'll fail RNDIS requests cleanly.
	 */
	rndis = is_rndis(&intf->cur_altsetting->desc)
		|| is_activesync(&intf->cur_altsetting->desc)
		|| is_wireless_rndis(&intf->cur_altsetting->desc);

	memset(info, 0, sizeof *info);
	info->control = intf;
	while (len > 3) {
		if (buf [1] != USB_DT_CS_INTERFACE)
			goto next_desc;

		/* use bDescriptorSubType to identify the CDC descriptors.
		 * We expect devices with CDC header and union descriptors.
		 * For CDC Ethernet we need the ethernet descriptor.
		 * For RNDIS, ignore two (pointless) CDC modem descriptors
		 * in favor of a complicated OID-based RPC scheme doing what
		 * CDC Ethernet achieves with a simple descriptor.
		 */
		switch (buf [2]) {
		case USB_CDC_HEADER_TYPE:
			if (info->header) {
				dev_dbg(&intf->dev, "extra CDC header\n");
				goto bad_desc;
			}
			info->header = (void *) buf;
			if (info->header->bLength != sizeof *info->header) {
				dev_dbg(&intf->dev, "CDC header len %u\n",
					info->header->bLength);
				goto bad_desc;
			}
			break;
		case USB_CDC_ACM_TYPE:
			/* paranoia:  disambiguate a "real" vendor-specific
			 * modem interface from an RNDIS non-modem.
			 */
			if (rndis) {
				struct usb_cdc_acm_descriptor *acm;

				acm = (void *) buf;
				if (acm->bmCapabilities) {
					dev_dbg(&intf->dev,
						"ACM capabilities %02x, "
						"not really RNDIS?\n",
						acm->bmCapabilities);
					goto bad_desc;
				}
			}
			break;
		case USB_CDC_UNION_TYPE:
			if (info->u) {
				dev_dbg(&intf->dev, "extra CDC union\n");
				goto bad_desc;
			}
			info->u = (void *) buf;
			if (info->u->bLength != sizeof *info->u) {
				dev_dbg(&intf->dev, "CDC union len %u\n",
					info->u->bLength);
				goto bad_desc;
			}

			/* we need a master/control interface (what we're
			 * probed with) and a slave/data interface; union
			 * descriptors sort this all out.
			 */
			info->control = usb_ifnum_to_if(dev->udev,
						info->u->bMasterInterface0);
			info->data = usb_ifnum_to_if(dev->udev,
						info->u->bSlaveInterface0);
			if (!info->control || !info->data) {
				dev_dbg(&intf->dev,
					"master #%u/%p slave #%u/%p\n",
					info->u->bMasterInterface0,
					info->control,
					info->u->bSlaveInterface0,
					info->data);
				goto bad_desc;
			}
			if (info->control != intf) {
				dev_dbg(&intf->dev, "bogus CDC Union\n");
				/* Ambit USB Cable Modem (and maybe others)
				 * interchanges master and slave interface.
				 */
				if (info->data == intf) {
					info->data = info->control;
					info->control = intf;
				} else
					goto bad_desc;
			}

			/* a data interface altsetting does the real i/o */
			d = &info->data->cur_altsetting->desc;
			if (d->bInterfaceClass != USB_CLASS_CDC_DATA) {
				dev_dbg(&intf->dev, "slave class %u\n",
					d->bInterfaceClass);
				goto bad_desc;
			}
			break;
		case USB_CDC_ETHERNET_TYPE:
			if (info->ether) {
				dev_dbg(&intf->dev, "extra CDC ether\n");
				goto bad_desc;
			}
			info->ether = (void *) buf;
			if (info->ether->bLength != sizeof *info->ether) {
				dev_dbg(&intf->dev, "CDC ether len %u\n",
					info->ether->bLength);
				goto bad_desc;
			}
			dev->hard_mtu = le16_to_cpu(
						info->ether->wMaxSegmentSize);
			/* because of Zaurus, we may be ignoring the host
			 * side link address we were given.
			 */
			break;
		}
next_desc:
		len -= buf [0];	/* bLength */
		buf += buf [0];
	}

	/* Microsoft ActiveSync based and some regular RNDIS devices lack the
	 * CDC descriptors, so we'll hard-wire the interfaces and not check
	 * for descriptors.
	 */
	if (rndis && !info->u) {
		info->control = usb_ifnum_to_if(dev->udev, 0);
		info->data = usb_ifnum_to_if(dev->udev, 1);
		if (!info->control || !info->data) {
			dev_dbg(&intf->dev,
				"rndis: master #0/%p slave #1/%p\n",
				info->control,
				info->data);
			goto bad_desc;
		}

	} else if (!info->header || !info->u || (!rndis && !info->ether)) {
		dev_dbg(&intf->dev, "missing cdc %s%s%sdescriptor\n",
			info->header ? "" : "header ",
			info->u ? "" : "union ",
			info->ether ? "" : "ether ");
		goto bad_desc;
	}

	/* claim data interface and set it up ... with side effects.
	 * network traffic can't flow until an altsetting is enabled.
	 */
	status = usb_driver_claim_interface(driver, info->data, dev);
	if (status < 0)
		return status;
	status = usbnet_get_endpoints(dev, info->data);
	if (status < 0) {
		/* ensure immediate exit from usbnet_disconnect */
		usb_set_intfdata(info->data, NULL);
		usb_driver_release_interface(driver, info->data);
		return status;
	}

	/* status endpoint: optional for CDC Ethernet, not RNDIS (or ACM) */
	dev->status = NULL;
	if (info->control->cur_altsetting->desc.bNumEndpoints == 1) {
		struct usb_endpoint_descriptor	*desc;

		dev->status = &info->control->cur_altsetting->endpoint [0];
		desc = &dev->status->desc;
		if (!usb_endpoint_is_int_in(desc)
				|| (le16_to_cpu(desc->wMaxPacketSize)
					< sizeof(struct usb_cdc_notification))
				|| !desc->bInterval) {
			dev_dbg(&intf->dev, "bad notification endpoint\n");
			dev->status = NULL;
		}
	}
	if (rndis && !dev->status) {
		dev_dbg(&intf->dev, "missing RNDIS status endpoint\n");
		usb_set_intfdata(info->data, NULL);
		usb_driver_release_interface(driver, info->data);
		return -ENODEV;
	}
	return 0;

bad_desc:
	dev_info(&dev->udev->dev, "bad CDC descriptors\n");
	return -ENODEV;
}
EXPORT_SYMBOL_GPL(usbnet_generic_cdc_bind);

void usbnet_cdc_unbind(struct usbnet *dev, struct usb_interface *intf)
{
	struct cdc_state		*info = (void *) &dev->data;
	struct usb_driver		*driver = driver_of(intf);
#ifdef CONFIG_CDC_ENCAP_COMMAND
	struct cdc_encap		*encap;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	encap = (struct cdc_encap *)info->header;
#else
	encap = dev->driver_priv;
#endif
	if (encap)
		cdc_encap_uninit(encap);
#endif
	/* disconnect master --> disconnect slave */
	if (intf == info->control && info->data) {
		/* ensure immediate exit from usbnet_disconnect */
		usb_set_intfdata(info->data, NULL);
		usb_driver_release_interface(driver, info->data);
		info->data = NULL;
	}

	/* and vice versa (just in case) */
	else if (intf == info->data && info->control) {
		/* ensure immediate exit from usbnet_disconnect */
		usb_set_intfdata(info->control, NULL);
		usb_driver_release_interface(driver, info->control);
		info->control = NULL;
	}
}
EXPORT_SYMBOL_GPL(usbnet_cdc_unbind);

/*-------------------------------------------------------------------------
 *
 * Communications Device Class, Ethernet Control model
 *
 * Takes two interfaces.  The DATA interface is inactive till an altsetting
 * is selected.  Configuration data includes class descriptors.  There's
 * an optional status endpoint on the control interface.
 *
 * This should interop with whatever the 2.4 "CDCEther.c" driver
 * (by Brad Hards) talked with, with more functionality.
 *
 *-------------------------------------------------------------------------*/

static void dumpspeed(struct usbnet *dev, __le32 *speeds)
{
	netif_info(dev, timer, dev->net,
		   "link speeds: %u kbps up, %u kbps down\n",
		   __le32_to_cpu(speeds[0]) / 1000,
		   __le32_to_cpu(speeds[1]) / 1000);
}

static void cdc_status(struct usbnet *dev, struct urb *urb)
{
	struct usb_cdc_notification	*event;

	if (urb->actual_length < sizeof *event)
		return;

	/* SPEED_CHANGE can get split into two 8-byte packets */
	if (test_and_clear_bit(EVENT_STS_SPLIT, &dev->flags)) {
		dumpspeed(dev, (__le32 *) urb->transfer_buffer);
		return;
	}

	event = urb->transfer_buffer;
	switch (event->bNotificationType) {
	case USB_CDC_NOTIFY_NETWORK_CONNECTION:
		netif_dbg(dev, timer, dev->net, "CDC: carrier %s\n",
			  event->wValue ? "on" : "off");
		if (event->wValue)
			netif_carrier_on(dev->net);
		else
			netif_carrier_off(dev->net);
		break;
	case USB_CDC_NOTIFY_SPEED_CHANGE:	/* tx/rx rates */
		netif_dbg(dev, timer, dev->net, "CDC: speed change (len %d)\n",
			  urb->actual_length);
		if (urb->actual_length != (sizeof *event + 8))
			set_bit(EVENT_STS_SPLIT, &dev->flags);
		else
			dumpspeed(dev, (__le32 *) &event[1]);
		break;
	/* USB_CDC_NOTIFY_RESPONSE_AVAILABLE can happen too (e.g. RNDIS),
	 * but there are no standard formats for the response data.
	 */
#ifdef CONFIG_CDC_ENCAP_COMMAND
	case USB_CDC_NOTIFY_RESPONSE_AVAILABLE:
		{
			struct cdc_encap	*encap;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
			struct cdc_state	*info = (void *) &dev->data;
			encap = (struct cdc_encap *)info->header;
#else
			encap = dev->driver_priv;
#endif
			if (encap)
				cdc_encap_response_avail(encap);
		}
		break;
#endif
	default:
		netdev_err(dev, "CDC: unexpected notification %02x!",
				 event->bNotificationType);
		break;
	}
}

static int cdc_bind(struct usbnet *dev, struct usb_interface *intf)
{
	int				status;
	struct cdc_state		*info = (void *) &dev->data;

	status = usbnet_generic_cdc_bind(dev, intf);
	if (status < 0) {
		status = usbnet_get_endpoints(dev, intf);
		if (status < 0)
			return status;
	}

	if (info->ether) {
		printk("\r\n %s,[%d]",__FUNCTION__,__LINE__);
		status = usbnet_get_ethernet_addr(dev,
			info->ether->iMACAddress);
		if (status < 0)
			goto error;
	}

	/* FIXME cdc-ether has some multicast code too, though it complains
	 * in routine cases.  info->ether describes the multicast support.
	 * Implement that here, manipulating the cdc filter as needed.
	 */
	return 0;
error:
	if (info->data) {
		usb_set_intfdata(info->data, NULL);
		usb_driver_release_interface(driver_of(intf), info->data);
	}
	return status;
}

struct cdc_iface_info {
	__u8 iface_number;
};

static const struct cdc_iface_info	zte_wcdma_ecm_iface_info = {
	.iface_number = 4
};

static const struct driver_info	zte_wcdma_ecm_dev_info = {
	.description =	"ZTE Ethernet Device",
	.flags =	FLAG_ETHER,
	.bind =		cdc_bind,
	.unbind =	usbnet_cdc_unbind,
	.status =	cdc_status,
	.data =		(unsigned long) &zte_wcdma_ecm_iface_info,
};

/*add by maxl for pid=0017*/
static const struct cdc_iface_info      zte_wcdma_ecm_iface_info_0017 = {
        .iface_number = 4 
};
static const struct cdc_iface_info      zte_wcdma_ecm_iface_info_0189 = {
        .iface_number = 4 
};
/*add by lirui for EVB_OSE_NDIS_PORT_SUPPORT 20120322 begin*/
static const struct cdc_iface_info      zte_wcdma_ecm_iface_info_0199 = {
        .iface_number = 1
};
/*add by lirui for EVB_OSE_NDIS_PORT_SUPPORT 20120322 end*/
static const struct cdc_iface_info      zte_ecm_iface_info_lte = {
        .iface_number = 3 
};

static const struct cdc_iface_info      zte_ecm_iface_info_lte_621 = {
        .iface_number = 4 
};
struct sk_buff *zte_0017_tx_fixup(struct usbnet *dev, struct sk_buff *skb,gfp_t flags)
{
        //dataprintk(skb->data,skb->len);
        return skb;
}
static const struct driver_info zte_wcdma_ecm_dev_info_0017 = {
        .description =  "ZTE Ethernet Device",
        .flags =        FLAG_ETHER,
        .bind =         cdc_bind,
        .unbind =       usbnet_cdc_unbind,
        .status =       cdc_status,
        .data =         (unsigned long) &zte_wcdma_ecm_iface_info_0017,
};
static const struct driver_info zte_wcdma_ecm_dev_info_0189 = {
        .description =  "ZTE Ethernet Device",
        .flags =        FLAG_ETHER,
        .bind =         cdc_bind,
        .unbind =       usbnet_cdc_unbind,
        .status =       cdc_status,
        .data =         (unsigned long) &zte_wcdma_ecm_iface_info_0189,
};
/*add by lirui for EVB_OSE_NDIS_PORT_SUPPORT 20120322 begin*/
static const struct driver_info zte_wcdma_ecm_dev_info_0199 = {
        .description =  "ZTE Ethernet Device",
        .flags =        FLAG_ETHER,
        .bind =         cdc_bind,
        .unbind =       usbnet_cdc_unbind,
        .status =       cdc_status,
        .data =         (unsigned long) &zte_wcdma_ecm_iface_info_0199,
};
/*add by lirui for EVB_OSE_NDIS_PORT_SUPPORT 20120322 end*/
static int lte_rx_fixup(struct usbnet *dev, struct sk_buff *skb)
{
	skb_push(skb,14);
	memcpy(skb->data,dev->net->dev_addr,6);
	memcpy(skb->data+6,LTE_DST_MAC_ADDR,8);
	return 1;
}
static struct sk_buff *lte_tx_fixup(struct usbnet *dev, struct sk_buff *skb,gfp_t flags)
{
        struct ethhdr *eth = (struct ethhdr *)skb->data;
        struct net_device *net  = dev->net;
        struct in_device *in_dev  = net->ip_ptr;
        struct in_ifaddr * ifa4 = in_dev->ifa_list;
        unsigned char  temp_ha[ETH_LENGTH_OF_ADDRESS] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	 unsigned char  fix_header[ETH_LENGTH_OF_ADDRESS] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
        unsigned char respond = 0;     
        plte_arp_header arp_hdr = NULL;
        unsigned int ulret = 0;
#if 1
        switch (ntohs(eth->h_proto))
        {
                case ETH_TYPE_ARP:  // && IPV4
                {       // locally process ARP under IPV4
                        if (ifa4 != NULL){
                                arp_hdr = (plte_arp_header)(skb->data + 14);
                               // Ignore non-Ethernet HW type and non-request Operation
                                if ((ntohs(arp_hdr->hardware_type) !=0x0001) || (ntohs(arp_hdr->operation) != 0x0001))
                                        return skb;
                                // Ignore non-IPV4 protocol type
                                if (ntohs(arp_hdr->protocol_type) != ETH_TYPE_IPV4)
                                        return skb;
                                // Validate HLEN and PLEN
                                if (arp_hdr->hlen != ETH_LENGTH_OF_ADDRESS)
                                        return skb;
                                if (arp_hdr->plen != 4)
                                        return skb;
                                // Ignore gratuitous ARP
                                if (*(unsigned int *)(arp_hdr->sender_ip) == *(unsigned int *)(arp_hdr->target_ip))
                                        return skb;
                                // Request for HA
                                ulret = memcmp(arp_hdr->target_ha, temp_ha, ETH_LENGTH_OF_ADDRESS);
                                // DAD
                                if ((*(unsigned int *)arp_hdr->sender_ip == 0) && (*(unsigned int *)(arp_hdr->target_ip) !=ifa4->ifa_address))
                                {
                                      respond = 1;
                                }
                                else if ((*(unsigned int *)arp_hdr->sender_ip != 0) && (0 == ulret))
                                {
                                      respond = 1;
                                }
                                
                                if (respond == 1)
                                {// respond with canned ARP
                                        usb_lte_arp_response(dev, skb->data , skb->len, flags);
                                }
                                return 0;                       
                        }else
                        {
                            return skb;
                        }
             }
             case ETH_TYPE_IPV4:  // && IPV4
             {
                skb_pull(skb,8);
                memcpy(skb->data,fix_header,ETH_LENGTH_OF_ADDRESS);
                //dataprintk(skb->data,skb->len);    
                return skb;
             }
             case ETH_TYPE_IPV6:  // && IPV4
             {
                  return skb;
             }
             default:
             {
                  return skb;
             }
      }
#endif
      return skb;
}

void usb_lte_arp_response(struct usbnet *dev, char* EthPkt, unsigned long Length ,gfp_t flags)
{
        pqc_eth_hdr        eth_hdr;
        plte_arp_header        arp_hdr;
        struct sk_buff *      data_pkt;
        char *                     p;
        struct net_device *net  = dev->net;
        struct in_device *in_dev4  = net->ip_ptr;
        struct in_ifaddr * ifa4 = in_dev4->ifa_list;
        // 1. Allocate new buffer for the response
        if ((data_pkt = alloc_skb(Length + NET_IP_ALIGN, flags)) == NULL) {
                    printk( "LeMaker : no rx skb");
                return;
        }
        skb_reserve (data_pkt, NET_IP_ALIGN);
        // 2. Formulate the response
        // Target: arp_hdr->sender_ha & arp_hdr->SenderIP
        // Sender: pAdapter->MacAddress2 & pAdapter->IPV4Address
        memcpy(data_pkt->data, EthPkt, Length);
        data_pkt->len=Length;
        p = (char *)data_pkt->data;
        // Ethernet header
        eth_hdr = (pqc_eth_hdr)p;
        memcpy(eth_hdr->dst_mac_address, eth_hdr->src_mac_address, ETH_LENGTH_OF_ADDRESS);
        memcpy(eth_hdr->src_mac_address, LTE_DST_MAC_ADDR, ETH_LENGTH_OF_ADDRESS);
        // ARP Header
        arp_hdr = (plte_arp_header)(p + 14);
        // target/requestor MAC and IP
        memcpy(arp_hdr->target_ha, arp_hdr->sender_ha, ETH_LENGTH_OF_ADDRESS);
        memcpy(arp_hdr->sender_ip, arp_hdr->target_ip, 4);
        // sender/remote MAC and IP
        memcpy(arp_hdr->sender_ha, LTE_DST_MAC_ADDR, ETH_LENGTH_OF_ADDRESS);
        memcpy(arp_hdr->target_ip,(char *)&(ifa4->ifa_address), ETH_LENGTH_OF_ADDRESS);
        // Operation:reply
        arp_hdr->operation = ntohs(0x0002);
        //dataprintk(data_pkt->data, Length);
        usbnet_skb_return (dev, data_pkt);
}  // usb_lte_arp_response

static const struct driver_info zte_ecm_dev_info_lte = {
        .description =  "ZTE Ethernet Device",
        .flags =        FLAG_ETHER,
        .bind =         cdc_bind,
        .unbind =       usbnet_cdc_unbind,
        .status =       cdc_status,
        //.rx_fixup =     lte_rx_fixup,
        //.tx_fixup =     lte_tx_fixup,
        .data =         (unsigned long) &zte_ecm_iface_info_lte,
};

static const struct driver_info zte_ecm_dev_info_lte_621 = {
        .description =  "ZTE Ethernet Device",
        .flags =        FLAG_ETHER,
        .bind =         cdc_bind,
        .unbind =       usbnet_cdc_unbind,
        .status =       cdc_status,
        .data =         (unsigned long) &zte_ecm_iface_info_lte_621,
};
static int
cdc_probe(struct usb_interface *intf, const struct usb_device_id *prod)
{
	struct driver_info	*info;
	int			status;
#ifdef CONFIG_CDC_ENCAP_COMMAND
	struct cdc_encap	*encap;
	struct usbnet		*unet;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	struct cdc_state	*cdc_info;
#endif
#endif
	#ifdef lr_debug_open
    printk(" enter cdc_probe  status=%x,encap->iface_num=%x,encap->opened=%x,encap->rsp_ready=%x\n",status,encap->iface_num,encap->opened,encap->rsp_ready);
    struct usb_device		*xdev;

    xdev = interface_to_usbdev (intf);

    printk("usbdev add.................%0x\n", xdev);

	#endif
	info = (struct driver_info *) prod->driver_info;

	if (info)
		dev_dbg(&intf->dev, "%s: Probe\n", info->description);

	if (info && info->data) {
		__u8			iface_num;
		struct cdc_iface_info	*iface_info;

		iface_num = intf->cur_altsetting->desc.bInterfaceNumber;
		iface_info = (struct cdc_iface_info *) info->data;

		dev_dbg (&intf->dev, "%s: trying iface %d\n",
			info->description, iface_num);

		if (iface_info->iface_number != iface_num)
			return -ENODEV;

		dev_info(&intf->dev, "%s: claiming interface %d\n",
			info->description, iface_num);
	}

	status = usbnet_probe(intf, prod);
	if (status < 0)
		return status;


#ifdef CONFIG_CDC_ENCAP_COMMAND
	unet = usb_get_intfdata(intf);

	status = cdc_encap_init(unet->net->name, intf,
		USB_CDC_SUBCLASS_ETHERNET, &encap);
	if (status < 0) {
		dev_dbg(&intf->dev, "failed to init encapsulation command\n");
		return 0;
	}
    	if(0x02 == prod->bInterfaceClass && 0x06 == prod->bInterfaceSubClass)	
	{    /* Ecm dial mode*/
             encap->ecm_ndis_dial_mode = 1;
	}else
	{     /* ndis dial mode*/
		encap->ecm_ndis_dial_mode = 2;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	cdc_info = (void *) &unet->data;
	cdc_info->header = (struct usb_cdc_header_desc *)encap;
#else
	unet->driver_priv = encap;
#endif
#endif

	#ifdef lr_debug_open
    printk(" cdc_probe ok  status=%x,encap->iface_num=%x,encap->opened=%x,encap->rsp_ready=%x\n",status,encap->iface_num,encap->opened,encap->rsp_ready);
	#endif

	return 0;
}
/* For other non-standard CDC ECM devices remove the cdc_bind function to use
 * generic probe mechnaism and place the product entry at the beginning of White
 * list */
static const struct driver_info	cdc_info = {
	.description =	"CDC Ethernet Device",
	.flags =	FLAG_ETHER,
	// .check_connect = cdc_check_connect,
	.bind =		cdc_bind,
	.unbind =	usbnet_cdc_unbind,
	.status =	cdc_status,
};

/*-------------------------------------------------------------------------*/


static const struct usb_device_id	products [] = {
/*
 * BLACKLIST !!
 *
 * First blacklist any products that are egregiously nonconformant
 * with the CDC Ethernet specs.  Minor braindamage we cope with; when
 * they're not even trying, needing a separate driver is only the first
 * of the differences to show up.
 */

#define	ZAURUS_MASTER_INTERFACE \
	.bInterfaceClass	= USB_CLASS_COMM, \
	.bInterfaceSubClass	= USB_CDC_SUBCLASS_ETHERNET, \
	.bInterfaceProtocol	= USB_CDC_PROTO_NONE

/* SA-1100 based Sharp Zaurus ("collie"), or compatible;
 * wire-incompatible with true CDC Ethernet implementations.
 * (And, it seems, needlessly so...)
 */
{
	.match_flags	=   USB_DEVICE_ID_MATCH_INT_INFO
			  | USB_DEVICE_ID_MATCH_DEVICE,
	.idVendor		= 0x04DD,
	.idProduct		= 0x8004,
	ZAURUS_MASTER_INTERFACE,
	.driver_info		= 0,
},

/* PXA-25x based Sharp Zaurii.  Note that it seems some of these
 * (later models especially) may have shipped only with firmware
 * advertising false "CDC MDLM" compatibility ... but we're not
 * clear which models did that, so for now let's assume the worst.
 */
{
	.match_flags	=   USB_DEVICE_ID_MATCH_INT_INFO
			  | USB_DEVICE_ID_MATCH_DEVICE,
	.idVendor		= 0x04DD,
	.idProduct		= 0x8005,	/* A-300 */
	ZAURUS_MASTER_INTERFACE,
	.driver_info		= 0,
}, {
	.match_flags	=   USB_DEVICE_ID_MATCH_INT_INFO
			  | USB_DEVICE_ID_MATCH_DEVICE,
	.idVendor		= 0x04DD,
	.idProduct		= 0x8006,	/* B-500/SL-5600 */
	ZAURUS_MASTER_INTERFACE,
	.driver_info		= 0,
}, {
	.match_flags    =   USB_DEVICE_ID_MATCH_INT_INFO
	          | USB_DEVICE_ID_MATCH_DEVICE,
	.idVendor		= 0x04DD,
	.idProduct		= 0x8007,	/* C-700 */
	ZAURUS_MASTER_INTERFACE,
	.driver_info		= 0,
}, {
	.match_flags    =   USB_DEVICE_ID_MATCH_INT_INFO
		 | USB_DEVICE_ID_MATCH_DEVICE,
	.idVendor               = 0x04DD,
	.idProduct              = 0x9031,	/* C-750 C-760 */
	ZAURUS_MASTER_INTERFACE,
	.driver_info		= 0,
}, {
	.match_flags    =   USB_DEVICE_ID_MATCH_INT_INFO
		 | USB_DEVICE_ID_MATCH_DEVICE,
	.idVendor               = 0x04DD,
	.idProduct              = 0x9032,	/* SL-6000 */
	ZAURUS_MASTER_INTERFACE,
	.driver_info		= 0,
}, {
	.match_flags    =   USB_DEVICE_ID_MATCH_INT_INFO
		 | USB_DEVICE_ID_MATCH_DEVICE,
	.idVendor               = 0x04DD,
	/* reported with some C860 units */
	.idProduct              = 0x9050,	/* C-860 */
	ZAURUS_MASTER_INTERFACE,
	.driver_info		= 0,
},

/* Olympus has some models with a Zaurus-compatible option.
 * R-1000 uses a FreeScale i.MXL cpu (ARMv4T)
 */
{
	.match_flags    =   USB_DEVICE_ID_MATCH_INT_INFO
		 | USB_DEVICE_ID_MATCH_DEVICE,
	.idVendor               = 0x07B4,
	.idProduct              = 0x0F02,	/* R-1000 */
	ZAURUS_MASTER_INTERFACE,
	.driver_info		= 0,
},

/*
 * WHITELIST!!!
 *
 * CDC Ether uses two interfaces, not necessarily consecutive.
 * We match the main interface, ignoring the optional device
 * class so we could handle devices that aren't exclusively
 * CDC ether.
 *
 * NOTE:  this match must come AFTER entries blacklisting devices
 * because of bugs/quirks in a given product (like Zaurus, above).
 */
{
	/* ZTE WCDMA Technologies MSM */
	USB_DEVICE_AND_INTERFACE_INFO(0x19d2, 0x0104, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long) &zte_wcdma_ecm_dev_info,
}, {
	/* ZTE WCDMA Technologies MSM */
	USB_DEVICE_AND_INTERFACE_INFO(0x19D2, 0x0167, 0xff, 0xff, 0xff),
        .driver_info = (unsigned long) &zte_ecm_dev_info_lte_621,
},{
	/* ZTE WCDMA Technologies MSM */
	USB_DEVICE_AND_INTERFACE_INFO(0x05c6, 0x9001, 0xff, 0xff, 0xff),
        .driver_info = (unsigned long) &zte_ecm_dev_info_lte,
},{
	USB_DEVICE_AND_INTERFACE_INFO(0x19d2, 0x0037, 0xff, 0xff, 0xff),
        .driver_info = (unsigned long) &zte_wcdma_ecm_dev_info,
},{
	USB_DEVICE_AND_INTERFACE_INFO(0x19d2, 0x0017, 0xff, 0xff, 0xff),
        .driver_info = (unsigned long) &zte_wcdma_ecm_dev_info_0017,
},{
	USB_DEVICE_AND_INTERFACE_INFO(0x19d2, 0x0189, 0xff, 0xff, 0xff),
        .driver_info = (unsigned long) &zte_wcdma_ecm_dev_info_0189,
},{
/*add by lirui for EVB_OSE_NDIS_PORT_SUPPORT 20120322 begin*/
	USB_DEVICE_AND_INTERFACE_INFO(0x19d2, 0x0199, 0xff, 0xff, 0xff),
        .driver_info = (unsigned long) &zte_wcdma_ecm_dev_info_0199,
},{
/*add by lirui for EVB_OSE_NDIS_PORT_SUPPORT 20120322 end*/
	USB_INTERFACE_INFO(USB_CLASS_COMM, USB_CDC_SUBCLASS_ETHERNET,
			USB_CDC_PROTO_NONE),
	.driver_info = (unsigned long) &cdc_info,
}, {
	/* Ericsson F3507g */
	USB_DEVICE_AND_INTERFACE_INFO(0x0bdb, 0x1900, USB_CLASS_COMM,
			USB_CDC_SUBCLASS_MDLM, USB_CDC_PROTO_NONE),
	.driver_info = (unsigned long) &cdc_info,
}, {
	/* Ericsson F3507g ver. 2 */
	USB_DEVICE_AND_INTERFACE_INFO(0x0bdb, 0x1902, USB_CLASS_COMM,
			USB_CDC_SUBCLASS_MDLM, USB_CDC_PROTO_NONE),
	.driver_info = (unsigned long) &cdc_info,
}, {
	/* Ericsson F3607gw */
	USB_DEVICE_AND_INTERFACE_INFO(0x0bdb, 0x1904, USB_CLASS_COMM,
			USB_CDC_SUBCLASS_MDLM, USB_CDC_PROTO_NONE),
	.driver_info = (unsigned long) &cdc_info,
}, {
	/* Ericsson F3307 */
	USB_DEVICE_AND_INTERFACE_INFO(0x0bdb, 0x1906, USB_CLASS_COMM,
			USB_CDC_SUBCLASS_MDLM, USB_CDC_PROTO_NONE),
	.driver_info = (unsigned long) &cdc_info,
}, {
	/* Toshiba F3507g */
	USB_DEVICE_AND_INTERFACE_INFO(0x0930, 0x130b, USB_CLASS_COMM,
			USB_CDC_SUBCLASS_MDLM, USB_CDC_PROTO_NONE),
	.driver_info = (unsigned long) &cdc_info,
}, {
	/* Dell F3507g */
	USB_DEVICE_AND_INTERFACE_INFO(0x413c, 0x8147, USB_CLASS_COMM,
			USB_CDC_SUBCLASS_MDLM, USB_CDC_PROTO_NONE),
	.driver_info = (unsigned long) &cdc_info,
},
	{ },		// END
};
MODULE_DEVICE_TABLE(usb, products);

static struct usb_driver cdc_driver = {
	.name =		"cdc_ether",
	.id_table =	products,
	.probe =	cdc_probe,
	.disconnect =	usbnet_disconnect,
	.suspend =	usbnet_suspend,
	.resume =	usbnet_resume,
};


static int __init cdc_init(void)
{
	BUILD_BUG_ON((sizeof(((struct usbnet *)0)->data)
			< sizeof(struct cdc_state)));

 	return usb_register(&cdc_driver);
}
module_init(cdc_init);

static void __exit cdc_exit(void)
{
 	usb_deregister(&cdc_driver);
}
module_exit(cdc_exit);

MODULE_AUTHOR("David Brownell");
MODULE_DESCRIPTION("USB CDC Ethernet devices");
MODULE_LICENSE("GPL");
