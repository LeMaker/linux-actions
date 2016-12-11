/*********************************************************************************
*                            Module: usb monitor driver
*                (c) Copyright 2003 - 2008, Actions Co,Ld. 
*                        All Right Reserved 
*
* History:        
*      <author>      <time>       <version >    <desc>
*       houjingkun   2011/07/08   1.0         build this file 
********************************************************************************/
/*!
 * \file   umonitor_core.c
 * \brief  
 *      usb monitor detect opration code.
 * \author houjingkun
 * \par GENERAL DESCRIPTION:
 * \par EXTERNALIZED FUNCTIONS:
 *       null
 *
 *  Copyright(c) 2008-2012 Actions Semiconductor, All Rights Reserved.
 *
 * \version 1.0
 * \date  2011/07/08
 *******************************************************************************/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/ioctl.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/platform_device.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/poll.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <linux/ctype.h>
#include <mach/hardware.h>
#include <linux/io.h>

#include "aotg_regs.h"
#include "umonitor_config.h"
#include "umonitor_core.h"


enum {
	USB_DET_NONE = 0,	/* nothing detected, maybe B plus is out. */
	USB_DET_DEVICE_DEBUOUNCING,	/* detected device, debouncing and confirming. */
	USB_DET_DEVICE_PC,	/* detected device confirmed. pc connected. */
	USB_DET_DEVICE_CHARGER	/* detected device confirmed. charger connected. */
};

enum {
	USB_DET_HOST_NONE = 0,	/* nothing detected. maybe udisk is plug out. */
	USB_DET_HOST_DEBOUNCING,	/* detecting host, debouncing and confirming. */
	USB_DET_HOST_UDISK	/* detected udisk confirmed. udisk connected. */
};

#define USB_DEVICE_DETECT_STEPS    4
#define USB_HOST_DETECT_STEPS      4
#define USB_MONITOR_DEF_INTERVAL   500	/* interval to check usb port state, unit: ms. */

umonitor_dev_status_t *umonitor_status;
static int usb_monitor_debug_status_inf( void )
{
#if 0
	umonitor_dev_status_t *pStatus = umonitor_status;

	printk(KERN_INFO ".det_phase %d %d %d %d %d \n",
	       (unsigned int) pStatus->det_phase,
	       (unsigned int) pStatus->vbus_status,
	       (unsigned int) pStatus->timer_steps,
	       (unsigned int) pStatus->host_confirm,
	       (unsigned int) pStatus->message_status);
	printk(KERN_INFO "-----------------------------\n");
	printk(KERN_INFO ".vbus_status %d %x \n", (unsigned int) pStatus->vbus_status,
	       (unsigned int) pStatus->vbus_status);
	printk(KERN_INFO ".vbus_enable_power %d\n", (unsigned int) pStatus->vbus_enable_power);
	printk(KERN_INFO ".det_phase %d \n", (unsigned int) pStatus->det_phase);
	printk(KERN_INFO ".device_confirm %d\n", (unsigned int) pStatus->device_confirm);
	printk(KERN_INFO ".host_confirm %d \n", (unsigned int) pStatus->host_confirm);
	printk(KERN_INFO ".usb_pll_on %d \n", (unsigned int) pStatus->usb_pll_on);
	printk(KERN_INFO ".dp_dm_status %d 0x%x \n", (unsigned int) pStatus->dp_dm_status,
	       (unsigned int) pStatus->dp_dm_status);
	printk(KERN_INFO ".timer_steps %d \n", (unsigned int) pStatus->timer_steps);
	printk(KERN_INFO ".timer_interval %d \n", (unsigned int) pStatus->timer_interval);
	printk(KERN_INFO ".check_cnt %d \n", (unsigned int) pStatus->check_cnt);
	printk(KERN_INFO ".sof_check_times %d\n", (unsigned int) pStatus->sof_check_times);
	printk(KERN_INFO "\n \n ");
#endif
	return 0;
}

static int usb_init_monitor_status(umonitor_dev_status_t * pStatus)
{
  
	pStatus->detect_valid = 0;
	pStatus->detect_running = 0;
	pStatus->vbus_status = 0;
	pStatus->dc5v_status = 0;
	pStatus->det_phase = 0;
	pStatus->device_confirm = 0;
	pStatus->sof_check_times = 0;
	pStatus->host_confirm = 0;
	pStatus->usb_pll_on = 0;
	pStatus->dp_dm_status = 0;
	pStatus->timer_steps = 0;
	pStatus->timer_interval = USB_MONITOR_DEF_INTERVAL;
	pStatus->check_cnt = 0;
	pStatus->message_status = 0;
	pStatus->core_ops = NULL;
		
	pStatus->vbus_enable_power = 0;
	
	return 0;
}

/* ��ȡ���е���һ�μ���ʱ����������ֵ�Ժ���Ϊ��λ�� */
unsigned int umonitor_get_timer_step_interval(void)
{
	umonitor_dev_status_t *pStatus;

	pStatus = umonitor_status;

	if ((pStatus->port_config->detect_type == UMONITOR_DISABLE)
		|| (pStatus->detect_valid == 0)) {
		return 0x70000000;	/* be longer enough that it would not run again. */
	}

	if (pStatus->timer_steps == 0) {
		//pStatus->timer_interval = USB_MONITOR_DEF_INTERVAL;
		pStatus->timer_interval = 30;	/*���½���step 0 ��� */
		goto out;
	}

	if (pStatus->det_phase == 0) {
		switch (pStatus->timer_steps) {
			/* 
			 * 1��3�������ʱ����500 ms���ɵ�������һ���˿��б仯���ϵ������Ĳ���
			 * ����debounce��confirm״̬��
			 */
		case 1:
		case 2:
		case 3:
			pStatus->timer_interval = USB_MONITOR_DEF_INTERVAL;
			break;

		case 4:
			switch (pStatus->device_confirm) {
			case 0:	/* �����4������һ���Ǽ��˿�vbus���ޱ仯�� */
				pStatus->timer_interval =
				    USB_MONITOR_DEF_INTERVAL;
				break;

			case 1:	/* �Ѿ���⵽�˿�vbus�е磬��Ҫ��һ����ȷ��һ�Ρ� */
				pStatus->timer_interval = 10;	/* 10 ms, 1 tick. */
				break;

				/*
				 * device_confirm == 2, �Ѿ�ȷ��vbus�е磬��enable����500k��
				 * disable����15k����һ�����dp��dm״̬�� 
				 */
			case 2:
				pStatus->timer_interval = 300;
				break;

				/* ��һ�λ�ȡdp��dm״̬����Ҫ��һ����ȷ��һ�Ρ� */
			case 3:
				pStatus->timer_interval = 30;
				break;

				/* 
				 * ������һ������Ҫ����ж�pc�Ƿ���sof��reset�źŸ�С��������ÿ20�����ѯsof�ж�һ�Σ�
				 * �ۻ����ѯ MAX_DETECT_SOF_CNT �Σ��ȴ�ʱ����ܻ���8�����ϡ� 
				 * ��Ϊ��С��dp������pc��sof���м������ʱ����8�����ϡ�
				 */
				/* wait sof again time interval, the whole detect sof time is (20 * sof_check_times) msecond. */
			case 4:
				pStatus->timer_interval = 20;
				break;

			default:
				USB_ERR_PLACE;
				pStatus->timer_interval =
				    USB_MONITOR_DEF_INTERVAL;
				break;
			}
			break;

		default:
			USB_ERR_PLACE;
			pStatus->timer_interval = USB_MONITOR_DEF_INTERVAL;
			break;
		}
	} else {
		switch (pStatus->timer_steps) {
		case 1:	/* ��step 0��idle״̬�л���vbus���⹩���ʱ������ */
			pStatus->timer_interval = 30;
			break;

		case 2:	/* vbus���⹩��󣬵���ʼ��2�μ�⣬�ж�dp�Ƿ�������ʱ�䡣 */
			pStatus->timer_interval = 600;
			break;

		case 3:	/* ��2�μ�⵽��3�μ��֮�䣬�ж�dp�Ƿ�������ʱ�䡣 */
			pStatus->timer_interval = 600;
			break;

		case 4:
			switch (pStatus->host_confirm) {
			case 0:
				pStatus->timer_interval =
				    USB_MONITOR_DEF_INTERVAL;
				break;

			case 1:	/* debounce time. */
				pStatus->timer_interval = 10;	/* 10 ms, 1 tick. */
				break;

			default:
				USB_ERR_PLACE;
				pStatus->timer_interval =
				    USB_MONITOR_DEF_INTERVAL;
				break;
			}
			break;

		default:
			USB_ERR_PLACE;
			pStatus->timer_interval = USB_MONITOR_DEF_INTERVAL;
			break;
		}
	}

out:
	return pStatus->timer_interval;
}

/* 
 * retval:
 * refer to below macro:
 *    USB_DET_NONE,
 *    USB_DET_DEVICE_DEBUOUNCING,
 *    USB_DET_DEVICE_PC,
 *    USB_DET_DEVICE_CHARGER,  
 */
static int usb_timer_det_pc_charger(umonitor_dev_status_t * pStatus)
{
	int ret = 0;
	unsigned int val = 0;
	usb_hal_monitor_t *p_hal = &pStatus->umonitor_hal;
	
	MONITOR_PRINTK("entring usb_timer_det_pc_charger\n");

	if (pStatus->device_confirm == 0) {
		/* make sure power off. */
		if (pStatus->vbus_enable_power != 0) {
			p_hal->vbus_power_onoff(p_hal, 0);
			pStatus->vbus_enable_power = 0;
			p_hal->set_soft_id(p_hal, 1, 1);
		}
	}

	pStatus->vbus_status = (unsigned char) p_hal->get_vbus_state(p_hal);

	if (pStatus->vbus_status == USB_VBUS_HIGH) {
      MONITOR_PRINTK("vbus is high!!!!!!!\n");
		/* 
		 * if B_IN is send out, needn't check device at all. 
		 * ����ֻ�����Ȳ�������������£����pc�����ӺͶϿ������������pc������ڳ�����Ĳ�μ�ⲻ�ˡ�
		 */
		if ((pStatus->message_status & (0x1 << MONITOR_B_IN)) != 0) {
#if 0
			/*
			 * �˶δ��뱾Ϊ���Բ�ڳ������pcͬʱ���������¼��pc�İ��ߣ���ʵ���ϴ������ж�pc���ߵ������
			 * ��Ϊpc��sof�����ڶ�η���δ����һ��ʱ���ڲ��ٷ��͡�
			 */
			/* if pc is connected, and charger is new plug in, we ignore it. */
			if ((pStatus->message_status &
			     (0x1 << MONITOR_CHARGER_IN)) == 0)
#endif
			pStatus->device_confirm = 0;
			pStatus->timer_steps = 0;
			ret = USB_DET_DEVICE_PC;
			goto out2;
		}
		if ((pStatus->message_status & (0x1 << MONITOR_CHARGER_IN)) != 0) {
			pStatus->device_confirm = 0;
			pStatus->timer_steps = 0;
			ret = USB_DET_DEVICE_CHARGER;
			goto out2;
		}

		switch (pStatus->device_confirm) {
			/* �����4������⵽�˿�vbus�е硣����deboundceһ�Σ�ȷ�������ȷ�� */
		case 0:
			pStatus->timer_steps = USB_DEVICE_DETECT_STEPS;	/* the last timer_steps is to confirm. */
			pStatus->device_confirm = 1;
			ret = USB_DET_DEVICE_DEBUOUNCING;
			goto out2;

			/* �Ѿ�ȷ��vbus�е磬��enable����500k��disable����15k����һ�����dp��dm״̬�� */
		case 1:
			p_hal->set_dp_500k_15k(p_hal, 1, 0);	/* 500k up enable, 15k down disable; */
			pStatus->device_confirm = 2;
			ret = USB_DET_DEVICE_DEBUOUNCING;
			goto out2;

			/* ��һ�λ�ȡdp��dm״̬����Ҫ��ȷ��һ�Ρ� */
		case 2:
			pStatus->dp_dm_status = p_hal->get_linestates(p_hal);	// get dp dm status.
			pStatus->device_confirm = 3;
			//pStatus->device_confirm = 2;  /* always in get dp dm states, just for test. */
			ret = USB_DET_DEVICE_DEBUOUNCING;
			goto out2;

			/* 
			 * �ڶ��λ�ȡdp��dm״̬��������β��䣬��ȷ��ok�������һ��debounce��
			 * dp��dm��0״̬Ϊ���������֮��һ���ж�sof�ж�λ�����Ƿ�pc��
			 */
		case 3:
			val = p_hal->get_linestates(p_hal);	// get dp dm status.
			pStatus->sof_check_times = 0;
			if (val == pStatus->dp_dm_status) {
				if (val == 0x00) {
					pStatus->timer_steps = 0;
					pStatus->device_confirm = 0;
					ret = USB_DET_DEVICE_PC;
					
					goto out2;
				} else {
					pStatus->device_confirm = 0;
					/* if enable monitor again, it should begin from step 0.  */
					pStatus->timer_steps = 0;
					ret = USB_DET_DEVICE_PC;
					goto out2;
				}
			} else {
				pStatus->device_confirm = 1;
				ret = USB_DET_DEVICE_DEBUOUNCING;
				goto out2;
			}

			/* 
			 * ������һ������Ҫ����ж�pc�Ƿ���sof��reset�źŸ�С����
			 * �ȴ�ʱ����ܻ���8�����ϡ� ��Ϊ��С��dp������pc��sof���м������ʱ����8�����ϡ�
			 */
			/* for detect sof or reset irq. */
		case 4:
			val = p_hal->is_sof(p_hal);
			if (val != 0) {
				/* if enable monitor again, it should begin from step 0. */
				pStatus->timer_steps = 0;
				pStatus->device_confirm = 0;
				pStatus->sof_check_times = 0;
				p_hal->dp_down(p_hal);
				ret = USB_DET_DEVICE_PC;
				goto out2;
			}
			if (pStatus->sof_check_times < MAX_DETECT_SOF_CNT) {	/* 10 * MAX_DETECT_SOF_CNT ms. */
				pStatus->device_confirm = 4;	/* next step still check again. */
				pStatus->sof_check_times++;
				ret = USB_DET_DEVICE_DEBUOUNCING;
				goto out2;
			}

			/* if enable monitor again, it should begin from step 0. */
			pStatus->timer_steps = 0;
			pStatus->device_confirm = 0;
			pStatus->sof_check_times = 0;
			p_hal->dp_down(p_hal);
			/* treated as charger in. */
			ret = USB_DET_DEVICE_CHARGER;
			goto out2;

		default:
			MONITOR_ERR("into device confirm default, err!\n");
			pStatus->device_confirm = 0;
			ret = USB_DET_NONE;
			goto out;
		}
	} else {	  
		pStatus->device_confirm = 0;
		pStatus->timer_steps =USB_DEVICE_DETECT_STEPS;
		ret = USB_DET_NONE;
		goto out;
	}

      out:
	pStatus->timer_steps++;
	if (pStatus->timer_steps > USB_DEVICE_DETECT_STEPS) {
		pStatus->timer_steps = 0;
	}
      out2:
	return ret;
}

/* 
 * retval:
 * refer to below macro:
 *    USB_DET_HOST_NONE,
 *    USB_DET_HOST_DEBOUNCING,
 *    USB_DET_HOST_UDISK,
 */
static int usb_timer_det_udisk(umonitor_dev_status_t * pStatus)
{
	unsigned int val;
	usb_hal_monitor_t *p_hal = &pStatus->umonitor_hal;

	if (pStatus->timer_steps == 1) {

		p_hal->set_dp_500k_15k(p_hal, 0, 1);	/* disable 500k, enable 15k. */

		if (pStatus->vbus_enable_power == 0) {
			p_hal->vbus_power_onoff(p_hal, 1);
			pStatus->vbus_enable_power = 1;
			p_hal->set_soft_id(p_hal, 1, 0);
		}
		goto out;
	} else {
		if (pStatus->vbus_enable_power != 1) {
			USB_ERR_PLACE;
		}
		   
		val = p_hal->get_linestates(p_hal);	// get dp dm status.
		MONITOR_PRINTK("host debounce!!!, linestate %04x\n", val);
		
    pStatus->timer_steps = 0;
    pStatus->host_confirm = 0;
    return USB_DET_HOST_UDISK;
		    
		if ((val == 0x1) || (val == 0x2)) {
			switch (pStatus->host_confirm) {
			case 0:
				pStatus->host_confirm = 1;
				/* the last step is always debounce and confirm step. */
				pStatus->timer_steps = USB_HOST_DETECT_STEPS;
				pStatus->dp_dm_status = val;
				return USB_DET_HOST_DEBOUNCING;

			case 1:
				if (val == pStatus->dp_dm_status) {
					/* if enable monitor again, it should begin from step 0.  */
					pStatus->timer_steps = 0;
					pStatus->host_confirm = 0;
					return USB_DET_HOST_UDISK;
				} else {
					pStatus->dp_dm_status = val;
					pStatus->host_confirm = 0;
					return USB_DET_HOST_DEBOUNCING;
				}

			default:
				break;
			}
		} else {
			pStatus->host_confirm = 0;
			goto out;
		}
	}

out:
	pStatus->timer_steps++;
	if (pStatus->timer_steps > USB_HOST_DETECT_STEPS) {
		pStatus->timer_steps = 0;
		return USB_DET_HOST_NONE;	/* nothing detect, maybe udisk is plug out. */
	}
	return USB_DET_HOST_DEBOUNCING;
}

/* 
 * ����ָ���step 0������0�����������step 0�׶β�����device��⻹��host��⣬
 * ��ֻ�ǻָ���һ��Ĭ��״̬��Ϊ��һ��device��host�����׼���� 
 */
static int usb_timer_process_step0(umonitor_dev_status_t * pStatus)
{
	int ret = 0;
	unsigned int status = 0;
	usb_hal_monitor_t *p_hal = &pStatus->umonitor_hal;
	
	MONITOR_PRINTK("entring usb_timer_process_step0\n");

	if ((pStatus->message_status & (0x1 << MONITOR_B_IN)) != 0) {
		MONITOR_PRINTK("\n%s--%d, SYS_MSG_USB_B_OUT\n", __FUNCTION__, __LINE__);
		printk(KERN_DEBUG "\n%s--%d, SYS_MSG_USB_B_OUT\n", __FUNCTION__, __LINE__);
		pStatus->core_ops->putt_msg(MON_MSG_USB_B_OUT);
		pStatus->message_status =pStatus->message_status & (~(0x1 << MONITOR_B_IN));
	}

	if ((pStatus->message_status & (0x1 << MONITOR_A_IN)) != 0) {
		MONITOR_PRINTK("\n%s--%d, SYS_MSG_USB_A_OUT\n", __FUNCTION__, __LINE__);
		printk(KERN_DEBUG "\n%s--%d, SYS_MSG_USB_A_OUT\n", __FUNCTION__, __LINE__);
		pStatus->core_ops->putt_msg(MON_MSG_USB_A_OUT);
		pStatus->message_status = pStatus->message_status & (~(0x1 << MONITOR_A_IN));
	}

	/*
	 * ������id pin, ����gpio���idpin�����, ��idpinΪ0, ������һֱ����host���״̬,
	 * ��Ҫ��vbus����. һֱvbus����,���Լ��ݲ���mp3,mp4�����. (��Ϊ��Щ�豸�п����ڹ���
	 * ��ʮ���dp��������
	 */
	if (p_hal->config->detect_type == UMONITOR_DEVICE_ONLY) {
		ret = USB_ID_STATE_DEVICE;
	} else if (p_hal->config->detect_type == UMONITOR_HOST_ONLY) {
		ret = USB_ID_STATE_HOST;
	} else {
		ret = p_hal->get_idpin_state(p_hal);
	}
  MONITOR_PRINTK("idpin is %d\n", ret);
  

	if (ret != USB_ID_STATE_INVALID) {
		if (ret == USB_ID_STATE_HOST) {
host_detect:		  
		  MONITOR_PRINTK("host detecting!!!!\n");
			if ((pStatus->message_status & (0x1 << MONITOR_B_IN)) != 0) {
				//MONITOR_PRINTK("\n%s--%d, SYS_MSG_USB_B_OUT\n", __FUNCTION__, __LINE__);
				printk(KERN_DEBUG "\n%s--%d, SYS_MSG_USB_B_OUT\n", __FUNCTION__, __LINE__);
				pStatus->core_ops->putt_msg(MON_MSG_USB_B_OUT);
				pStatus->message_status =pStatus->message_status & (~(0x1 << MONITOR_B_IN));
			}
			if ((pStatus->message_status & (0x1 << MONITOR_CHARGER_IN)) != 0) {
				MONITOR_PRINTK("\n%s--%d, SYS_MSG_USB_CHARGER_OUT\n", __FUNCTION__, __LINE__);
				pStatus->core_ops->putt_msg(MON_MSG_USB_CHARGER_OUT);
				pStatus->message_status =pStatus->message_status & (~(0x1 << MONITOR_CHARGER_IN));
			}
      
			p_hal->set_dp_500k_15k(p_hal, 0, 1);	/* disable 500k, enable 15k. */

			if (pStatus->vbus_enable_power == 0) {
				p_hal->vbus_power_onoff(p_hal, 1);
				pStatus->vbus_enable_power = 1;
				p_hal->set_soft_id(p_hal, 1, 0);
			}
			pStatus->det_phase = 1;
		} else {
		  MONITOR_PRINTK("device detect prepare!!!!\n");
			if ((pStatus->message_status & (0x1 << MONITOR_A_IN)) != 0) {
				printk(KERN_DEBUG "\n%s--%d, SYS_MSG_USB_A_OUT\n", __FUNCTION__, __LINE__);
				pStatus->core_ops->putt_msg(MON_MSG_USB_A_OUT);
				pStatus->message_status = pStatus->message_status & (~(0x1 << MONITOR_A_IN));
			}			
			if (pStatus->vbus_enable_power) {
			    p_hal->vbus_power_onoff(p_hal, 0);
			    pStatus->vbus_enable_power = 0;
			}
			p_hal->set_dp_500k_15k(p_hal, 0, 0);	/* disable 500k, disable 15k. */
			p_hal->set_soft_id(p_hal, 1, 1);

			pStatus->det_phase = 0;
		}
		pStatus->device_confirm = 0;
		pStatus->host_confirm = 0;
		pStatus->timer_steps = 1;
		goto out;
	}

	/* the last time check host state before change to device detect phase. */
	if ((pStatus->vbus_enable_power != 0) && (pStatus->det_phase != 0)) {
		pStatus->dp_dm_status = p_hal->get_linestates(p_hal);	// get dp dm status.
		if ((pStatus->dp_dm_status == 0x1) || (pStatus->dp_dm_status == 0x2)) {
			pStatus->timer_steps = USB_HOST_DETECT_STEPS;
			pStatus->host_confirm = 0;
			goto out;
		}
	}

	p_hal->vbus_power_onoff(p_hal, 0);
	pStatus->vbus_enable_power = 0;
	p_hal->set_dp_500k_15k(p_hal, 0, 0);	/* disable 500k, disable 15k. */
	p_hal->set_soft_id(p_hal, 1, 1);
	
	pStatus->check_cnt++;

	/* if it's the first time to check, must in checking device phase. */
	if ((pStatus->check_cnt == 1) ||
	    (pStatus->port_config->detect_type == UMONITOR_DEVICE_ONLY)) {
		pStatus->det_phase = 0;
	} else {
		/* reverse detect phase. */
		pStatus->det_phase = !pStatus->det_phase;

		/* if it's B_IN status, it needn't to check host in, because there is just one usb port. 
		   ͬʱ�����ֻ����usb���������ʱ��ʹ��GPIO���⹩�������host�Ƿ���룬��ᵼ�»������硣
		   һ��Ҳ����Ҫ��ʱ��ֹ���host */
		status = pStatus->message_status & ((0x1 << MONITOR_B_IN) | (0x1 << MONITOR_CHARGER_IN));
		if ((pStatus->det_phase == 1) && (status != 0)) {
			pStatus->det_phase = 0;
			goto out1;
		}
		pStatus->check_cnt = 0;
		goto host_detect;
		
	}
out1:
	pStatus->device_confirm = 0;
	pStatus->host_confirm = 0;
	pStatus->timer_steps = 1;

out:
	return 0;
}

/******************************************************************************/
/*!
* \brief  check whether usb plug in/out
*
* \par    Description
*         this function is a timer func, interval is 500ms.
*
* \param[in]  null
* \return     null
* \ingroup   usbmonitor
*
* \par
******************************************************************************/
void umonitor_timer_func(void)
{
	int ret = 0;
	unsigned int status = 0;
	umonitor_dev_status_t *pStatus;
	usb_hal_monitor_t * p_hal;
	u32 reg;
    
	pStatus = umonitor_status;
	p_hal = &pStatus->umonitor_hal;
	
	MONITOR_PRINTK("entring umonitor_timer_func\n");

	if ((pStatus->port_config->detect_type == UMONITOR_DISABLE)
		|| (pStatus->detect_valid == 0)) {
		goto out;
	}
	pStatus->detect_running = 1;

	/* err check! */
	if ((pStatus->timer_steps > USB_DEVICE_DETECT_STEPS)
	    && (pStatus->timer_steps > USB_HOST_DETECT_STEPS)) {
		MONITOR_ERR("timer_steps err:%d \n", pStatus->timer_steps);
		pStatus->timer_steps = 0;
		goto out;
	}
	//usb_monitor_debug_status_inf(usb_ctrl_no);

	if (pStatus->timer_steps == 0) {	/* power on/off phase. */
		usb_timer_process_step0(pStatus);
		goto out;
	}

	if (pStatus->det_phase == 0) {	/* power off, device detect phase. */
		ret = usb_timer_det_pc_charger(pStatus);
		switch (ret) {
		case USB_DET_NONE:
			if ((pStatus->message_status & (0x1 << MONITOR_B_IN)) != 0) {
				printk(KERN_DEBUG "\n%s--%d, SYS_MSG_USB_B_OUT\n", __FUNCTION__, __LINE__);
				pStatus->core_ops->putt_msg(MON_MSG_USB_B_OUT);
				pStatus->message_status =pStatus->message_status & (~(0x1 << MONITOR_B_IN));
			}
			if ((pStatus->message_status & (0x1 << MONITOR_CHARGER_IN)) != 0) {
				printk(KERN_DEBUG "\n%s--%d, SYS_MSG_USB_CHARGER_OUT\n", __FUNCTION__, __LINE__);
				pStatus->core_ops->putt_msg(MON_MSG_USB_CHARGER_OUT);
				pStatus->message_status = pStatus->message_status & (~(0x1 << MONITOR_CHARGER_IN));
			}
			break;

		case USB_DET_DEVICE_DEBUOUNCING:	/* debounce. */
			break;

		case USB_DET_DEVICE_PC:
			if(p_hal->get_idpin_state(p_hal) != USB_ID_STATE_DEVICE){
				pStatus->device_confirm = 0;
				pStatus->timer_steps =0;
                		goto out;
			}
			status = pStatus->message_status & (0x1 << MONITOR_B_IN);
			if (status != 0) {
				goto out;
			}
			p_hal->set_mode(p_hal, USB_IN_DEVICE_MOD);
			//need to reset dp/dm before dwc3 loading
			reg = readl(p_hal->usbecs);
			reg &=  ~((0x1 << USB3_P0_CTL_DPPUEN_P0)|(0x1 << USB3_P0_CTL_DMPUEN_P0)); 
			writel(reg, p_hal->usbecs );
			printk(KERN_DEBUG "\n%s--%d, SYS_MSG_USB_B_IN\n", __FUNCTION__, __LINE__);
			pStatus->core_ops->putt_msg(MON_MSG_USB_B_IN);
			pStatus->message_status |= 0x1 << MONITOR_B_IN;
			pStatus->detect_valid = 0;	//disable detection
			goto out;	/* todo stop timer. */

		case USB_DET_DEVICE_CHARGER:
			/* if B_IN message not clear, clear it. B_OUT when adaptor is in. */
			status = pStatus->message_status & (0x1 << MONITOR_B_IN);
			if (status != 0) {
			  printk(KERN_DEBUG "\n%s--%d, SYS_MSG_USB_B_OUT\n", __FUNCTION__, __LINE__);
				pStatus->core_ops->putt_msg(MON_MSG_USB_B_OUT);
				pStatus->message_status =pStatus->message_status & (~(0x1 << MONITOR_B_IN));
			}
			/* if adaptor in is send, it needn't sent again. */
			status = pStatus->message_status & (0x1 << MONITOR_CHARGER_IN);
			if (status != 0) {
				goto out;
			}
			p_hal->set_mode(p_hal, USB_IN_DEVICE_MOD);
			MONITOR_PRINTK("\n%s--%d, SYS_MSG_USB_CHARGER_IN\n", __FUNCTION__, __LINE__);
			pStatus->core_ops->putt_msg(MON_MSG_USB_CHARGER_IN);
			pStatus->message_status |= 0x1 << MONITOR_CHARGER_IN;
			pStatus->detect_valid = 0;	//disable detection
			goto out;	/* todo stop timer. */

		default:
			USB_ERR_PLACE;
			break;
		}
		goto out;
	} else {		/* power on, host detect phase. */

		ret = usb_timer_det_udisk(pStatus);
		status = pStatus->message_status & (0x1 << MONITOR_A_IN);
		if ((status != 0) && (ret == USB_DET_HOST_NONE)) {
			MONITOR_PRINTK("\n%s--%d, SYS_MSG_USB_A_OUT\n", __FUNCTION__, __LINE__);
			pStatus->core_ops->putt_msg(MON_MSG_USB_A_OUT);
			pStatus->message_status = pStatus->message_status & (~(0x1 << MONITOR_A_IN));
			goto out;
		}
		if (ret == USB_DET_HOST_UDISK) {
			p_hal->set_mode(p_hal, USB_IN_HOST_MOD);
			MONITOR_PRINTK("\n%s--%d, SYS_MSG_USB_A_IN\n", __FUNCTION__, __LINE__);
			pStatus->core_ops->putt_msg(MON_MSG_USB_A_IN);
			pStatus->message_status |= 0x1 << MONITOR_A_IN;

			/*�����A�߲��룬��رն�ʱ����B�߲��룬��ʱ�����ùر� */
			pStatus->detect_valid = 0;	//disable detection
			goto out;	/* todo stop timer. */
		}
		goto out;
	}
	
out:
	pStatus->detect_running = 0;
	return;
}

/******************************************************************************/
/*!
* \brief  set monitor detect flag
*
* \par    Description
*         set monitor detect flag
*
* \param[in]  status
*             1---   set detection flag to detect
*             0---   reverse
* \return     0------���óɹ�
* \ingroup   usbmonitor
*
* \par
******************************************************************************/
static int set_monitor_detect_flag(umonitor_dev_status_t *pStatus, unsigned int status)
{
	int i;
	unsigned int ms_status = 0;	/* record is a in ? */
	usb_hal_monitor_t *p_hal = &pStatus->umonitor_hal;

	pStatus->check_cnt = 0;
	pStatus->det_phase = 0;
	pStatus->timer_steps = 0;

	if (status != 0) {	/*enable detect flag */
		p_hal->vbus_power_onoff(p_hal, 0);
		pStatus->vbus_enable_power = 0;

		if (pStatus->detect_valid == 0) {
			MONITOR_PRINTK("%s,%d\n", __FUNCTION__, __LINE__);
			pStatus->detect_valid = 1;
			goto out;
		} else {
			MONITOR_PRINTK("usb detection flag is already setted, %s,%d\n", __FUNCTION__, __LINE__);
		}
	} 
	else {		/*disable detection flag */
		i = 0;
		do {
			if (pStatus->detect_running == 0) {
				pStatus->detect_valid = 0;
				break;
			}
			msleep(1);
			++i;
		} while (i < 1000);
		MONITOR_PRINTK("enable detection flag\n");
		
		if (ms_status == 0) {
			/* make sure power is off. */
			p_hal->vbus_power_onoff(p_hal, 0);
			pStatus->vbus_enable_power = 0;
			p_hal->set_soft_id(p_hal, 1, 1);
		}
	}

out:
	if (pStatus->core_ops->wakeup_func != NULL) {
		pStatus->core_ops->wakeup_func();
	}
	return 0;
}

/*! \cond USBMONITOR_INTERNAL_API*/
/******************************************************************************/
/*!
* \brief  enable or disable usb plug_in/out check
*
* \par    Description
*         enable or disable the func of checking usb plug_in/out
*
*
* \param[in]  status
*             1---   enable check func;
*             0---   disable check func;
* \return     0------ʹ��/��ֹ�ɹ�
                ��ֵ---������ǰæ�����Ժ����½��д˲���
* \ingroup   usbmonitor
*
* \par
******************************************************************************/
int umonitor_detection(unsigned int status)
{
	umonitor_dev_status_t *pStatus;
	usb_hal_monitor_t * p_hal;


	pStatus = umonitor_status;
	p_hal = &pStatus->umonitor_hal;
	MONITOR_PRINTK("umonitor_detection:%d\n", status);

	if (status != 0) {
		p_hal->dwc3_otg_mode_cfg(p_hal);
		p_hal->aotg_enable(p_hal, 1);
		p_hal->set_mode(p_hal, USB_IN_DEVICE_MOD);
		set_monitor_detect_flag(pStatus, 1);
	} else {
		//�ⲿ����������Ч,�����Ѿ���⵽B����A����ʱ,��������Ϣ��,����ʱ��port_timerֹͣ;
		//checktimer�Ծ����м��A(id�Ƿ�仯)����B(vbus�Ƿ�ı�)�����״̬�Ƿ����ı�.
		//�˴�Ϊ����ԭʼ����,/*disable detection,����UDC����ʱ���ȹرն�ʱ����� */
		p_hal->aotg_enable(p_hal, 0);
		set_monitor_detect_flag(pStatus, 0);
	}
	return 0;
}

/*! \cond NOT_INCLUDE*/
/******************************************************************************/
/*!
* \brief  parse the runtime args of monitor driver.
* \par    Description
*         ��ʼ������ʼ׼�����м�⡣
*
* \retval      0---args parse successed
* \ingroup     UsbMonitor
******************************************************************************/
int umonitor_core_init(umonitor_api_ops_t * core_ops,
		   umon_port_config_t * port_config , unsigned int base)
{
	umonitor_dev_status_t *pStatus;

	pStatus = kmalloc(sizeof (umonitor_dev_status_t), GFP_KERNEL);
	if (pStatus == NULL) {
		return -1;
	}
	umonitor_status = pStatus;

	usb_hal_init_monitor_hw_ops(&pStatus->umonitor_hal, port_config, base);
	usb_init_monitor_status(pStatus);
	pStatus->core_ops = core_ops;
	pStatus->port_config = port_config;

	return 0;
}

int umonitor_core_exit(void)
{
	umonitor_dev_status_t *pStatus;
	usb_hal_monitor_t *p_hal;

	pStatus = umonitor_status;
	p_hal = &pStatus->umonitor_hal;

	p_hal->enable_irq(p_hal, 0);
	if (pStatus != NULL)
		kfree(pStatus);
		
	umonitor_status = NULL;
	return 0;
}

unsigned int umonitor_get_run_status(void)
{
	umonitor_dev_status_t *pStatus;

	pStatus = umonitor_status;
	
	return (unsigned int)pStatus->detect_valid;
}

unsigned int umonitor_get_message_status(void)
{
	umonitor_dev_status_t *pStatus;

	pStatus = umonitor_status;
	
	return (unsigned int)pStatus->message_status;
}

void umonitor_printf_debuginfo(void)
{
	umonitor_dev_status_t *pStatus;
	usb_hal_monitor_t *p_hal;

	pStatus = umonitor_status;
	p_hal = &pStatus->umonitor_hal;

	usb_monitor_debug_status_inf();
	printk(KERN_DEBUG "in printf_debuginfo\n");
	p_hal->debug(p_hal);

	return;
}

int umonitor_vbus_power_onoff(int value)
{
	umonitor_dev_status_t *pStatus;
	usb_hal_monitor_t *p_hal;

	pStatus = umonitor_status;
	p_hal = &pStatus->umonitor_hal;
	
	return p_hal->vbus_power_onoff(p_hal, value);
}

int umonitor_core_suspend(void)
{
	umonitor_dev_status_t *pStatus;
	usb_hal_monitor_t *p_hal;

	pStatus = umonitor_status;
	p_hal = &pStatus->umonitor_hal;

  pStatus->detect_valid = 0;
  
  printk(KERN_DEBUG "SUSPEND pStatus->message_status is %d!!!!!!!!!!!!!!\n", pStatus->message_status);
  
	if(pStatus->vbus_enable_power && p_hal->vbus_power_onoff)
		p_hal->vbus_power_onoff(p_hal,  0);
	
  p_hal->suspend_or_resume(p_hal, 1);
	
	return 0;
}

int umonitor_core_resume(void)
{
	umonitor_dev_status_t *pStatus;
	usb_hal_monitor_t *p_hal;
	pStatus = umonitor_status;
	p_hal = &pStatus->umonitor_hal;	
	
	printk(KERN_DEBUG"RESUME pStatus->message_status is %d!!!!!!!!!!!!!!\n", pStatus->message_status);

	if((pStatus->message_status &(0x1 << MONITOR_B_IN)) != 0){
		printk(KERN_DEBUG"RESUME SNED B_OUT\n");
		pStatus->core_ops->putt_msg(MON_MSG_USB_B_OUT);
			pStatus->message_status &= ~(0x1 << MONITOR_B_IN);
	}
	if((pStatus->message_status &(0x1 << MONITOR_A_IN)) != 0){
		printk(KERN_DEBUG"RESUME SNED A_OUT\n");
		//p_hal->vbus_power_onoff(p_hal,  1);
		//pStatus->vbus_enable_power = 1;
		pStatus->core_ops->putt_msg(MON_MSG_USB_A_OUT);
		pStatus->message_status &= ~(0x1 << MONITOR_A_IN);
	}
	p_hal->suspend_or_resume(p_hal, 0);
	umonitor_detection(1);
	return 0;
}

/*��֤�ػ������вŻ����,�����ط��������*/
int umonitor_dwc_otg_init(void)
{
	umonitor_dev_status_t *pStatus;
	usb_hal_monitor_t *p_hal;

	pStatus = umonitor_status;
	p_hal = &pStatus->umonitor_hal;

  p_hal->dwc3_otg_init(p_hal);
	
	return 0;
}
