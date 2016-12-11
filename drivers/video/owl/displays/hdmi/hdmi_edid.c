/*
 * hdmi_edid.c
 *
 * HDMI OWL IP driver Library
 *
 * Copyright (C) 2014 Actions Corporation
 * Author: Guo Long  <guolong@actions-semi.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/poll.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/cdev.h>

#include "hdmi_ip.h"
#include "hdmi.h"


#define VID1920x1080P_24_16VS9_3D_FP  (VID1920x1080P_24_16VS9 +0x80)
#define VID1280x720P_50_16VS9_3D_FP   (VID1280x720P_50_16VS9  +0x80)
#define VID1280x720P_60_16VS9_3D_FP   (VID1280x720P_60_16VS9  +0x80)

#define HDMI_EDID_ADDR		(0x60 >> 1)
#define HDMI_EDID_DDC_ADDR	(0xa0 >> 1)

#define IIC_FROM_DTS

extern void set_hdmi_i2c_flag(int flag);

struct edid_dev {
	struct i2c_client *client;
	
};

#ifndef IIC_FROM_DTS
static struct i2c_board_info i2c_hdmi_devices ={	
	I2C_BOARD_INFO("hdmi_read_edid", 0x60),	
};
#endif

static const struct i2c_device_id hdmi_edid_id[] = {
	{ "hdmi_read_edid", 0 },
	{ }
};

static const struct of_device_id hdmi_edid_of_match[] = {
	{ "actions,hdmi_read_edid" },
	{ }
};

MODULE_DEVICE_TABLE(i2c,hdmi_edid_id);
MODULE_DEVICE_TABLE(of, hdmi_edid_of_match);

struct edid_dev *edid_devp;

static int hdmi_iic_probe(struct i2c_client *client,
        const struct i2c_device_id *id)
{
    int err = 0;
	
	EDID_DEBUG("ok iic~~~~~~~\n");
	edid_devp->client = client;
	return err;
}

static int hdmi_iic_remove(struct i2c_client *i2c)
{
	return 0;
}

static struct i2c_driver hdmi_iic_driver = {
    .driver = {
        .owner    = THIS_MODULE,
        .name    = "hdmi_iic",
		.of_match_table = of_match_ptr(hdmi_edid_of_match),
    },
	.id_table	  = hdmi_edid_id,
    .probe        = hdmi_iic_probe,
	.remove		  = hdmi_iic_remove,
};

static int i2c_check_adapter(void)
{
	EDID_DEBUG("i2c_check_adapter iic~~~~~~~\n");
	if((edid_devp)&&(edid_devp->client)){
		EDID_DEBUG("i2c_check_adapter OK!\n");
		return 0;	
	}else{
		DEBUG_ERR("i2c_check_adapter edid_devp->client = NULL!\n");
		return -EFAULT;
	}
}

int ddc_init(void)
{	
	EDID_DEBUG("[%s start]  \n", __func__);
	EDID_DEBUG("gll i2c_add_driver~~~\n");
#ifdef IIC_FROM_DTS
	edid_devp = kzalloc(sizeof(struct edid_dev),GFP_KERNEL);  
	if(i2c_add_driver(&hdmi_iic_driver))
	{
		DEBUG_ERR("i2c_add_driver hdmi_iic_driver error!!!\n");
		goto err;
	}
#else	
		struct i2c_adapter *i2c_adap;  
		edid_devp = kzalloc(sizeof(struct edid_dev),GFP_KERNEL);         	        
		i2c_adap = i2c_get_adapter(3);  
		if (!i2c_adap) {
			DEBUG_ERR("hdmi  adapter error!\n");
			goto err;
		}
	 
		edid_devp->client = i2c_new_device(i2c_adap, &i2c_hdmi_devices);  
		i2c_put_adapter(i2c_adap); 
#endif 
	return 0;
err:
	kfree(edid_devp);
	return -EFAULT;

}

static int ddc_read(char segment_index, char segment_offset, char * pbuf)
{
	int ret;
	int retry_num = 0;
	char segment_pointer;
	struct i2c_msg msg[3];
	struct i2c_adapter *adap;
	struct i2c_client *client;
	
	EDID_DEBUG("[%s start]\n",__func__);
	
	set_hdmi_i2c_flag(1);

RETRY:
	retry_num++;

	/*add i2c driver*/
	adap = edid_devp->client->adapter;
	client = edid_devp->client;
	segment_pointer = (char)segment_index;
	
	/* set segment pointer */
	msg[0].addr = HDMI_EDID_ADDR;
	msg[0].flags = client->flags | I2C_M_IGNORE_NAK;
	msg[0].buf = &segment_pointer;
	msg[0].len = 1;
	msg[1].addr = HDMI_EDID_DDC_ADDR;
	msg[1].flags = client->flags;
	msg[1].buf = &segment_offset;
	msg[1].len = 1;
	msg[2].addr = HDMI_EDID_DDC_ADDR;
	msg[2].flags = client->flags  | I2C_M_RD;
	msg[2].buf = pbuf;
	msg[2].len = 128;

	ret = i2c_transfer(adap, msg, 3);

	if (ret != 3) {
		
		DEBUG_ERR("[in %s]fail to read EDID ret %d \n",__func__,ret);
		ret = -1;
		goto RETURN1;
		
	} 
	EDID_DEBUG("[%s finished]\n",__func__);

RETURN1:
	if ((ret < 0) && (retry_num < 3)) {
		
		EDID_DEBUG("ret_val1 is %d,retry_num is %d\n",ret,retry_num);
		EDID_DEBUG("[in %s]the %dth read EDID error,try again\n", __func__,retry_num);

		goto RETRY;
		
	} else {
	
		set_hdmi_i2c_flag(0);
	
		return ret;
	}    	
}

static int get_edid_data(u8 block,u8 *buf)
{
	u8 i;
    u8 * pbuf = buf + 128*block;
    u8 offset = (block&0x01)? 128:0;
  
	if(ddc_read(block>>1,offset,pbuf)<0)
	{
		DEBUG_ERR("read edid error!!!\n");
		return -1;
	}
//	edid_test(offset, pbuf);
	////////////////////////////////////////////////////////////////////////////
    EDID_DEBUG("Sink : EDID bank %d:\n",block);

	EDID_DEBUG(" 0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F\n");
	EDID_DEBUG(" ===============================================================================================\n");

	for (i = 0; i < 8; i++) 
	{
		EDID_DEBUG(" %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x\n",
				pbuf[i*16 + 0 ],pbuf[i*16 + 1 ],pbuf[i*16 + 2 ],pbuf[i*16 + 3 ],
				pbuf[i*16 + 4 ],pbuf[i*16 + 5 ],pbuf[i*16 + 6 ],pbuf[i*16 + 7 ],
				pbuf[i*16 + 8 ],pbuf[i*16 + 9 ],pbuf[i*16 + 10],pbuf[i*16 + 11],
				pbuf[i*16 + 12],pbuf[i*16 + 13],pbuf[i*16 + 14],pbuf[i*16 + 15]
				);
	}
    EDID_DEBUG(" ===============================================================================================\n");

    return 0;
	
}

/////////////////////////////////////////////////////////////////////
// parse_edid()
// Check EDID check sum and EDID 1.3 extended segment.
/////////////////////////////////////////////////////////////////////
int edid_checksum(u8 block,u8 *buf)
{
    int i = 0, CheckSum = 0;
	u8 *pbuf = buf + 128*block;
	
    for( i = 0, CheckSum = 0 ; i < 128 ; i++ )
	{
        CheckSum += pbuf[i] ; 
        CheckSum &= 0xFF ;
    }

	if( CheckSum != 0 )
	{
		DEBUG_ERR("EDID block %d checksum error\n",block);
		return -1 ;
	}
	return 0;
}

int edid_header_check(u8 *pbuf)
{
	if( pbuf[0] != 0x00 ||
	    pbuf[1] != 0xFF ||
	    pbuf[2] != 0xFF ||
	    pbuf[3] != 0xFF ||
	    pbuf[4] != 0xFF ||
	    pbuf[5] != 0xFF ||
	    pbuf[6] != 0xFF ||
	    pbuf[7] != 0x00)
	{
    	DEBUG_ERR("EDID block0 header error\n");
        return -1 ;
    }
	return 0;
}

int edid_version_check(u8 *pbuf)
{
    EDID_DEBUG("EDID version: %d.%d ",pbuf[0x12],pbuf[0x13]) ;
    if( (pbuf[0x12]!= 0x01) || (pbuf[0x13]!=0x03))
	{
		DEBUG_ERR("Unsupport EDID format,EDID parsing exit\n");
		return -1;
    }
	return 0;
}

int parse_dtd_block(struct hdmi_edid *edid, u8 *pbuf)
{
	u32 	pclk,sizex,Hblanking,sizey,Vblanking,Hsync_offset,Hsync_plus,
			Vsync_offset,Vsync_plus,H_image_size,V_image_size,H_Border,
			V_Border,pixels_total,frame_rate;
    pclk 		= ( (u32)pbuf[1]	<< 8) + pbuf[0];
    sizex 		= (((u32)pbuf[4] 	<< 4) & 0x0f00) + pbuf[2];
    Hblanking 	= (((u32)pbuf[4] 	<< 8) & 0x0f00) + pbuf[3];
    sizey 		= (((u32)pbuf[7] 	<< 4) & 0x0f00) + pbuf[5];
    Vblanking 	= (((u32)pbuf[7] 	<< 8) & 0x0f00) + pbuf[6];
    Hsync_offset= (((u32)pbuf[11] << 2) & 0x0300) + pbuf[8];
    Hsync_plus 	= (((u32)pbuf[11] << 4) & 0x0300) + pbuf[9];
    Vsync_offset= (((u32)pbuf[11] << 2) & 0x0030) + (pbuf[10] >> 4);
    Vsync_plus 	= (((u32)pbuf[11] << 4) & 0x0030) + (pbuf[8] & 0x0f);
    H_image_size= (((u32)pbuf[14] << 4) & 0x0f00) + pbuf[12];
    V_image_size= (((u32)pbuf[14] << 8) & 0x0f00) + pbuf[13];
    H_Border 	=  pbuf[15];
	V_Border 	=  pbuf[16];

	pixels_total = (sizex + Hblanking) * (sizey + Vblanking);

	if( (pbuf[0] == 0) && (pbuf[1] == 0) && (pbuf[2] == 0))
	{
		return 0;
	}
	
	if(pixels_total == 0){
		return 0;
	}
	else
	{
		frame_rate = (pclk * 10000) /pixels_total;
	}

    if ((frame_rate == 59) || (frame_rate == 60))
	{
        if ((sizex== 720) && (sizey == 240))
        {
        	edid->Device_Support_VIC[VID720x480I_60_4VS3] = 1;
        }
        if ((sizex== 720) && (sizey == 480))
        {
        	edid->Device_Support_VIC[VID720x480P_60_4VS3] = 1;
        }
        if ((sizex== 1280) && (sizey == 720))
        {
            edid->Device_Support_VIC[VID1280x720P_60_16VS9] = 1;
        }
        if ((sizex== 1920) && (sizey == 540))
        {
            edid->Device_Support_VIC[VID1920x1080I_60_16VS9] = 1;
        }
        if ((sizex== 1920) && (sizey == 1080))
        {
            edid->Device_Support_VIC[VID1920x1080P_60_16VS9] = 1;
        }
    }
	else if ((frame_rate == 49) || (frame_rate == 50))
	{
        if ((sizex== 720) && (sizey == 288))
        {
        	edid->Device_Support_VIC[VID720x576I_50_4VS3] = 1;
        }
        if ((sizex== 720) && (sizey == 576))
        {
        	edid->Device_Support_VIC[VID720x576P_50_4VS3] = 1;
        }
        if ((sizex== 1280) && (sizey == 720))
        {
            edid->Device_Support_VIC[VID1280x720P_50_16VS9] = 1;
        }          
        if ((sizex== 1920) && (sizey == 540))
        {
            edid->Device_Support_VIC[VID1920x1080I_50_16VS9] = 1;
        }
        if ((sizex== 1920) && (sizey == 1080))
        {
            edid->Device_Support_VIC[VID1920x1080P_50_16VS9] = 1;
        }
    }
	else if ((frame_rate == 23) || (frame_rate == 24))
	{
        if ((sizex== 1920) && (sizey == 1080))
        {
            edid->Device_Support_VIC[VID1920x1080P_24_16VS9] = 1;
        }
    }
	EDID_DEBUG("PCLK=%d\tXsize=%d\tYsize=%d\tFrame_rate=%d\n",
		  pclk*10000,sizex,sizey,frame_rate);
		  
    return 0;
}

int parse_videodata_block(struct hdmi_edid *edid, u8 *pbuf,u8 size)
{
	int i=0;
	while(i<size)
	{
		edid->Device_Support_VIC[pbuf[i] &0x7f] = 1;
		if(pbuf[i] &0x80)
		{
		   EDID_DEBUG("parse_videodata_block: VIC %d(native) support\n", pbuf[i]&0x7f);
		}
		else
		{
		   EDID_DEBUG("parse_videodata_block: VIC %d support\n", pbuf[i]);
		}
		i++;
	}
	
	////////////////////////////////////////////////////////////////////////////
    EDID_DEBUG("parse_videodata_block : Device_Support_VIC :\n");

	EDID_DEBUG(" 0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F\n");
	EDID_DEBUG(" ===============================================================================================\n");

	for (i = 0; i < 8; i++) 
	{
		EDID_DEBUG(" %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x  %2.2x\n",
				edid->Device_Support_VIC[i*16 + 0 ],edid->Device_Support_VIC[i*16 + 1 ],edid->Device_Support_VIC[i*16 + 2 ],edid->Device_Support_VIC[i*16 + 3 ],
				edid->Device_Support_VIC[i*16 + 4 ],edid->Device_Support_VIC[i*16 + 5 ],edid->Device_Support_VIC[i*16 + 6 ],pbuf[i*16 + 7 ],
				edid->Device_Support_VIC[i*16 + 8 ],edid->Device_Support_VIC[i*16 + 9 ],edid->Device_Support_VIC[i*16 + 10],pbuf[i*16 + 11],
				edid->Device_Support_VIC[i*16 + 12],edid->Device_Support_VIC[i*16 + 13],edid->Device_Support_VIC[i*16 + 14],pbuf[i*16 + 15]
				);
	}
    EDID_DEBUG(" ===============================================================================================\n");
   
	return 0;
}

int parse_audiodata_block(u8 *pbuf,u8 size)
{
	u8 sum = 0;
	
	while(sum < size)
	{
    	if( (pbuf[sum]&0xf8) == 0x08)
    	{
			EDID_DEBUG("parse_audiodata_block: max channel=%d\n",(pbuf[sum]&0x7)+1);
			EDID_DEBUG("parse_audiodata_block: SampleRate code=%x\n",pbuf[sum+1]);
			EDID_DEBUG("parse_audiodata_block: WordLen code=%x\n",pbuf[sum+2]);
    	}
    	sum += 3;
	}
	return 0;
}

int parse_hdmi_vsdb(struct hdmi_edid *edid, u8 * pbuf,u8 size)
{
	u8 index = 8;

	if( (pbuf[0] ==0x03) &&	(pbuf[1] ==0x0c) &&	(pbuf[2] ==0x00) )	//check if it's HDMI VSDB
	{
		edid->isHDMI = HDMI_HDMI;
		EDID_DEBUG("Find HDMI Vendor Specific DataBlock\n");
	}
	else
	{
		edid->isHDMI = HDMI_DVI;
		return 0;
	}
	
	if(size <=8)
		return 0;

	if((pbuf[7]&0x20) == 0 )
		return 0;
	if((pbuf[7]&0x40) == 1 )
		index = index +2;
	if((pbuf[7]&0x80) == 1 )
		index = index +2;

	if(pbuf[index]&0x80)		//mandatary format support
	{
		edid->Device_Support_VIC[VID1920x1080P_24_16VS9_3D_FP] = 1;
		edid->Device_Support_VIC[VID1280x720P_50_16VS9_3D_FP] = 1;
		edid->Device_Support_VIC[VID1280x720P_60_16VS9_3D_FP] = 1;
		EDID_DEBUG("3D_present\n");
	}
	else
	{
		return 0;
	}
	
	if( ((pbuf[index]&0x60) ==1) || ((pbuf[index]&0x60) ==2) )
	{
		EDID_DEBUG("3D_multi_present\n");
	}
	
	index += (pbuf[index+1]&0xe0) + 2;
	if(index > (size+1) )
	   	return 0;
	   	
	EDID_DEBUG("3D_multi_present byte(%2.2x,%2.2x)\n",pbuf[index],pbuf[index+1]);

	return 0;
}

int read_edid(u8 * edid , int len)
{
	int r, l;

	if (len < 128)
		return -EINVAL;
		
	if(i2c_check_adapter())
	{
		DEBUG_ERR("iic adapter error!!!\n");
		return -1;		
	}
	
	if(ddc_read(0,0,edid)<0)
	{
		DEBUG_ERR("read edid error!!!\n");
		return -1;
	}
	
	l = 128;

	if (len >= 128 * 2 && edid[0x7e] > 0) {
		r = ddc_read(1,0x80,edid + 0x80);
		if (r<0)
			{
				printk("read ddc_read is error r=%d\n");
				return r;
			}

		l = 256;
	}
		
	return l;
	
}
int parse_edid(struct hdmi_edid *edid)
{
    //collect the EDID ucdata of segment 0
    u8 BlockCount ;
    u32 i,offset ;

    EDID_DEBUG("parse_edid\n");

    memset(edid->Device_Support_VIC,0,sizeof(edid->Device_Support_VIC));
    memset(edid->EDID_Buf,0,sizeof(edid->EDID_Buf));
	memset(edid->video_formats,0,sizeof(edid->video_formats));
	
    edid->isHDMI = HDMI_HDMI;
    edid->YCbCr444_Support = 0;
	edid->read_ok = 0;

	if(i2c_check_adapter())
	{
		DEBUG_ERR("iic adapter error!!!\n");
		goto err0;		
	}
	
    if( get_edid_data(0, edid->EDID_Buf) != 0)
	{
		DEBUG_ERR("get_edid_data error!!!\n");
		goto err0;
	}

	if( edid_checksum(0, edid->EDID_Buf) != 0)
	{
		DEBUG_ERR("edid_checksum error!!!\n");
		goto err0;
	}

	if( edid_header_check(edid->EDID_Buf)!= 0)
	{
		DEBUG_ERR("edid_header_check error!!!\n");
		goto err0;
	}

	if( edid_version_check(edid->EDID_Buf)!= 0)
	{
		DEBUG_ERR("edid_version_check error!!!\n");
		goto err0;
	}
	
	parse_dtd_block(edid, edid->EDID_Buf + 0x36);	

	parse_dtd_block(edid, edid->EDID_Buf + 0x48);

    BlockCount = edid->EDID_Buf[0x7E];

    if( BlockCount > 0 )
    {
	    if ( BlockCount > 4 )
	    {
	        BlockCount = 4 ;
	    }
	    for( i = 1 ; i <= BlockCount ; i++ )
	    {
	        get_edid_data(i, edid->EDID_Buf) ;  
	        if( edid_checksum(i, edid->EDID_Buf)!= 0)
	        {
	        	return 0;
	        }

			if((edid->EDID_Buf[0x80*i+0]==2)/*&&(edid->EDID_Buf[0x80*i+1]==1)*/)
			{
				//add by matthew 20120809 to add rgb/yuv detect
				if( (edid->EDID_Buf[0x80*i+1]>=1))
				{
						if(edid->EDID_Buf[0x80*i+3]&0x20)
						{
							edid->YCbCr444_Support = 1;
							EDID_DEBUG("device support YCbCr44 output\n");
						}
				}
				//end by matthew 20120809
				
				offset = edid->EDID_Buf[0x80*i+2];
				if(offset > 4)		//deal with reserved data block
				{
					u8 bsum = 4;
					while(bsum < offset)
					{
						u8 tag = edid->EDID_Buf[0x80*i+bsum]>>5;
						u8 len = edid->EDID_Buf[0x80*i+bsum]&0x1f;
						if( (len >0) && ((bsum + len + 1) > offset) )
						{
						    EDID_DEBUG("len or bsum size error\n");
							return 0;
						}else
						{
							if( tag == 1)		//ADB
							{
								parse_audiodata_block(edid->EDID_Buf+0x80*i+bsum+1,len);
							}
							else if( tag == 2)	//VDB
							{
								parse_videodata_block(edid, edid->EDID_Buf+0x80*i+bsum+1,len);
							}
							else if( tag == 3)	//vendor specific 
							{
								parse_hdmi_vsdb(edid, edid->EDID_Buf+0x80*i+bsum+1,len);
							}
						}

						bsum += (len +1);
					}
					
				}else
				{
					EDID_DEBUG("no data in reserved block%d\n",i);
				}
				
				if(offset >= 4)		//deal with 18-byte timing block
				{
					if(offset == 4)
					{
						edid->isHDMI = HDMI_DVI;
						EDID_DEBUG("dvi mode\n");
					}				
					while(offset < (0x80-18))
					{
						parse_dtd_block(edid, edid->EDID_Buf + 0x80*i + offset);	
						offset += 18;
					}
					EDID_DEBUG("deal with 18-byte timing block\n");

				}else
				{
					EDID_DEBUG("no datail timing in block%d\n",i);
				}
			}

	    }
    }
	
	for(i=0;i<128;i++)
	{
		if(edid->Device_Support_VIC[i]==1)
		{
			edid->video_formats[i/32] |= (1<<(i%32));
		}
	}
	edid->video_formats[0] |= 0x04;
	edid->read_ok = 1;
	EDID_DEBUG("edid->video_formats[0] = 0x%x\n", edid->video_formats[0]);
	EDID_DEBUG("edid->video_formats[1] = 0x%x\n", edid->video_formats[1]);	
	EDID_DEBUG("edid->video_formats[2] = 0x%x\n", edid->video_formats[2]);	
	EDID_DEBUG("edid->video_formats[3] = 0x%x\n", edid->video_formats[3]);	
    return 0 ;

err0:
	edid->video_formats[0] = 0x80090014;
	edid->video_formats[1] = 0;
	edid->video_formats[2] = 0;
	edid->video_formats[3] = 0;
	DEBUG_ERR("read edid err0\n");
	return -1 ;
}

#define HDCP_ADDR	(0x74 >> 1)
int i2c_hdcp_write(const char *buf, unsigned short offset, int count) 
{
    int ret;
    struct i2c_client *client = edid_devp->client;
    struct i2c_adapter *adap = client->adapter;

    struct i2c_msg msg;
	
	set_hdmi_i2c_flag(1);

    msg.addr = HDCP_ADDR;
    msg.flags = client->flags | I2C_M_IGNORE_NAK;
    msg.len = count;
    msg.buf = (char *)buf;

    ret = i2c_transfer(adap, &msg, 1);

    /*
     * If everything went ok (i.e. 1 msg transmitted), return #bytes
     * transmitted, else error code.
     */
	 
	set_hdmi_i2c_flag(0);
    return (ret == 2) ? count : ret;

}

int i2c_hdcp_read(char *buf, unsigned short offset, int count) 
{

    struct i2c_client *client = edid_devp->client;
    struct i2c_adapter *adap = client->adapter;
    struct i2c_msg msg[2];
    int ret;
    int i;
	set_hdmi_i2c_flag(1);
    msg[0].addr = HDCP_ADDR;
    msg[0].flags = client->flags | I2C_M_IGNORE_NAK;
    msg[0].buf = (unsigned char *)&offset;
    msg[0].len = 1;
    msg[1].addr = HDCP_ADDR;
    msg[1].flags = client->flags | I2C_M_RD;
    msg[1].buf = buf;
    msg[1].len = count;
    ret = i2c_transfer(adap, msg, 2);
    for (i = 0; i < count; i++)
    	HDCP_DEBUG("i2c hdcp read :buf[%d]   %d\n", i, msg[1].buf[i]);

    /*
     * If everything went ok (i.e. 1 msg received), return #bytes received,
     * else error code.
     */
	set_hdmi_i2c_flag(0);
    return (ret == 2) ? count : ret;

}


