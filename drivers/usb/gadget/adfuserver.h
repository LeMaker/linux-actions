/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2009 Actions Semi Inc.
*/
/******************************************************************************/

/******************************************************************************/
#ifndef __MBR_INFO_H__
#define __MBR_INFO_H__

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PARTITION   	12
#define HDCP_KEY_SIZE		308 	//bytes
#define SERIAL_NO_SIZE		16   	//bytes
#define PARTITION_TBL_SIZE	(MAX_PARTITION * sizeof(partition_info_t))


#define RECOVERY_ACCESS      0
#define MISC_ACCESS       1
#define ROOTFS_ACCESS       2
#define ANDROID_DATA_ACCESS 3
#define ANDROID_CACHE_ACCESS 4

#define SNAPSHOT_ACCESS		5
#define WHD_ACCESS			6

#define CONFIG_RW_ACCESS 	7


#define UDISK_ACCESS        10

typedef struct
{
    unsigned char   flash_ptn;                  //flash partition number
    unsigned char   partition_num;              //ÿ��������Ӧ�����ڵ�flash partition�ı��
    unsigned short  reserved;                   //reserved������չ�ɸ÷���������
    unsigned int    partition_cap;              //��Ӧ�����Ĵ�С
}__attribute__ ((packed)) partition_info_t;


typedef struct
{
    unsigned char   flash_ptn;                  //flash partition number
    unsigned char   partition_num;              //ÿ��������Ӧ�����ڵ�flash partition�ı��
    unsigned short  phy_info;                   //reserved������չ�ɸ÷���������
    unsigned int    partition_cap;              //��Ӧ�����Ĵ�С
}__attribute__ ((packed)) CapInfo_t;


/*
 * don't re-order
 */
typedef struct
{
    partition_info_t partition_info[MAX_PARTITION];            //������Ϣ��
    unsigned char HdcpKey[HDCP_KEY_SIZE];
    unsigned char SerialNo[SERIAL_NO_SIZE];
    unsigned char reserved[0x400 - PARTITION_TBL_SIZE - HDCP_KEY_SIZE - SERIAL_NO_SIZE];     //mbr_info_t����СΪ1k��Ϊ�Ժ���չ
}__attribute__ ((packed)) mbr_info_t;



/********************************************************************
������ʽ��ԭ���Ϸ�����˳�����У�
            flash_ptn       partition_num       partition_cap�ĵ�λ
mbrc:           0                   0               block
vmlinux         0                   1               M
rootfs          1                   0               M
configfs        1                   1               M
others          2                   0~n             M

��partition_numΪ0xff�������һ������
*********************************************************************/

#ifdef __cplusplus
}
#endif

#endif
