#ifndef _GSENSOR_DETECT_H_
#define _GSENSOR_DETECT_H_

struct gsensor_device
{
    char * name;            //0.IC����
    char * ko_name;         //1.ko����
    bool has_sa0;             //2.��sa0 pin
    unsigned char i2c_addr;    //3.i2c��ַ
    bool has_chipid;        //4.��chipid
    unsigned char chipid_reg; //5.chipid�Ĵ���
    unsigned char chipid[2];   //6.chipid 
    bool need_detect;	     //7.�Ƿ�ɨ��
};

//ÿ����һ��IC��������б������
//ע���������ic��i2c��ַ��ͬ������chipid�ķ���ǰ�档
struct gsensor_device gsensor_device_list[]=
{
    // AFA750
    {
        "afa750",                    //0.IC����
        "gsensor_afa750.ko",    //1.ko����
        true,                           //2.��sa0 pin
        0x3c,                          //3.i2c��ַ
        true,                           //4.��chipid
        0x37,                          //5.chipid�Ĵ���
        {0x3c, 0x3d},              //6.chipid
        true,                           //7.�Ƿ�ɨ��
    },
    // BMA220
    {
        "bma220",                    //0.IC����
        "gsensor_bma220.ko",    //1.ko����
        false,                           //2.��sa0 pin
        0x0a,                          //3.i2c��ַ
        true,                           //4.��chipid
        0x00,                          //5.chipid�Ĵ���
        {0xdd, 0xdd},              //6.chipid
        true,                           //7.�Ƿ�ɨ��
    },
    
    // BMA222 bma223
    {
        "bma222",                    //0.IC����
        "gsensor_bma222.ko",    //1.ko����
        false,                           //2.��sa0 pin
        0x18,                          //3.i2c��ַ
        true,                           //4.��chipid
        0x00,                          //5.chipid�Ĵ���
        {0x02, 0xf8},              //6.chipid
        true,                           //7.�Ƿ�ɨ��
    },
    
    // BMA250/BMA250E
    {
        "bma250",                    //0.IC����
        "gsensor_bma250.ko",    //1.ko����
        false,                           //2.��sa0 pin
        0x18,                          //3.i2c��ַ
        true,                           //4.��chipid
        0x00,                          //5.chipid�Ĵ���
        {0x03, 0xf9},              //6.chipid
        //true,                           //7.�Ƿ�ɨ��
        false,                           //7.�Ƿ�ɨ��
    },
    // DMARD10
    {
        "dmard10",                    //0.IC����
        "gsensor_dmard10.ko",    //1.ko����
        false,                           //2.��sa0 pin
        0x18,                          //3.i2c��ַ
        false,                           //4.��chipid
        0x00,                          //5.chipid�Ĵ���
        {0x00, 0x00},              //6.chipid
        true,                           //7.�Ƿ�ɨ��
    },
    
    // kxtj9-1007
    {
        "kxtj9",                    //0.IC����
        "gsensor_kionix_accel.ko",    //1.ko����
        true,                           //2.��sa0 pin
        0x0e,                          //3.i2c��ַ
        true,                           //4.��chipid
        0x0f,                          //5.chipid�Ĵ���
        {0x08, 0x08},              //6.chipid
        true,                           //7.�Ƿ�ɨ��
    },
    
    // lis3dh
    {
        "lis3dh",                    //0.IC����
        "gsensor_lis3dh_acc.ko",    //1.ko����
        true,                           //2.��sa0 pin
        0x18,                          //3.i2c��ַ
        true,                           //4.��chipid
        0x0f,                          //5.chipid�Ĵ���
        {0x33, 0x33},              //6.chipid
        true,                           //7.�Ƿ�ɨ��
    },
    
    // mc3210
    {
        "mc3210",                    //0.IC����
        "gsensor_mc3210.ko",    //1.ko����
        false,                           //2.��sa0 pin
        0x4c,                          //3.i2c��ַ
        true,                           //4.��chipid
        0x3b,                          //5.chipid�Ĵ���
        {0x90, 0x90},              //6.chipid
        true,                           //7.�Ƿ�ɨ��
    },

    // mc3232
    {
        "mc3232",                    //0.IC����
        "gsensor_mc3232.ko",    //1.ko����
        false,                           //2.��sa0 pin
        0x4c,                          //3.i2c��ַ
        true,                           //4.��chipid
        0x3b,                          //5.chipid�Ĵ���
        {0x19, 0x19},              //6.chipid
        true,                           //7.�Ƿ�ɨ��
    },

    // mc3236
    {
        "mc3236",                    //0.IC����
        "gsensor_mc3236.ko",    //1.ko����
        false,                           //2.��sa0 pin
        0x4c,                          //3.i2c��ַ
        true,                           //4.��chipid
        0x3b,                          //5.chipid�Ĵ���
        {0x60, 0x60},              //6.chipid
        true,                           //7.�Ƿ�ɨ��
    },

    // mma7660
    {
        "mma7660",                    //0.IC����
        "gsensor_mma7660.ko",    //1.ko����
        false,                           //2.��sa0 pin
        0x4c,                          //3.i2c��ַ
        false,                           //4.��chipid
        0x00,                          //5.chipid�Ĵ���
        {0x00, 0x00},              //6.chipid
        true,                           //7.�Ƿ�ɨ��
    },
    
    // mma8452
    {
        "mma8452",                    //0.IC����
        "gsensor_mma8452.ko",    //1.ko����
        true,                           //2.��sa0 pin
        0x1c,                          //3.i2c��ַ
        true,                           //4.��chipid
        0x0d,                          //5.chipid�Ĵ���
        {0x2a, 0x2a},              //6.chipid
        true,                           //7.�Ƿ�ɨ��
    },
    
    // stk8312
    {
        "stk8312",                    //0.IC����
        "gsensor_stk8312.ko",    //1.ko����
        false,                           //2.��sa0 pin
        0x3d,                          //3.i2c��ַ
        false,                           //4.��chipid
        0x00,                          //5.chipid�Ĵ���
        {0x00, 0x00},              //6.chipid
        true,                           //7.�Ƿ�ɨ��
    },
    
    // stk8313
    {
        "stk8313",                    //0.IC����
        "gsensor_stk8313.ko",    //1.ko����
        false,                           //2.��sa0 pin
        0x22,                          //3.i2c��ַ
        false,                           //4.��chipid
        0x00,                          //5.chipid�Ĵ���
        {0x00, 0x00},              //6.chipid
        true,                           //7.�Ƿ�ɨ��
    },
};


#endif
