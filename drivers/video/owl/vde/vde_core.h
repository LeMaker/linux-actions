#ifndef _VDE_CORE_H_
#define _VDE_CORE_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum VDE_REG_NO
{
    VDE_REG0 = 0,    
    VDE_REG1 ,  VDE_REG2,  VDE_REG3,  VDE_REG4,  VDE_REG5,  VDE_REG6,  VDE_REG7,  VDE_REG8, 
    VDE_REG9 , VDE_REG10, VDE_REG11, VDE_REG12, VDE_REG13, VDE_REG14, VDE_REG15, VDE_REG16,
    VDE_REG17, VDE_REG18, VDE_REG19, VDE_REG20, VDE_REG21, VDE_REG22, VDE_REG23, VDE_REG24,
    VDE_REG25, VDE_REG26, VDE_REG27, VDE_REG28, VDE_REG29, VDE_REG30, VDE_REG31, VDE_REG32,
    VDE_REG33, VDE_REG34, VDE_REG35, VDE_REG36, VDE_REG37, VDE_REG38, VDE_REG39, VDE_REG40,          
    VDE_REG41 ,VDE_REG42, VDE_REG43, VDE_REG44, VDE_REG45, VDE_REG46, VDE_REG47, VDE_REG48,
    VDE_REG49, VDE_REG50, VDE_REG51, VDE_REG52, VDE_REG53, VDE_REG54, VDE_REG55, VDE_REG56,
    VDE_REG57, VDE_REG58, VDE_REG59, VDE_REG60, VDE_REG61, VDE_REG62, VDE_REG63, VDE_REG64,
    VDE_REG65, VDE_REG66, VDE_REG67, VDE_REG68, VDE_REG69, VDE_REG70, VDE_REG71, VDE_REG72,  
    VDE_REG73, VDE_REG74, VDE_REG75, VDE_REG76, VDE_REG77, VDE_REG78, VDE_REG79, VDE_REG80,
    VDE_REG81, VDE_REG82, VDE_REG83, VDE_REG84, VDE_REG85, VDE_REG86, VDE_REG87, VDE_REG88,
    VDE_REG89, VDE_REG90, VDE_REG91, VDE_REG92, VDE_REG93, VDE_REG94, VDE_REG_MAX
} VDE_RegNO_t;   


#define MAX_VDE_REG_NUM         (VDE_REG_MAX+1)


// ��Ϊһ��backdoor, �ṩ����Ĳ�������ӿ�, ʹ�÷��������üĴ�������
#define CODEC_CUSTOMIZE_ADDR            (VDE_REG_MAX)
#define CODEC_CUSTOMIZE_VALUE_PERFORMANCE  0x00000001
#define CODEC_CUSTOMIZE_VALUE_LOWPOWER     0x00000002
#define CODEC_CUSTOMIZE_VALUE_DROPFRAME    0x00000004
#define CODEC_CUSTOMIZE_VALUE_MAX          0xffffffff


typedef enum VDE_STATUS
{
    VDE_STATUS_IDLE                 = 0x1,   
    VDE_STATUS_READY_TO_RUN,                // ��ǰinstance�Ѿ�ִ��run, ��vde������instanceռ��
    VDE_STATUS_RUNING,                      // ��������
    VDE_STATUS_GOTFRAME,                    // ��֡���
    VDE_STATUS_JPEG_SLICE_READY     = 0x100, // JPEG ����һ��slice���, ��ʱ���ܱ�����instance��ϣ�ֱ��GOTFRAMEʱ�ſ��Ա����
    VDE_STATUS_DIRECTMV_FULL,               // h264 Direct mv buffer������,��Ҫ������������������    
    VDE_STATUS_STREAM_EMPTY,                // ���������꣬��Ҫ������������������VDE, 5202��������ִ����     
    VDE_STATUS_ASO_DETECTED,                // ��⵽h264 ASO, ��Ҫ������ʽ���������vde, 5202��������ִ����
    VDE_STATUS_TIMEOUT              = -1,   // timeout
    VDE_STATUS_STREAM_ERROR         = -2,   // ��������        
    VDE_STATUS_BUS_ERROR            = -3,   // ����ddr����, ��������Ϊ���õķ����������ڴ�
    VDE_STATUS_DEAD                 = -4,   // vpx���ˣ��޷������κμĴ���, video�м����Ҫ�ر�����instance    
    VDE_STATUS_UNKNOWN_ERROR        = -0x100       // ��������        
} VDE_Status_t;


typedef struct vde_handle 
{    
    // ���Ĵ���
    unsigned int (*readReg)(struct vde_handle*, VDE_RegNO_t);
    
    // д�Ĵ���, ״̬�Ĵ���(reg1)������ͳһ����, ����д, ����-1��
    int (*writeReg)(struct vde_handle*, VDE_RegNO_t, const unsigned int);

    // ��������, ����-1����ʾvde״̬���󣬲�������;
    int (*run)(struct vde_handle*);
    
    // ��ѯVDE״̬���������汾��vde�������з���VDE_STATUS_RUNING
    int (*query)(struct vde_handle*, VDE_Status_t*);    
    
    // ��ѯVDE״̬, �����汾, ֱ��VDE_STATUS_DEAD����VDE�жϲ���, ����ֵ��VDE_Status_t
    int (*query_timeout)(struct vde_handle*, VDE_Status_t*);    
    
    // ��״̬תΪidle
    int (*reset)(struct vde_handle*);   
    
} vde_handle_t;

// ��ȡ���. ����������ߴﵽ��������instance����������NULL;     
vde_handle_t *vde_getHandle(void);

// �رվ��    
void vde_freeHandle(struct vde_handle*);

// DEBUG, ���ڲ���ӡ
void vde_enable_log(void);

// DEBUG, �ر��ڲ���ӡ
void vde_disable_log(void);

// DEBUG ��ȡ��ǰ���е�instance��Ϣ�����мĴ�����Ϣ, ������Ч
void vde_dump_info(void);



/**********************************************************
�������:  vd_h264.so  ----> libvde_core.so ----> vde_drv.ko

���������� ���ܿ����ʹ�ã�����ͬinstance��������ͬһ�������С�

ʹ�÷�����
    Android.mk������ LOCAL_SHARED_LIBRARIES := libvde_core
    ����ʱ���Զ�����libvde_core.so, �Ϳ����Զ�����so, ʹ��api����, ����Ҫֱ�ӵ���vde_drv.ko

����˵��:  reg1(status�Ĵ���������д

Example code��

    int vde_close(void *codec_handle)
    {
        // ...
        vde_freeHandle(codec_handle->vde_handle);
        codec_handle->vde_handle = NULL;
        // ...        
    }
    
    int vde_init(void *codec_handle)
    {
        codec_handle->vde_handle == vde_getHandle();
        if(codec_handle->vde_handle == NULL) return -1;
        
        if(DEBUG)
            vde_enable_log();           
        
        // if you need to know about overload of VDE;
        vde_dump_info();
                
        return 0;
    }
    
    int vde_decode_one_frame(void *codec_handle)
    {
        int rt;        
        unsigned int value;
        int status;
        
        vde_handle_t *vde = codec_handle->vde_handle;                
                      
        vde->reset(vde);      
        
        value = vde->readReg(vde, REG10);                
        value &= 0x2;
        
        rt = vde->writeReg(vde, REG10, value);
        if(rt) goto SOMETHING_WRONG;
        
        rt = vde->run(vde);
        if(rt) goto SOMETHING_WRONG;          
                        
#if USE_QUERY 
        // ���飬Ч�ʵ�    
        while(timeout_ms < 10000)        
            rt = vde->query(vde, &status);
            if(rt) return -1;
            
            if(status != VDE_STATUS_RUNING && status != VDE_STATUS_IDLE) 
                break;               
        }
#else                
        // dosomthing else, �����飬�ڲ���������ȣ������cpu������
        rt = vde->query_timeout(vde, &status);
        if(rt) goto SOMETHING_WRONG;

#endif
        
        if(status == VDE_STATUS_GOTFRAME) {                
            return 0;
        } else {
            goto SOMETHING_WRONG;
        }           
           
SOMETHING_WRONG:
        
        if(status == VDE_STATUS_DEAD) {
            ACTAL_ERROR("VDE Died");            
            return -1; //fatal error here.
        } else {
            ACTAL_ERROR("something wrong, check your code")
            return -1;
        }       
                   
    }

**********************************************************/
#ifdef __cplusplus
}
#endif

#endif//_VDE_CORE_H_

