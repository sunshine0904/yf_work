#ifndef AES_LIB_H
#define AES_LIB_H

#include <string.h>

//����ֲ���������ͣ�����������ֲ
typedef unsigned char AES_U8;
typedef unsigned int  AES_U16;

//�洢��Flash�еĴ洢���Ͷ���(û�б�Ҫ���ÿո����)
#define CODE_MEM_TYP  code

//��֧��128λ���ܱ�׼
#define Nc (4)          // state�������չ��Կ������
#define Nr (10)         // ��������


/*_____ D E F I N I T I O N __________________________________________________*/

/*_____ D E C L A R A T I O N ________________________________________________*/

void AES_ExpandKey(AES_U8 *key, AES_U8 *expKey);  //��չ��Կ�Ӳ������൱�ڳ�ʼ��AES�㷨
void AES_Encrypt(AES_U8 *in, AES_U8 *expKey, AES_U8 *out);  //128λ���ܺ���
void AES_Decrypt(AES_U8 *in, AES_U8 *expKey, AES_U8 *out);	//128λ���ܺ���


/******************************************************************************
                                ʹ�÷���
#include <stdio.h>
#include "AES_Lib.h"

AES_U8 in[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,  //����16�ֽڣ�128λ������
                  0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};  

AES_U8 key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,  //����16�ֽڣ�128λ����Կ
                  0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};  
AES_U8 out[16];  //����һ������16��Ԫ�أ�128λ�������飬���������

void main (void)  //����Ӵ˴���ʼ����
{
AES_U8  expKey[4 * Nc * (Nr + 1)];  //����һ������չ��Կ�����飬����4*4*(10+1)��Ԫ��
AES_U16 idx;  //����һ���������ͱ�������Ϊ��������

    AES_ExpandKey (key, expKey);  //��Կ����չ���㷨�ĳ�ʼ����
    
    AES_Encrypt (in, expKey, out);  //��in����������м��ܣ���ͨ��out�������

    for (idx=0; idx<16; idx++)  //ͨ��out�����������
    {
        printf ("%.2x ", out[idx]);
    }
    printf ("\n");  //�س���

    AES_Decrypt (out, expkey, in);  //��out���Ľ��н��ܣ���ͨ��in�������
    
    for (idx=0; idx<16; idx++)  //ͨ��in���齫���ܺ���������
    {
        printf ("%.2x ", in[idx]);
    }
    printf ("\n");  //�س���
}
******************************************************************************/

#endif /*AES_LIB_H*/
