#ifndef __HEAD_H
#define __HEAD_H
#include <stdio.h>

struct m_ip
{
	int ip_dec[4];
	unsigned char ip_h[4];
};

struct path_index
{
	unsigned char index1:5;
	unsigned char index2:5;
	unsigned char index3:5;
	unsigned char index4:5;
	unsigned char index5:5;
};

struct path_as
{
	unsigned char as:5;
};

#if 1
struct aes_encry
{
	unsigned char ip1_ip3_time[16];
};
#endif

#pragma pack(1)
struct encrypt_ip
{
	unsigned int session_num;
	unsigned char len;
	unsigned char index[0];
	unsigned short index_value[0];	
	struct aes_encry aes[0];
};
#pragma pack()


/***************************************************/
#define MAX_IP_NUM        100
#define MAX_BIT_NUM       32

#define getbit(addr, n) ((addr & mask[n]) == mask[n])
#define lor(val1, val2) ((val1 << 1) | val2)

typedef unsigned int      u32_t;
typedef u32_t             ip_t;

ip_t mask[MAX_BIT_NUM] = {
  0x00000001, 0x00000002, 0x00000004, 0x00000008,
  0x00000010, 0x00000020, 0x00000040, 0x00000080,
  0x00000100, 0x00000200, 0x00000400, 0x00000800,
  0x00001000, 0x00002000, 0x00004000, 0x00008000,
  0x00010000, 0x00020000, 0x00040000, 0x00080000,
  0x00100000, 0x00200000, 0x00400000, 0x00800000,
  0x01000000, 0x02000000, 0x04000000, 0x08000000,
  0x10000000, 0x20000000, 0x40000000, 0x80000000
};

extern int get_index(ip_t tbl[], int n, u32_t indx[], u32_t value[]);
int not_same(u32_t value, u32_t tbl[], int n);
extern int get_index_value(int i,int value[],int index[]);
/*******************************************************/

#endif/*_HEAD_H*/
