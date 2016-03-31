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
	unsigned char session_num[4];
	unsigned char len:5;
	struct path_index pi;
	struct path_as    pas[0];	
	struct aes_encry aes[0];
};
#pragma pack()

extern int count_ip;
extern int stor_ip_bit[32][6];

int get_count_ip(FILE *fp);
void split_str(char *buf,struct m_ip stemp[]);
int get_bit_of_ip(struct m_ip bit_temp,int num_bit);
int get_flag_bit(struct m_ip src_ip[],int stor_flag_bit[]);
#if 0
//void dectobin(int num)
int is_zero(int a,int b);
int bit(struct m_ip bit_temp,int ip_nbit);
int is_valid(struct m_ip is_temp[num_ip],int ip_nbit);

unsigned int get_fir_colum(struct m_ip bit_temp[num_ip],int colum,short int a[num_ip][4]);
unsigned int get_sec_colum(struct m_ip bit_temp[num_ip],int colum,short int a[num_ip][4],int fir_colum);
unsigned int get_thir_colum(struct m_ip bit_temp[num_ip],int colum,short int a[num_ip][4],int fir_sec_colum);
struct encrypt_ip stor_index_as(struct encrypt_ip ecy_ip,int fir,int sec,int thir,short int a[num_ip][4]);
void check_right(struct m_ip is_temp[num_ip],int a,int b,int c);
#endif


#endif/*_HEAD_H*/
