#include "sha1.h"
#include <stdio.h>
#include <stdlib.h>

typedef unsigned char u8_t;
typedef unsigned short  u16_t;
typedef unsigned int    u32_t;

u8_t ip1[4] = {0xc0,0xa8,0x1,0x1};

u8_t ip2[4] = {0xc0,0xa8,0x1,0x2};
u8_t ip3[4] = {0xc0,0xa8,0x1,0x3};
u8_t ip4[4] = {0xc0,0xa8,0x1,0x4};
u8_t ip5[4] = {0xc0,0xa8,0x1,0x5};



void main()
{
	//variable about hmac_sha
	u8_t key[16] = {0x0};
	u8_t key_len = 16;
	u8_t data[16] = {0x0};
	u8_t data_len = 16;
	u8_t out[16] = {0x0};
	u8_t out_len = 16;


	//def buff to storage encrypt data
	u8_t *buff = NULL;
	u8_t buff_len = 0;

	buff_len = sizeof(key) + sizeof(out);
	buff = (u8_t *)malloc(buff_len);
	memset(buff,0,buff_len);

	//initital key
	memset(key,0,16);
	memcpy(key,ip1,4);


	//initital data
	memset(data,0,16);
	memcpy(data,ip2,4);
	memcpy(data+4,ip3,4);
	memcpy(data+8,ip4,4);
	memcpy(data+12,ip5,4);

	hmac_sha(key,key_len,data,data_len,out,out_len);
	
	//copy encrypt data
	memcpy(buff,ip2,4);
	memcpy(buff + 4,ip3,4);
	memcpy(buff + 8,ip4,4);
	memcpy(buff + 12,ip5,4);
	memcpy(buff + 16,out,16);
	
	//open output file
	FILE *fpd;
	if((fpd = fopen("output.txt","a+")) == NULL)
	{
		printf("open output file failure\n");
		return 0;
	}
	printf("fwrite ret:%d\n",fwrite(buff,1,buff_len,fpd));



	fclose(fpd);
}
