#include <stdio.h>
#include "sha1.h"

//variable about hmac_sha
unsigned char key[16] = {0x0};
unsigned char key_len = 16;
unsigned char data[16] = {0x0};
unsigned char data_len = 16;
unsigned char out[16] = {0x0};
unsigned char out_len = 16;

unsigned char ip1[4] = {0xc0,0xa8,0x1,0x1};
unsigned char ip2[4] = {0xc0,0xa8,0x1,0x2};
unsigned char ip3[4] = {0xc0,0xa8,0x1,0x3};
unsigned char ip4[4] = {0xc0,0xa8,0x1,0x4};
unsigned char ip5[4] = {0xc0,0xa8,0x1,0x5};

void main()
{
	int i = 0,j = 0;	
	SHA1_CTX ictx,octx,tctx;	
	

	for(i = 0;i<5;i++)
	{
		SHA1Init(&ictx);
		SHA1Init(&octx);
		SHA1Init(&tctx);
	
		//initital out
		memset(out,0,16);
		
		//initital key
		memset(key,0,16);
		memcpy(key,ip1,4);
	
		//initital data
		memset(data,0,16);
		memcpy(data,ip2,4);
		memcpy(data+4,ip3,4);
		memcpy(data+8,ip4,4);
		memcpy(data+12,ip5,4);

		printf("key:");
		for(j = 0;j<16;j++)
		{
			printf("%02x ",((unsigned char *)key)[j]);
		}
		printf("\n");


		printf("encry_data:");
		for(j = 0;j<16;j++)
		{
			printf("%02x ",((unsigned char *)data)[j]);
		}
		printf("\n");

		hmac_sha(key,key_len,data,data_len,out,out_len);

		printf("out %d:\n",out_len);
		for(j = 0;j<out_len;j++)
		{
			printf("%02x ",out[j]);
		}
		printf("\n");
		printf("\n");
	}

}
