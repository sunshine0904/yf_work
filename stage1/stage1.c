#include <stdio.h>
#include <stdlib.h>
#include "aes_lib.h"

typedef unsigned int u32_t;
typedef unsigned short u16_t;
typedef unsigned char u8_t;

#define ip2uint(val1, val2, val3, val4) (\
  (val1 << 24) | (val2 << 16) | (val3 << 8) | (val4)) 
#define printaddr(addr) printf("%d.%d.%d.%d", \
  ((addr & 0xff000000) >> 24), ((addr & 0x00ff0000) >> 16), \
  ((addr & 0x0000ff00) >> 8),  (addr & 0x000000ff))

unsigned int iptbl[] = {
/*
    ip2uint(192, 168, 1, 1),
    ip2uint(224, 0,   0, 1),
    ip2uint(123, 234, 5, 6),
    ip2uint(111, 222, 333, 444), 
    ip2uint(0, 0, 0, 0),
    ip2uint(255, 255, 255, 255)


    ip2uint(192, 168, 255, 1),
    ip2uint(192, 168, 245, 2),
    ip2uint(192, 193, 255, 1),
    ip2uint(193, 168, 255, 2),
    ip2uint(192, 169, 255, 1),
    ip2uint(192, 168, 233, 2),
    ip2uint(192, 167, 255, 1),
    ip2uint(191, 168, 255, 2),
    ip2uint(192, 168, 155, 9)

*/
    ip2uint(192, 168, 255, 1),
    ip2uint(192, 168, 245, 2),
    ip2uint(192, 193, 255, 1),
    ip2uint(193, 168, 255, 2),
    ip2uint(192, 169, 255, 1),
    ip2uint(192, 168, 233, 2),
    ip2uint(192, 167, 255, 1),
    ip2uint(191, 168, 255, 2),
    ip2uint(192, 168, 155, 9),

    ip2uint(182, 178, 255, 3),
    ip2uint(182, 178, 245, 4),
    ip2uint(182, 183, 255, 5),
    ip2uint(183, 178, 255, 78),
    ip2uint(182, 179, 255, 3),
    ip2uint(182, 178, 233, 4),
    ip2uint(182, 177, 255, 5),
    ip2uint(181, 178, 255, 78),
    ip2uint(182, 178, 155, 10),

    ip2uint(172, 188, 155, 5),
    ip2uint(172, 188, 145, 6),
    ip2uint(172, 183, 155, 7),
    ip2uint(173, 188, 155, 8),
    ip2uint(172, 189, 155, 5),
    ip2uint(172, 188, 133, 6),
    ip2uint(172, 187, 155, 7),
    ip2uint(171, 188, 155, 8),
    ip2uint(172, 188, 155, 11),

   #if 0
    ip2uint(162, 198, 255, 7),
    ip2uint(162, 198, 245, 8),
    ip2uint(162, 193, 255, 9),
    ip2uint(163, 198, 255, 10),
    ip2uint(162, 199, 255, 7),
    ip2uint(162, 198, 233, 8),
    ip2uint(162, 197, 255, 9),
    ip2uint(161, 198, 255, 10),
    ip2uint(162, 198, 155, 12)
#endif
  };


int main()
{
  u32_t indx[32] = {0};
  u32_t value[100] = {0};
  int i = 0,j = 0, ipnum = 27, bitnum = 0;
  
  //encrypt struct
  u32_t session_num ;
  u8_t  len;
  u8_t  index[bitnum];
  //u32_t index_value[ipnum];
  u8_t  ip1_ip3[ipnum-1][16] ;

  u8_t index_value_size = 1;;
  	u8_t index_value1[ipnum];
  	u16_t index_value2[ipnum];
  	u32_t index_value3[ipnum];
  
  
  //128 bit secret key
  unsigned char key[16] = {0}; 
  //expand key
  unsigned char  input[16];
  unsigned char  expKey[4 * Nc * (Nr + 1)]; 
  unsigned char  out[16]; 
  unsigned char  dencrypt[16];
  unsigned int idx;
  
  bitnum = get_index(iptbl, ipnum, indx, value);
 
  printf("bitnum:%d\n",bitnum);
  
  if(bitnum < 9)
  {
	index_value_size = 1;
  }
  else if(bitnum > 8 && bitnum < 17)
  {
	index_value_size = 2;
  }
  else if(bitnum > 16 && bitnum < 33)
  {
	index_value_size = 4;
  }

  int buff_len = sizeof(session_num) + sizeof(len) + sizeof(u8_t) * bitnum + index_value_size * ipnum + (ipnum -1) * 16 * sizeof(u8_t);
  unsigned char *buff = malloc(buff_len);
  printf("buff_len:%d\n",buff_len);

#if 1 
  printf("Result: (");
  for (i = 0; i < bitnum; i++) printf("%d ", indx[i]);
  printf(")\n");

  for (i = 0; i < ipnum; i++) {
    printf("[%d]", i);
    printaddr(iptbl[i]);
    printf(" ==> %d\n", value[i]);
  }
#endif


  session_num  = 12345;
  len = bitnum;
  //stor index
  for(i = 0;i<bitnum;i++)
  {
 	 index[i] = indx[i];
  }

#if 0
  for(i = 0;i<bitnum;i++)
  {
 	 printf("index:%d  ",index[i]);
  }
  printf("\n");
#endif

  //copy ency struct data to buff
  memcpy(buff,&session_num,sizeof(session_num));
  memcpy(buff + sizeof(session_num),&len,sizeof(len));
  memcpy(buff + sizeof(session_num) + sizeof(len),index,bitnum);

#if 1

  for(i = 0;i<ipnum;i++)
  {
	  if(index_value_size == 1)
	  {
		index_value1[i] = value[i];
	  }
	  else if(index_value_size == 2)
	  {
		index_value2[i] = value[i];
	  }
	  else if(index_value_size == 3)
	  {
		index_value3[i] = value[i];
	  }
  }

  printf("index_value:");
  for(i = 0;i<ipnum;i++)
  {
	  if(index_value_size == 1)
	  {
  		printf("%d ",index_value1[i]);
	  }
	  else if(index_value_size == 2)
	  {
  		printf("%d ",index_value2[i]);
	  }
	  else if(index_value_size == 3)
	  {
  		printf("%d ",index_value3[i]);
	  }
  }
  printf("\n");
#endif

  //copy encypt data to buff
  if(index_value_size == 1)
  {
  	memcpy(buff + sizeof(session_num) + sizeof(len)+sizeof(u8_t)*bitnum,index_value1,ipnum * index_value_size);
  }
  if(index_value_size == 2)
  {
  	memcpy(buff + sizeof(session_num) + sizeof(len)+sizeof(u8_t)*bitnum,index_value2,ipnum * index_value_size);
  }
  else if(index_value_size == 3)
  {
  	memcpy(buff + sizeof(session_num) + sizeof(len)+sizeof(u8_t)*bitnum,index_value3,ipnum * index_value_size);
  }
  
  printf("stor index and value ok\n");



  
	/****************encrypt and dencrypt*****************************************/
	for(i = 1;i < ipnum;i++)
	{
		memset(key,0,16);
		//fill the secret key
		unsigned int key_temp = htonl(*(iptbl + i));
		memcpy(key,&key_temp,4);

		#if 1
   		printf ("***************secrte key***********************\n");  
		for (idx=0; idx<16; idx++) 
    		{
   	    		 printf ("%.2x ",key[idx]);
    		}
		printf("\n");
		#endif

		//expand the key and inital algorithm
		AES_ExpandKey(key,expKey);

		//inital the data will be encrypted
		memset(input,0,16);
		unsigned int data1= 0,data2 = 0;
		if(i < ipnum -1)
		{
			data1 = htonl(iptbl[i-1]);
			data2 = htonl(iptbl[i+1]);
			memcpy(input,&data1,4);
			memcpy(input+4,&data2,4);
			//memset(ip1_ip3[i],0,8);
		}
		else
		{
			data1 = htonl(iptbl[i-1]);
			data2 = htonl(iptbl[0]);
			memcpy(input,&data1,4);
			memcpy(input+4,&data2,4);
			//memset(ip1_ip3[i],0,8);
		}
		
		
		#if 1
		//show the  data be encrypt
   		printf ("*************input encrypted data**************************\n");  
		for (idx=0; idx<16; idx++) 
    		{
   	    		 printf ("%.02x ",input[idx]);
    		}
		printf("\n");
		#endif
	
		//encrypt the data
		AES_Encrypt(input,expKey,ip1_ip3[i-1]);
		//memset(ecy_ip.aes + i-1,0,16);

		
		#if 1
		//show the encrypt data
   		printf ("*************encrypted data**************************\n");  
		for (idx=0; idx<16; idx++) 
    		{
   	    		 printf ("%.2x ",ip1_ip3[i-1][idx]);
    		}
		printf("\n");
		#endif
		
		AES_Decrypt(ip1_ip3[i-1],expKey,dencrypt);

#if 1
   		printf ("*************dencrypted data**************************\n");  
		for (idx=0; idx<16; idx++) 
    		{
       			 printf ("%.2x ", dencrypt[idx]);
    		}
		printf("\n");
		printf("\n");
#endif
		

	}
  	memcpy(buff + sizeof(session_num) + sizeof(len)+sizeof(u8_t)*bitnum + index_value_size * ipnum,ip1_ip3,(ipnum-1)*16);
	/***********************end encrypt ip and fill**********************/


	//open output file
	FILE *fpd;
	if((fpd = fopen("output.txt","a+")) == NULL)
	{
		printf("open output file failure\n");
		return 0;
	}
	printf("fwrite ret:%d\n",fwrite(buff,1,buff_len,fpd));

#if 1
	printf("buff_len:%d bitnum:%d\n",buff_len,bitnum);
	for(i = 0;i<buff_len;i++)
	{
		printf("%02x ",buff[i]);
	}
	printf("\n");
#endif

	free(buff);
	fclose(fpd);
	return 0;
}
