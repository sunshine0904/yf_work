#include <stdio.h>
#include <stdlib.h>
#include "aes_lib.h"

typedef unsigned int u32_t;
typedef unsigned int u16_t;
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
  u32_t session_num = 12345;
  u8_t  len = bitnum;
  u8_t  index[bitnum];
  u16_t index_value[bitnum];
  u8_t  ip1_ip3[ipnum-1][16] ;
  
  
  //128 bit secret key
  unsigned char key[16] = {0}; 
  //expand key
  unsigned char  expKey[4 * Nc * (Nr + 1)]; 
  unsigned char  out[16]; 
  unsigned char  dencrypt[16];
  unsigned int idx;
  
  bitnum = get_index(iptbl, ipnum, indx, value);
 
  printf("bitnum:%d\n",bitnum);
 
#if 0 
  printf("Result: (");
  for (i = 0; i < bitnum; i++) printf("%d ", indx[i]);
  printf(")\n");

  for (i = 0; i < ipnum; i++) {
    printf("[%d]", i);
    printaddr(iptbl[i]);
    printf(" ==> %d\n", value[i]);
  }
#endif


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

  i = 0;
  for(j = 0;j<ipnum;j++)
  {
	  for(i = 0;i<bitnum;i++)
	  {
		  if(index[i] == j)
  	    	   index_value[i] = value[j];
	  }
  }
  
  printf("stor index and value ok\n");

#if 0
  for(i = 0;i<bitnum;i++)
  {
  	printf("index:%d value:%d\n",index[i],index_value[i]);
  }
#endif


  
	/****************encrypt and dencrypt*****************************************/
	for(i = 1;i < ipnum;i++)
	{
		memset(key,0,16);
		//fill the secret key
		unsigned int temp = htonl(*(iptbl + i));
		memcpy(key,&temp,4);

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
		if(i < ipnum -1)
		{
			memcpy(ip1_ip3[i],&iptbl[i-1],4);
			memcpy(ip1_ip3[i]+4,&iptbl[i+1],4);
			memset(ip1_ip3[i],0,8);
		}
		else
		{
			memcpy(ip1_ip3[i],&iptbl[i-1],4);
			memcpy(ip1_ip3[i]+4,&iptbl[0],4);
			memset(ip1_ip3[i],0,8);
		}
		
		printf("data need to encrypt\n");
		printf("%x\n",ip1_ip3[i][0]);
	
		//encrypt the data
		AES_Encrypt(ip1_ip3[i],expKey,out);
		//memset(ecy_ip.aes + i-1,0,16);


		#if 1
		//show the encrypt data
   		printf ("*************encrypted data**************************\n");  
		for (idx=0; idx<16; idx++) 
    		{
   	    		 printf ("%.2x ",ip1_ip3[i][idx]);
    		}
		printf("\n");
		#endif

		AES_Decrypt(out,expKey,dencrypt);
		
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
	/***********************end encrypt ip and fill**********************/






  

	return 0;
}
