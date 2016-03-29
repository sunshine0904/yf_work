#include <stdio.h>
#include <stdlib.h>
#include "aes_lib.h"
#include "head.h"

int main()
{
	FILE *fps;
	int i = 0,j = 0;
	char buffer[25];

	//open ip file
	if((fps = fopen("ip.txt","r")) == NULL)
	{
		printf("open ip.txt failed\n");
		return 0;
	}
	count_ip = get_count_ip(fps);
	
	int stor_flag_bit[count_ip];
	//read ip.txt and storage in src_ip
	struct m_ip src_ip[count_ip];
	while(fgets(buffer,20,fps) != NULL)
	{
		//printf("%s",buffer);
		split_str(buffer,src_ip);
	}

#if 1
	//just for debug
	for( i = 0;i<count_ip;i++)
	{
		printf("ip%d:   ",i+1);
		for(j = 0;j<4;j++)
		{
			printf("%02x ",src_ip[i].ip_h[j]);
		}
		printf("\n");
	}
#endif	
	get_flag_bit(src_ip,stor_flag_bit);	

	return 0;
}
