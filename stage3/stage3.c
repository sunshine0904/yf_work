#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "head.h"
#include "struct_head.h"
#include "aes_lib.h"



#if 1
int gbit(unsigned int a,int b)
{
	if(a & 1<< b)
		return 1;
	else
		return 0;
}
#endif	


int main()
{
	FILE *fpd,*fps;
	uint32_t i = 0,j = 0,count = 0,src_len = 0;
	char *buff = NULL;
	int cur_point = 0,file_len = 0;
	int dencrypt_index = 0;

	int ipnum = 18;
  	//encrypt struct
  	uint32_t session_num;
  	unsigned char  len;
  	//unsigned char  index[32];
  	//unsigned short index_value[32];
  	//unsigned char  ip1_ip3[ipnum-1][16] ;
	

	struct timeval start,end;//test run time
	gettimeofday(&start,NULL);
	
	//unsigned char ip1[4] = {0xc0,0xa8,0xff,0x1};//prev.txt
	//unsigned int  ip2 = 0xc0<<24 | 0xa8 << 16 | 0xf5 << 8 | 0x02;//key
	unsigned int  ip2 = 0xc0<<24 | 0xc1 << 16 | 0xff << 8 | 0x01;
	unsigned int temp_ip2 = htonl(ip2);
	unsigned char key1[16] = {0};
	memset(key1,0,16);
	memcpy(key1,&temp_ip2,4);

	unsigned char ip3[4] = {0xc0,0xc1,0xff,0x01};

	//expand key
    	unsigned char  expKey[4 * Nc * (Nr + 1)];
	
	unsigned char  dencrypt[16];
 	
	struct pcap_header *file_header = (struct pcap_header *)malloc(sizeof(struct pcap_header));
	struct pkt_header *packet_header = (struct pkt_header *)malloc(sizeof(struct pkt_header));

	struct ether_header *eth_data = (struct ether_header *)malloc(sizeof(struct ether_header)); 
	struct ipheader *ip_data = (struct ipheader *)malloc(sizeof(struct ipheader));
	struct tcphdr *tcphdr_data = (struct tcphdr *)malloc(sizeof(struct tcphdr));
	struct encrypt_ip *aes_struct = (struct encrypt_ip *)malloc(sizeof(struct encrypt_ip)); 


	if((fpd = fopen("../stage2/mod100.pcap","r+"))==NULL)
	{
		printf("open pcap file failure\n");
		exit(0);
	}

	fseek(fpd,0,SEEK_END);
	file_len = ftell(fpd);
	//printf("file_len:%d\n",ftell(fpd));

	//printf("*****************pcap file header*************************/\n");
	fseek(fpd,0,SEEK_SET);
	fread(file_header,1,sizeof(struct pcap_header),fpd);
	cur_point += sizeof(struct pcap_header);
	//printf("pcap_header:\nmagic:%#x\n version_major:%#x version_minor:%#x\nthiszone:%#x\nsigfigs:%#x\nsnaplen:%#x\nlinktype:%#x\n",file_header->magic,file_header->version_major,file_header->version_minor,file_header->thiszone,file_header->sigfigs,file_header->snaplen,file_header->linktype);

	//printf("*****************end pcap file header**************************/\n\n");

	
	

	while(1)
	{
		if(!(cur_point < file_len))
		{
			printf("cur_point:%d file_len:%d\n",cur_point,file_len);
			break;
		}
	//printf("*****************packet header data*************************/\n");
	
	//printf("count:%d\n",count++);
	fseek(fpd,cur_point,SEEK_SET);	
//	printf("1111cur_point:%d\n",cur_point);
	fread(packet_header,1,sizeof(struct pkt_header),fpd);
	cur_point += sizeof(struct pkt_header);
	//printf("2222cur_point:%d\n",cur_point);
	//printf("pkt_header:\nsec_time:%#x  usec_time:%#x   caplen:%#x  len:%#x\n",packet_header->sec_time,packet_header->usec_time,packet_header->caplen,packet_header->len);

	
	//printf("********************eth data****************************/\n");
	fseek(fpd,cur_point,SEEK_SET);
	//printf("1111cur_point:%d\n",cur_point);
	fread(eth_data,1,sizeof(struct ether_header),fpd);
	cur_point += sizeof(struct ether_header);
	//printf("2222cur_point:%d\n",cur_point);

#if 0
	printf("dst mac :");
	for(i = 0;i<6;i++)
	{
		printf("%#x ",eth_data->dmac[i]);
	}
	printf("\n");

	printf("src mac: ");
	for(i = 0;i<6;i++)
	{
		printf("%#x ",eth_data->smac[i]);
	}
	printf("\n");

	printf("eth_type: ");
	printf("%#.4x \n",eth_data->eth_typ_len[0] << 8 | eth_data->eth_typ_len[1]);
#endif
	//printf("********************end eth data****************************/\n\n");
	

	//printf("*********************ip data********************\n");	
	fseek(fpd,cur_point,SEEK_SET);
	//printf("1111cur_point:%d\n",cur_point);
	fread(ip_data,1,sizeof(struct ipheader),fpd);
	cur_point += sizeof(struct ipheader);
	//printf("2222cur_point:%d\n",cur_point);

#if 0
	printf("ipversion and iphdr_len:%#x  ",ip_data->iplv);
	printf("ip_len:%#x  \n",ip_data->iph_len);
	
	printf("it is small endian!  ");
	printf("ip_srcip:%#x  ",ip_data->iph_sourceip);
	printf("ip_dstip:%#x  \n",ip_data->iph_destip);
#endif
	//printf("****************end ip data********************/\n\n");

	int payload_len = ntohs(ip_data->iph_len);
	//printf("payload_len:%d\n",payload_len);
#if 0
	printf("************tcp header data****************/\n");
	fseek(fpd,cur_point,SEEK_SET);
	fread(tcphdr_data,1,sizeof(struct tcphdr),fpd); 
	//cur_point += sizeof(struct tcphdr);
	printf("tcp:src port:%#x dst port:%#x\n",tcphdr_data->source,tcphdr_data->dest);
	printf("*********end tcp header data****************/\n");
#endif

	cur_point += sizeof(struct tcphdr);

	//printf("*********************aes_struct data********************\n");	
	fseek(fpd,cur_point,SEEK_SET);
	//printf("cur_point:%d\n",cur_point);
	unsigned char *buff = malloc(payload_len);
	fread(buff,1,payload_len,fpd);

#if 0
	for(i = 0;i<448;i++)
	{
		printf("%02x ",buff[i]);
	}
#endif
	memcpy(&session_num,buff,4);	
	//printf("\nsession_num:%d\n",session_num);

	memcpy(&len,buff+4,1);
	//printf("len:%d\n",len);
	
	unsigned char index[len];
	memcpy(index,buff+5,len);
	//printf("index:");
	int temp = 0;
	for(i = 0;i<len;i++)
	{
		//printf("%d ",index[i]);
		temp += pow(2,(len-i-1))*gbit(ip2,index[i]); 
	}
	//printf("key_index_value:%d \n",temp);

	unsigned int index_value[len];
	memcpy(&index_value,buff + 5 + len,ipnum * 4);
#if 0
	printf("index value:");
	for(i = 0;i<ipnum;i++)
	{
		printf("%d ",index_value[i]);
	}
	printf("\n");
#endif
	int decry_index = 0;
	for(i = 0;i<ipnum;i++)
	{
		if(index_value[i] == temp)
		{
			//printf("the data we decrypt:%d\n",i);
			decry_index = i;
		}
	}
	//printf("\n");
	
	
	
	AES_ExpandKey(key1,expKey);

	unsigned char ip1_ip3[16] = {0};
	memcpy(ip1_ip3,buff + 5 +len + ipnum * 4 + ((decry_index -1) * 16),16);
	
	AES_Decrypt(ip1_ip3,expKey,dencrypt);
	
#if 0
	printf("decrypt data:\n");
	for(j = 0;j<16;j++)
	{
		printf("%02x ",dencrypt[j]);
	}
	printf("\n");
#endif

	unsigned char compare_ip[4] = {0};
	unsigned char read_ip[4] = {0};
	FILE  *fc = NULL;
	unsigned char ip_buff[25] = {0};
	if((fc = fopen("cmp_ip.txt","r+")) == NULL)
	{
		printf("open cmp_ip file failure\n");
		exit(0);
	}
			

	memcpy(compare_ip,dencrypt,4);
	fgets(ip_buff,20,fc);
	fclose(fc);
	//printf("read_ip:%s\n",ip_buff);
	inet_aton(ip_buff,read_ip);

	for(j = 0;j<4;j++)
	{
		//printf("compare_ip:%02x  ip1:%02x\n",compare_ip[j],read_ip[j]);
		if(compare_ip[j] == read_ip[j])
		{
			if(j == 3)
			{
				//printf("cmp result: the same ip\n");
			}
		}
		else
		{
			//printf("cmp result:it is the different ip\n");
			break;
		}
	}

	
#if 0
	//decrypt all data
	unsigned char ip1_ip3[ipnum-1][16];
	memcpy(ip1_ip3,buff + 5 + len + ipnum*4,(ipnum-1)*16);
	for(i = 0;i<ipnum-1;i++)
	{
		printf("encrypt data:\n");
		for(j = 0;j<16;j++)
		{
			printf("%02x ",ip1_ip3[i][j]);
		}
		printf("\n");
	

		AES_Decrypt(ip1_ip3[i],expKey,dencrypt);
		printf("decrypt data:\n");
		for(j = 0;j<16;j++)
		{
			printf("%02x ",dencrypt[j]);
		}
		printf("\n");
	}
	printf("\n\n");
#endif

	cur_point = cur_point + (packet_header->len - sizeof(struct ether_header) - sizeof(struct ipheader) - sizeof(struct tcphdr));
	//printf("\n****************end packet header data*********************/\n\n");
		
	}
	
	gettimeofday(&end,NULL);
        
	unsigned long int timeuse = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec -start.tv_usec;
	printf("timeuse:%lu us\n",timeuse);
	printf("timeuse:%lu s\n",timeuse/1000000);

	fclose(fpd);
	return 0;
}
