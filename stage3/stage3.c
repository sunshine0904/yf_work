#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "head.h"
#include "struct_head.h"
#include "aes_lib.h"


int main()
{
	FILE *fpd,*fps;
	uint32_t i = 0,j = 0,count = 0,src_len = 0;
	char *buff = NULL;
	int cur_point = 0,file_len = 0;
	int dencrypt_index = 0;

	int ipnum = 27;
  	//encrypt struct
  	uint32_t session_num;
  	unsigned char  len;
  	//unsigned char  index[32];
  	//unsigned short index_value[32];
  	//unsigned char  ip1_ip3[ipnum-1][16] ;
	

	struct timeval start,end;//test run time
	gettimeofday(&start,NULL);
	
	unsigned char ip1[4] = {0xc0,0xa8,0xff,0x1};//prev.txt
	unsigned char key1[16] = {0xc0,0xa8,0xf5,0x2,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	unsigned char ip[4] = {0xd3,0xc0,0xff,0x14};

	//expand key
    	unsigned char  expKey[4 * Nc * (Nr + 1)];
	
	unsigned char  dencrypt[16];
 	
	struct pcap_header *file_header = (struct pcap_header *)malloc(sizeof(struct pcap_header));
	struct pkt_header *packet_header = (struct pkt_header *)malloc(sizeof(struct pkt_header));

	struct ether_header *eth_data = (struct ether_header *)malloc(sizeof(struct ether_header)); 
	struct ipheader *ip_data = (struct ipheader *)malloc(sizeof(struct ipheader));
	struct tcphdr *tcphdr_data = (struct tcphdr *)malloc(sizeof(struct tcphdr));
	struct encrypt_ip *aes_struct = (struct encrypt_ip *)malloc(sizeof(struct encrypt_ip)); 


	if((fpd = fopen("../stage2/mod10.pcap","r+"))==NULL)
	{
		printf("open pcap file failure\n");
		exit(0);
	}

	//printf("sizeof(struct pcap_header):%d\n",sizeof(struct pcap_header));
	fseek(fpd,0,SEEK_END);
	file_len = ftell(fpd);
	printf("file_len:%d\n",ftell(fpd));

	printf("*****************pcap file header*************************/\n");
	fseek(fpd,0,SEEK_SET);
	//printf("sizeof(pcap_header):%d\n",sizeof(struct pcap_header));
	fread(file_header,1,sizeof(struct pcap_header),fpd);
	cur_point += sizeof(struct pcap_header);
	printf("pcap_header:\nmagic:%#x\n version_major:%#x version_minor:%#x\nthiszone:%#x\nsigfigs:%#x\nsnaplen:%#x\nlinktype:%#x\n",file_header->magic,file_header->version_major,file_header->version_minor,file_header->thiszone,file_header->sigfigs,file_header->snaplen,file_header->linktype);

	printf("*****************end pcap file header**************************/\n\n");

	
	

	while(1)
	{
		if(!(cur_point < file_len))
		{
			break;
		}
	printf("*****************packet header data*************************/\n");
	printf("count:%d\n",count++);
	fseek(fpd,cur_point,SEEK_SET);	
	printf("1111cur_point:%d\n",cur_point);
	fread(packet_header,1,sizeof(struct pkt_header),fpd);
	cur_point += sizeof(struct pkt_header);
	printf("2222cur_point:%d\n",cur_point);
	printf("pkt_header:\nsec_time:%#x  usec_time:%#x   caplen:%#x  len:%#x\n",packet_header->sec_time,packet_header->usec_time,packet_header->caplen,packet_header->len);

	//fseek(fpd,cur_point+sizeof(struct pkt_header)+sizeof(struct ether_header)+sizeof(struct ipheader),SEEK_SET);
	
	printf("********************eth data****************************/\n");
	fseek(fpd,cur_point,SEEK_SET);
	printf("1111cur_point:%d\n",cur_point);
	fread(eth_data,1,sizeof(struct ether_header),fpd);
	cur_point += sizeof(struct ether_header);
	printf("2222cur_point:%d\n",cur_point);

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
	printf("********************end eth data****************************/\n\n");
	

	printf("*********************ip data********************\n");	
	fseek(fpd,cur_point,SEEK_SET);
	printf("1111cur_point:%d\n",cur_point);
	fread(ip_data,1,sizeof(struct ipheader),fpd);
	cur_point += sizeof(struct ipheader);
	printf("2222cur_point:%d\n",cur_point);

#if 0
	printf("ipversion and iphdr_len:%#x  ",ip_data->iplv);
	printf("ip_len:%#x  \n",ip_data->iph_len);
	
	printf("it is small endian!  ");
	printf("ip_srcip:%#x  ",ip_data->iph_sourceip);
	printf("ip_dstip:%#x  \n",ip_data->iph_destip);
#endif
	printf("****************end ip data********************/\n\n");

	int payload_len = ntohs(ip_data->iph_len);
	printf("payload_len:%d\n",payload_len);
#if 0
	printf("************tcp header data****************/\n");
	fseek(fpd,cur_point,SEEK_SET);
	fread(tcphdr_data,1,sizeof(struct tcphdr),fpd); 
	//cur_point += sizeof(struct tcphdr);
	printf("tcp:src port:%#x dst port:%#x\n",tcphdr_data->source,tcphdr_data->dest);
	printf("*********end tcp header data****************/\n");
#endif

	cur_point += sizeof(struct tcphdr);

	printf("*********************aes_struct data********************\n");	
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
	printf("\nsession_num:%d\n",session_num);

	memcpy(&len,buff+4,1);
	printf("len:%d\n",len);
	
	unsigned char index[len];
	memcpy(index,buff+5,len);
	printf("index:");
	for(i = 0;i<len;i++)
	{
		printf("%d ",index[i]);
	}
	printf("\n");

	unsigned short index_value[len];
	memcpy(&index_value,buff + 5 + len,len * 2);
	printf("index value:");
	for(i = 0;i<len;i++)
	{
		printf("%d ",index_value[i]);
	}
	printf("\n");
	
	AES_ExpandKey(key1,expKey);

	unsigned char ip1_ip3[ipnum-1][16];
	memcpy(ip1_ip3,buff + 5 + len *3,(ipnum-1)*16);
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


	cur_point = cur_point + (packet_header->len - sizeof(struct ether_header) - sizeof(struct ipheader) - sizeof(struct tcphdr));
	printf("\n****************end packet header data*********************/\n\n");
		
	}
	
	gettimeofday(&end,NULL);
        
	unsigned long int timeuse = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec -start.tv_usec;
	printf("timeuse:%lu us\n",timeuse);

	fclose(fpd);
	return 0;
}
