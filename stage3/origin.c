#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "head.h"
#include "struct_head.h"
#include "aes_lib.h"

struct secret_key
{
	unsigned char mkey[16];
};

int main()
{
	FILE *fpd,*fps;
	uint32_t i = 0,j = 0,count = 0,src_len = 0;
	char *buff = NULL;
	int cur_point = 0,file_len = 0;
	int dencrypt_index = 0;
	
	struct timeval start,end;//test run time
	gettimeofday(&start,NULL);
	
	unsigned char ip1[4] = {0xc0,0xa8,0xff,0x1};//prev.txt
	unsigned char key1[16] = {0xd3,0xc0,0xff,0x14,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	unsigned char ip[4] = {0xd3,0xc0,0xff,0x14};
	struct m_ip ip3;
	memcpy(ip3.ip_h,ip,4);
	ip3.ip_dec[0] = 211;
	ip3.ip_dec[1] = 192;
	ip3.ip_dec[2] = 255;
	ip3.ip_dec[3] = 20;
	
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
	printf("sizeof(pcap_header):%d\n",sizeof(struct pcap_header));
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
	//printf("cur_point:%d\n",cur_point);
	fread(packet_header,1,sizeof(struct pkt_header),fpd);\
	cur_point += sizeof(struct pkt_header);
	printf("pkt_header:\nsec_time:%#x  usec_time:%#x   caplen:%#x  len:%#x\n",packet_header->sec_time,packet_header->usec_time,packet_header->caplen,packet_header->len);

	//fseek(fpd,cur_point+sizeof(struct pkt_header)+sizeof(struct ether_header)+sizeof(struct ipheader),SEEK_SET);
	
	printf("********************eth data****************************/\n");
	fseek(fpd,cur_point,SEEK_SET);
	fread(eth_data,1,sizeof(struct ether_header),fpd);
	cur_point += sizeof(struct ether_header);

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
	printf("********************end eth data****************************/\n\n");
	

	printf("*********************ip data********************\n");	
	fseek(fpd,cur_point,SEEK_SET);
	fread(ip_data,1,sizeof(struct ipheader),fpd);
	cur_point += sizeof(struct ipheader);

	printf("ipversion and iphdr_len:%#x  ",ip_data->iplv);
	printf("ip_len:%#x  \n",ip_data->iph_len);
	
	printf("it is small endian!  ");
	printf("ip_srcip:%#x  ",ip_data->iph_sourceip);
	printf("ip_dstip:%#x  \n",ip_data->iph_destip);
	printf("****************end ip data********************/\n\n");

	cur_point += sizeof(struct tcphdr);
	printf("*********************aes_struct data********************\n");	


	cur_point += sizeof(struct encrypt_ip);
	printf("*********************end aes_struct data********************\n");

	printf("************tcp header data****************/\n");
	fseek(fpd,cur_point,SEEK_SET);
	fread(tcphdr_data,1,sizeof(struct tcphdr),fpd); 
	//cur_point += sizeof(struct tcphdr);
	printf("tcp:src port:%#x dst port:%#x\n",tcphdr_data->source,tcphdr_data->dest);
	printf("*********end tcp header data****************/\n");


	cur_point = cur_point + (packet_header->len - sizeof(struct ether_header) - sizeof(struct ipheader) - sizeof(struct tcphdr));
	printf("****************end packet header data*********************/\n\n");
		
	}
	
	gettimeofday(&end,NULL);
        
	unsigned long int timeuse = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec -start.tv_usec;
	printf("timeuse:%lu us\n",timeuse);

	fclose(fpd);
	return 0;
}
