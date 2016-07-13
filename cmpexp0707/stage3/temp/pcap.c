#include <stdio.h>
#include <stdlib.h>

#include "head.h"


void main()
{
	FILE *fps,*fpd;	
	long int src_point = NULL,dst_point = NULL;
	int i = 0,count = 0,ip_total_len = 0,src_file_len = 0;

	if((fps = fopen("../../stage2/mod100.pcap","r"))==NULL)
	{
		printf("open mod100.pcap file failure\n");
		exit(0);
	}
	if((fpd = fopen("stage3.pcap","a+"))==NULL)
	{
		printf("open stage3.pcap file failure\n");
		exit(0);
	}

	struct pcap_header * pcaphdr = (struct pcap_header *)malloc(sizeof(struct pcap_header)); 
	struct pkt_header * pkthdr = (struct pkt_header *)malloc(sizeof(struct pcap_header));
	struct ether_header *ethhdr = (struct ether_header *)malloc(sizeof(struct ether_header));
	struct ipheader *iphdr = (struct ipheader *)malloc(sizeof(struct ipheader)); 
	struct tcpheader *tcphdr = (struct tcpheader *)malloc(sizeof(struct tcpheader));

	fseek(fps,0,SEEK_SET);
	fseek(fps,0,SEEK_END);
	src_file_len =  ftell(fps);
	printf("src_file_len:%d\n",src_file_len);


	//read pcaphdr
	fseek(fps,0,SEEK_SET);
	printf("read pcaphdr:%d\n",fread(pcaphdr,1,sizeof(struct pcap_header),fps));
	src_point += sizeof(struct pcap_header);

	//write pcaphdr
	fseek(fpd,0,SEEK_SET);
	printf("write pcaphdr:%d\n",fwrite(pcaphdr,1,sizeof(struct pcap_header),fpd));
	dst_point += sizeof(struct pcap_header);

	memset(pcaphdr,0,sizeof(struct pcap_header));

	while(1){

	//read pkt_hdr
	fseek(fps,src_point,SEEK_SET);
	printf("read pkthdr:%d\n",fread(pkthdr,1,sizeof(struct pkt_header),fps));
	src_point += sizeof(struct pkt_header);

	//write pkt_hdr
	fseek(fpd,dst_point,SEEK_SET);
	printf("write pkthdr:%d\n",fwrite(pkthdr,1,sizeof(struct pkt_header),fpd));
	dst_point += sizeof(struct pkt_header);

	//read eth hdr
	fseek(fps,src_point,SEEK_SET);
	printf("read eth hdr:%d\n",fread(ethhdr,1,sizeof(struct ether_header),fps));
	src_point += sizeof(struct ether_header);
	
	//write pkt_hdr
	fseek(fpd,dst_point,SEEK_SET);
	printf("write eth hdr:%d\n",fwrite(ethhdr,1,sizeof(struct ether_header),fpd));
	dst_point += sizeof(struct ether_header);
	
	//read ip hdr
	fseek(fps,src_point,SEEK_SET);
	printf("read ip hdr:%d\n",fread(iphdr,1,sizeof(struct ipheader),fps));
	ip_total_len = htons(iphdr->iph_len);
	printf("ip_total_len:%d\n",ip_total_len);
	src_point += sizeof(struct ipheader);

	//write ip hdr
	fseek(fpd,dst_point,SEEK_SET);
	printf("write ip hdr:%d\n",fwrite(iphdr,1,sizeof(struct ipheader),fpd));
	dst_point += sizeof(struct ipheader);

	//read tcp hdr
	fseek(fps,src_point,SEEK_SET);
	printf("read tcp hdr:%d\n",fread(tcphdr,1,sizeof(struct tcpheader),fps));
	src_point += sizeof(struct tcpheader);

	//write tcp hdr
	fseek(fpd,dst_point,SEEK_SET);
	printf("write tcp hdr:%d\n",fwrite(tcphdr,1,sizeof(struct tcpheader),fpd));
	dst_point += sizeof(struct tcpheader);

	//read tcp data
	unsigned char *buff = malloc(ip_total_len);
	fseek(fps,src_point,SEEK_SET);
	printf("read data:%d\n",fread(buff,1,ip_total_len - 20,fps));
	src_point += (ip_total_len - 20);

	stage3_process(buff);

	//write tcp data
	fseek(fpd,dst_point,SEEK_SET);
	printf("write data:%d\n",fwrite(buff,1,ip_total_len - 20,fpd));
	dst_point += (ip_total_len - 20);
	free(buff);
	
	if(src_point == src_file_len)
	{
		printf("file end\n");
		break;
	}

	
	memset(pkthdr,0,sizeof(struct pkt_header));
	memset(ethhdr,0,sizeof(struct ether_header));
	memset(iphdr,0,sizeof(struct ipheader));
	memset(tcphdr,0,sizeof(struct tcpheader));
	
	
	}	
	
	free(pkthdr);
	free(ethhdr);
	free(iphdr);
	free(tcphdr);

}

int stage3_process(unsigned char *temp_buf)
{
	unsigned char ip1[4] = {0xc0,0xa8,0x1,0x1};

	int i = 0,equal_flag = 0;
	
	//variable about hmac_sha
	unsigned char key[16] = {0x0};
	unsigned char key_len = 16;
	unsigned char data[16] = {0x0};
	unsigned char data_len = 16;
	unsigned char out[16] = {0x0};
	unsigned char out_len = 16;

	//initital key
	memset(key,0,16);
	memcpy(key,ip1,4);
	
	//initital data
	memset(data,0,16);

	//initital out
	memset(out,0,16);
	unsigned char *encry_data = malloc(encry_data_len);
	memcpy(encry_data,temp_buff,encry_data_len);
#if 1 
	printf("encry_data:pvf and pvf'\n");
	for(i = 0;i<encry_data_len;i++)
	{
		printf("%02x ",encry_data[i]);
	}
	printf("\n");
#endif
	unsigned char *pvf2 = encry_data + 16;

	//init be encrypt_data
	memcpy(data,encry_data,16);
	memset(encry_data,0,16);

#if 1
	printf("pvf_data:\n");
	for(i = 0;i<data_len;i++)
	{
		printf("%02x ",data[i]);
	}
	printf("\n");

	printf("key:\n");
	for(i = 0;i<key_len;i++)
	{
		printf("%02x ",key[i]);
	}
	printf("\n");
#endif

	memset(out,0,out_len);
	hmac_sha(key,key_len,data,data_len,out,out_len);

#if 1
	printf("pvf':\n");
	for(i = 0;i<out_len;i++)
	{
		printf("%02x ",out[i]);
	}
	printf("\n");
#endif
	//cmp pvf1 and pvf2
	for(i = 0;i<out_len;i++)
	{
		if(pvf2[i] != out[i])
		{
			printf("it is not equal\n");
			equal_flag = 0;
			break;
		}
		else
		{
			if(i == 14)
			{
				printf("it is equal\n");
				equal_flag = 1;
			}
		}
	}
	if(equal_flag == 1)
	{
		//init be encrypt_data
		memcpy(data,encry_data+16,16);

		//initital data
		memset(data,0,16);

		//initital out
		memset(out,0,16);

		hmac_sha(key,key_len,data,data_len,out,out_len);
		
		printf("pvf'':\n");
		for(i = 0;i<out_len;i++)
		{
			printf("%02x ",out[i]);
		}
		printf("\n");
	
		//copy pvf'' to replace pvf'
		memcpy(encry_data+16,out,16);
	}
#endif
}
