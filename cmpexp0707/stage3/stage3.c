#include "sha1.h"
#include "head.h"

#include <stdio.h>
#include <stdlib.h>



unsigned char ip1[4] = {0xc0,0xa8,0x1,0x1};

int main()
{
	FILE *fpo,*fps,*fpd;
	long int src_cur_point = 0,dst_cur_point = 0,file_len = 0,encry_data_len = 0;
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



	struct pcap_header *file_header = (struct pcap_header *)malloc(sizeof(struct pcap_header));
	struct pkt_header *packet_header = (struct pkt_header *)malloc(sizeof(struct pkt_header));

	struct ether_header *eth_data = (struct ether_header *)malloc(sizeof(struct ether_header)); 
	struct ipheader *ip_data = (struct ipheader *)malloc(sizeof(struct ipheader));
	
	struct tcphdr *tcphdr_buff = (struct tcphdr *)malloc(sizeof(struct tcphdr));


	
	if((fpo = fopen("../stage1/output.txt","r"))==NULL)
	{
		printf("open output.txt file failure\n");
		exit(0);
	}
	if((fps = fopen("cmp_ip.txt","r"))==NULL)
	{
		printf("open cmp_ip.txt file failure\n");
		exit(0);
	}
	if((fpd = fopen("../stage2/mod100.pcap","r"))==NULL)
	//if((fpd = fopen("../../../jl/pcap_yf/pcap/process100.pcap","r"))==NULL)
	{
		printf("open mod100.pcap file failure\n");
		exit(0);
	}
	
	//get the output.txt len
	fseek(fpo,0,SEEK_END);
	encry_data_len = ftell(fpo);
	printf("output.txt file_len:%d\n",ftell(fpo));
	unsigned char *encry_data = malloc(encry_data_len);	



	//get the len of src pcap file
	fseek(fpd,0,SEEK_END);
	file_len = ftell(fpd);
	printf("original pcap file_len:%d\n",ftell(fpd));


	printf("*****************pcap file header*************************/\n");
	fseek(fpd,0,SEEK_SET);
	////printf("sizeof(pcap_header):%d\n",sizeof(struct pcap_header));
	printf(">>>>>>>read file_header src_point1111:%d\n",src_cur_point);
	fread(file_header,1,sizeof(struct pcap_header),fpd);
	//file_header->snaplen -= (1452-src_len-write_data_len) * 10; 
	src_cur_point += sizeof(struct pcap_header);
	printf(">>>>>>>read file_header src_point2222:%d\n",src_cur_point);
	
	
	printf("pcap_header:\nmagic:%#x\n version_major:%#x version_minor:%#x\nthiszone:%#x\nsigfigs:%#x\nsnaplen:%#x\nlinktype:%#x\n",file_header->magic,file_header->version_major,file_header->version_minor,file_header->thiszone,file_header->sigfigs,file_header->snaplen,file_header->linktype);

	printf("*****************end pcap file header**************************/\n\n");




	while(1)
	{
					
		if(!(src_cur_point < file_len))
		{
			break;
		}
		


	//printf("*****************packet header data*************************/\n");
	////printf("src_cur_point:%d\n",src_cur_point);
	//printf("count:%d\n",count++);

	//read pkt_header data
	fseek(fpd,src_cur_point,SEEK_SET);
	//printf(">>>>>>>read pkt_hdr src_point11111:%d\n",src_cur_point);
	fread(packet_header,1,sizeof(struct pkt_header),fpd);
	
	src_cur_point +=sizeof(struct pkt_header);
	//printf(">>>>>>>read pkt_hdr src_point2222:%d\n",src_cur_point);


    	//read eth header data
	fseek(fpd,src_cur_point,SEEK_SET);
	//printf(">>>>>read eth_hdr src_point1111:%d\n",src_cur_point);	
	fread(eth_data,1,sizeof(struct ether_header),fpd);
	src_cur_point += sizeof(struct ether_header);
	//printf(">>>>>read eth_hdr src_point2222:%d\n",src_cur_point);	
	
	////printf("--->eth2 dst_point:%d\n",dst_cur_point);

	//read ip header data
	fseek(fpd,src_cur_point,SEEK_SET);
	//printf(">>>>>read ip_hdr src_point1111:%d\n",src_cur_point);	
	fread(ip_data,1,sizeof(struct ipheader),fpd);
	////printf("test ip_data->len:%d\n",ntohs(((struct ipheader *)ip_data)->iph_len));
	src_cur_point += sizeof(struct ipheader);
	//printf(">>>>>read ip_hdr src_point2222:%d\n",src_cur_point);	

	

	//read tcphdr data
	fseek(fpd,src_cur_point,SEEK_SET);
	//printf(">>>>>read tcp_hdr src_point1111:%d\n",src_cur_point);	
	//tcphdr_buff = malloc(sizeof(struct tcphdr));
	fread(tcphdr_buff,1,sizeof(struct tcphdr),fpd);
	src_cur_point += sizeof(struct tcphdr);
	//printf(">>>>>read tcp_hdr src_point2222:%d\n",src_cur_point);	


	
	//read tcp data
    	fseek(fpd,src_cur_point,SEEK_SET);
	//printf(">>>>>read tcp_data src_point1111:%d\n",src_cur_point);	
	fread(encry_data,1,encry_data_len,fpd);
	//src_cur_point = src_cur_point + tcphdr_data_len;
	//printf(">>>>>read tcp_data src_point2222:%d\n",src_cur_point);	

	printf("encry_data:\n");
	for(i = 0;i<encry_data_len;i++)
	{
		printf("%02x ",encry_data[i]);
	}
	printf("\n");

	unsigned char *pvf2 = encry_data + 16;

	//init be encrypt_data
	memcpy(data,encry_data,16);

	hmac_sha(key,key_len,data,data_len,out,out_len);

	//cmp pvf1 and pvf2
	for(i = 0;i<out_len;i++)
	{
		if(pvf2[i] != out[i])
		{
			printf("it is not equal\n");
			break;
		}
		if(i == 15)
		{
			printf("it is equal\n");
			equal_flag = 1;
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
	}


	src_cur_point = src_cur_point + (packet_header->len - sizeof(struct ether_header) - sizeof(struct ipheader) - sizeof(struct tcphdr));
	//printf("****************end packet header data*********************/\n\n");
		
	}

	free(tcphdr_buff);
	free(eth_data);
	free(ip_data);
	free(packet_header);
	free(encry_data);

	fclose(fpo);
	fclose(fpd);
	fclose(fps);

	return 0;


}
