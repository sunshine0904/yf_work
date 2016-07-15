#include <stdio.h>
#include <stdlib.h>

#include "head.h"
#include "aes_lib.h"

void main()
{
	FILE *fps,*fpd;	
	long int src_point = NULL,dst_point = NULL;
	int i = 0,count = 0,ip_total_len = 0,src_file_len = 0;
	
	struct timeval start,end;//test run time
	gettimeofday(&start,NULL);

	if((fps = fopen("cmp_ip.txt","r"))==NULL)
	{
		printf("open cmp_ip.txt file failure\n");
		exit(0);
	}
	//if((fps = fopen("../stage2/mod100.pcap","r"))==NULL)
	if((fps = fopen("../../stage2/mod10.pcap","r"))==NULL)
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

	
#if 0
	void cost_write_loop()
	{
		pid_t pid_tmp = 0;
		char *cmd[100];
		pid_tmp = getpid();
		printf("pid:%d\n",pid_tmp);
		sprintf(cmd,"ps -h -u -p %d",pid_tmp);
		freopen("./stage3_cmp_cost.log","w+",stdout);
		while(1)
		{
			system(cmd);
		}
	}

	 pthread_t tid;
         if(pthread_create(&tid,NULL,cost_write_loop,NULL) != 0)
	 {
	      printf("creae cost_loop thread error\n");
	      return -1;
	 }

#endif	
	
	
	
	
	
	while(1){

	//read pkt_hdr
	fseek(fps,src_point,SEEK_SET);
	fread(pkthdr,1,sizeof(struct pkt_header),fps);
	src_point += sizeof(struct pkt_header);

	//write pkt_hdr
	fseek(fpd,dst_point,SEEK_SET);
	fwrite(pkthdr,1,sizeof(struct pkt_header),fpd);
	dst_point += sizeof(struct pkt_header);

	//read eth hdr
	fseek(fps,src_point,SEEK_SET);
	fread(ethhdr,1,sizeof(struct ether_header),fps);
	src_point += sizeof(struct ether_header);
	
	//write pkt_hdr
	fseek(fpd,dst_point,SEEK_SET);
	fwrite(ethhdr,1,sizeof(struct ether_header),fpd);
	dst_point += sizeof(struct ether_header);
	
	//read ip hdr
	fseek(fps,src_point,SEEK_SET);
	fread(iphdr,1,sizeof(struct ipheader),fps);
	ip_total_len = htons(iphdr->iph_len);
	//printf("ip_total_len:%d\n",ip_total_len);
	src_point += sizeof(struct ipheader);

	//write ip hdr
	fseek(fpd,dst_point,SEEK_SET);
	fwrite(iphdr,1,sizeof(struct ipheader),fpd);
	dst_point += sizeof(struct ipheader);

	//read tcp hdr
	fseek(fps,src_point,SEEK_SET);
	fread(tcphdr,1,sizeof(struct tcpheader),fps);
	src_point += sizeof(struct tcpheader);

	//write tcp hdr
	fseek(fpd,dst_point,SEEK_SET);
	fwrite(tcphdr,1,sizeof(struct tcpheader),fpd);
	dst_point += sizeof(struct tcpheader);

	//read tcp data
	unsigned char *buff = malloc(ip_total_len);
	fseek(fps,src_point,SEEK_SET);
	fread(buff,1,ip_total_len - 20,fps);
	src_point += (ip_total_len - 20);

	stage3_process(buff);

	//write tcp data
	fseek(fpd,dst_point,SEEK_SET);
	fwrite(buff,1,ip_total_len - 20,fpd);
	dst_point += (ip_total_len - 20);
	free(buff);
	
	if(src_point == src_file_len)
	{
		//printf("file end\n");
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
	
	gettimeofday(&end,NULL);
        
	unsigned long int timeuse = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec -start.tv_usec;
	printf("timeuse:%lu us\n",timeuse);
	printf("timeuse:%lu s\n",timeuse/1000000);
	

}

int stage3_process(unsigned char *temp_buf)
{
	unsigned char ip1[4] = {0xc0,0xa8,0x1,0x1};

	int i = 0,equal_flag = 0,encry_data_len = 32;
	
	//variable about hmac_sha
	unsigned char key[16] = {0x0};
	unsigned char key_len = 16;
	unsigned char data[16] = {0x0};
	unsigned char data_len = 16;
	unsigned char out[16] = {0x0};
	unsigned char out_len = 16;

	//aes
  	unsigned char  expKey[4 * Nc * (Nr + 1)]; 


	//initital key
	memset(key,0,16);
	memcpy(key,ip1,4);
	
	//initital data
	memset(data,0,16);

	//initital out
	memset(out,0,16);
	unsigned char *encry_data = malloc(encry_data_len);
	memcpy(encry_data,temp_buf,encry_data_len);
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
	//hmac_sha(key,key_len,data,data_len,out,out_len);
	AES_ExpandKey(key,expKey);  
	AES_Encrypt(data,expKey,out);

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
		//cp pvf' as data
		memcpy(data,out,16);

		//initital out
		memset(out,0,16);

		printf("key:\n");
		for(i = 0;i<key_len;i++)
		{
			printf("%02x ",key[i]);
		}
		printf("\n");
		
		printf("data:\n");
		for(i = 0;i<data_len;i++)
		{
			printf("%02x ",data[i]);
		}
		printf("\n");
		
		printf("out:\n");
		for(i = 0;i<out_len;i++)
		{
			printf("%02x ",out[i]);
		}
		printf("\n");

		//hmac_sha(key,key_len,data,data_len,out,out_len);
		AES_Encrypt(data,expKey,out);
		
#if 1
		printf("pvf'':\n");
		for(i = 0;i<out_len;i++)
		{
			printf("%02x ",out[i]);
		}
		printf("\n");
#endif	
		//copy pvf'' to replace pvf'
		memcpy(encry_data+16,out,16);
	}

#if 1
	printf("encry_data:pvf and pvf'\n");
	for(i = 0;i<encry_data_len;i++)
	{
		printf("%02x ",encry_data[i]);
	}
	printf("\n");
	printf("\n");

#endif

	memcpy(temp_buf,encry_data,encry_data_len);

}
