#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "head.h"


int main(int argc,char **argv)
{
	if(argc != 2)
	{
		printf("please input payload data len!\n usage: ./stage2 800(payload data len)\n");
		return -1;
	}
	
	FILE *fpd,*fps,*fpp;
	uint32_t i = 0,j = 0,count = 0,src_len = 0,tcphdr_data_len = 0;
	int write_data_len = atoi(argv[1]);
	unsigned char *ins_buff = NULL,*eth_ip_buff = NULL,*tcphdr_data_buff = NULL;
	int src_cur_point = 0,dst_cur_point = 0,file_len = 0;
	struct pcap_header *file_header = (struct pcap_header *)malloc(sizeof(struct pcap_header));
	struct pkt_header *packet_header = (struct pkt_header *)malloc(sizeof(struct pkt_header));

	struct ether_header *eth_data = (struct ether_header *)malloc(sizeof(struct ether_header)); 
	struct ipheader *ip_data = (struct ipheader *)malloc(sizeof(struct ipheader));
	
	struct tcphdr *tcphdr_buff = (struct tcphdr *)malloc(sizeof(struct tcphdr));

	printf("write_payload_data_len:%d\n",write_data_len);


	if((fpd = fopen("10.pcap","r"))==NULL)
	{
		printf("open 10.pcap file failure\n");
		exit(0);
	}
	if((fps = fopen("../xx_stage1ok/output.txt","r"))==NULL)
	{
		printf("open output.txt file failure\n");
		exit(0);
	}
	if((fpp = fopen("mod10.pcap","w+"))==NULL)
	{
		printf("open mod10.pcap file failure\n");
		exit(0);
	}
	
	//get the len of insert file
	fseek(fps,0,SEEK_END);
	src_len = ftell(fps);
	printf("ency struct len:%d\n",src_len);
	ins_buff = (char *)malloc(src_len);
	fseek(fps,0,SEEK_SET);
	if(fread(ins_buff,1,src_len,fps) != src_len)
	{
		printf("read ency struct error\n");
		return -1;
	}
	for(i = 0;i<src_len;i++)
	{
		printf("%02x ",ins_buff[i]);
	}
	printf("\n");


	//get the len of src pcap file
	//printf("sizeof(struct pcap_header):%d\n",sizeof(struct pcap_header));
	fseek(fpd,0,SEEK_END);
	file_len = ftell(fpd);
	printf("original pcap file_len:%d\n",ftell(fpd));


	printf("*****************pcap file header*************************/\n");
	fseek(fpd,0,SEEK_SET);
	//printf("sizeof(pcap_header):%d\n",sizeof(struct pcap_header));
	printf(">>>>>>>read file_header src_point1111:%d\n",src_cur_point);
	fread(file_header,1,sizeof(struct pcap_header),fpd);
	//file_header->snaplen -= (1452-src_len-write_data_len) * 10; 
	src_cur_point += sizeof(struct pcap_header);
	printf(">>>>>>>read file_header src_point2222:%d\n",src_cur_point);
	
	fseek(fpp,0,SEEK_SET);
	printf("--->pcap file hdr1 dst_point:%d\n",dst_cur_point);
	fwrite(file_header,1,sizeof(struct pcap_header),fpp);
	dst_cur_point += sizeof(struct pcap_header);
	printf("--->pcap file  hdr2 dst_point:%d\n",dst_cur_point);
	
	printf("pcap_header:\nmagic:%#x\n version_major:%#x version_minor:%#x\nthiszone:%#x\nsigfigs:%#x\nsnaplen:%#x\nlinktype:%#x\n",file_header->magic,file_header->version_major,file_header->version_minor,file_header->thiszone,file_header->sigfigs,file_header->snaplen,file_header->linktype);

	printf("*****************end pcap file header**************************/\n\n");

	
	

	while(1)
	{
		if(!(src_cur_point < file_len))
		{
			break;
		}
	printf("*****************packet header data*************************/\n");
	//printf("src_cur_point:%d\n",src_cur_point);
	printf("count:%d\n",count++);

	//read pkt_header data
	fseek(fpd,src_cur_point,SEEK_SET);
	printf(">>>>>>>read pkt_hdr src_point11111:%d\n",src_cur_point);
	fread(packet_header,1,sizeof(struct pkt_header),fpd);
	//printf("1111pkt_header:\nsec_time:%#x\nusec_time:%#x\ncaplen:%#x\nlen:%#x\n",packet_header->sec_time,packet_header->usec_time,packet_header->caplen,packet_header->len);
	
	packet_header-> caplen = sizeof(struct ether_header) + sizeof(struct ipheader) + sizeof(struct tcphdr) + src_len + write_data_len;
	packet_header-> len = sizeof(struct ether_header) + sizeof(struct ipheader) + sizeof(struct tcphdr) + src_len + write_data_len;
	//printf("2222pkt_header:\nsec_time:%#x\nusec_time:%#x\ncaplen:%#x\nlen:%#x\n",packet_header->sec_time,packet_header->usec_time,packet_header->caplen,packet_header->len);
	src_cur_point +=sizeof(struct pkt_header);
	printf(">>>>>>>read pkt_hdr src_point2222:%d\n",src_cur_point);

	//write pkt_header data
	printf("--->pkt_head1 dst_point:%d\n",dst_cur_point);
	fseek(fpp,dst_cur_point,SEEK_SET);	
	fwrite(packet_header,1,sizeof(struct pkt_header),fpp);
	dst_cur_point +=sizeof(struct pkt_header);
	printf("--->pkt_head2 dst_point:%d\n",dst_cur_point);


    	//read eth header data
	fseek(fpd,src_cur_point,SEEK_SET);
	printf(">>>>>read eth_hdr src_point1111:%d\n",src_cur_point);	
	fread(eth_data,1,sizeof(struct ether_header),fpd);
	src_cur_point += sizeof(struct ether_header);
	printf(">>>>>read eth_hdr src_point2222:%d\n",src_cur_point);	
	
	//write eth header data
	fseek(fpp,dst_cur_point,SEEK_SET);	
	printf("--->eth1 dst_point:%d\n",dst_cur_point);
	fwrite(eth_data,1,sizeof(struct ether_header),fpp);
	dst_cur_point = dst_cur_point + sizeof(struct ether_header);
	printf("--->eth2 dst_point:%d\n",dst_cur_point);

	//read ip header data
	fseek(fpd,src_cur_point,SEEK_SET);
	printf(">>>>>read ip_hdr src_point1111:%d\n",src_cur_point);	
	fread(ip_data,1,sizeof(struct ipheader),fpd);
	//printf("test ip_data->len:%d\n",ntohs(((struct ipheader *)ip_data)->iph_len));
	int temp_ip_len = ntohs(((struct ipheader *)ip_data)->iph_len);
	((struct ipheader *)ip_data)->iph_len = htons(sizeof(struct  tcphdr) + src_len + write_data_len); 
	src_cur_point += sizeof(struct ipheader);
	printf(">>>>>read ip_hdr src_point2222:%d\n",src_cur_point);	

	//write ip header data
	fseek(fpp,dst_cur_point,SEEK_SET);	
	printf("--->ip1 dst_point:%d\n",dst_cur_point);
	fwrite(ip_data,1,sizeof(struct ipheader),fpp);
	dst_cur_point += sizeof(struct ipheader);
	printf("--->ip2 dst_point:%d\n",dst_cur_point);
	
	
	

	
#if 0 	
	fseek(fpd,src_cur_point,SEEK_SET);
	eth_ip_buff = malloc(sizeof(struct ether_header) + sizeof(struct ipheader));
	fread(eth_ip_buff,1,sizeof(struct ether_header) + sizeof(struct ipheader),fpd);
	src_cur_point = src_cur_point + sizeof(struct ether_header) + sizeof(struct ipheader);
	printf("src_cur_point:%d\n",src_cur_point);

	fseek(fpp,dst_cur_point,SEEK_SET);	
	fwrite(eth_ip_buff,1,sizeof(struct ether_header) + sizeof(struct ipheader),fpp);
	dst_cur_point = dst_cur_point + sizeof(struct ether_header) + sizeof(struct ipheader);
#endif	
	

	//read tcphdr data
	fseek(fpd,src_cur_point,SEEK_SET);
	printf(">>>>>read tcp_hdr src_point1111:%d\n",src_cur_point);	
	tcphdr_buff = malloc(sizeof(struct tcphdr));
	fread(tcphdr_buff,1,sizeof(struct tcphdr),fpd);
	src_cur_point += sizeof(struct tcphdr);
	printf(">>>>>read tcp_hdr src_point2222:%d\n",src_cur_point);	

	//write tcphdr data
	fseek(fpp,dst_cur_point,SEEK_SET);
	printf("--->tcphdr1 dst_point:%d\n",dst_cur_point);
	fwrite(tcphdr_buff,1,sizeof(struct tcphdr),fpp);
	dst_cur_point += sizeof(struct tcphdr);
	printf("--->tcphdr2 dst_point:%d\n",dst_cur_point);


	printf("the space we need\n");
	
	//write encypt struct
	printf("---------wirte the encypt struct---------\n");
	fseek(fpp,dst_cur_point,SEEK_SET);	
	printf("--->ency1 dst_point:%d\n",dst_cur_point);
	fwrite(ins_buff,1,src_len,fpp);
	dst_cur_point = dst_cur_point + src_len;
	printf("--->ency2 dst_point:%d\n",dst_cur_point);

	
	//read tcp data
    	fseek(fpd,src_cur_point,SEEK_SET);
	//tcphdr_data_len = 1506 - sizeof(struct ether_header) - sizeof(struct ipheader) - sizeof(struct tcphdr);
	tcphdr_data_len = temp_ip_len - sizeof(struct ipheader) - sizeof(struct tcphdr);
	tcphdr_data_buff = malloc(tcphdr_data_len);
	printf(">>>>>read tcp_data src_point1111:%d\n",src_cur_point);	
	fread(tcphdr_data_buff,1,tcphdr_data_len,fpd);
	src_cur_point = src_cur_point + tcphdr_data_len;
	printf(">>>>>read tcp_data src_point2222:%d\n",src_cur_point);	


	//write tcp data 
	fseek(fpp,dst_cur_point,SEEK_SET);	
	printf("--->tcpdata1 dst_point:%d\n",dst_cur_point);
	printf("write:%d\n",fwrite(tcphdr_data_buff,1,write_data_len,fpp));
	dst_cur_point = dst_cur_point + write_data_len;
	printf("--->tcpdata2 dst_point:%d\n",dst_cur_point);

	printf("src_cur_point:%d\n",src_cur_point);

	//memset(packet_header,0,sizeof(struct pkt_header));
	printf("****************end packet header data*********************/\n\n");
		
	}

	fclose(fpp);
	fclose(fpd);
	fclose(fps);
	return 0;
}
