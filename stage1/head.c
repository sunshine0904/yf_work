#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "head.h"

int count_ip = 0;
int get_count_ip(FILE *fp)
{
	char *buff = (char *)malloc(25);
	int count = 0;

	while(fgets(buff,20,fp)!=NULL)
	{
		count ++;
	}
	fseek(fp,0,SEEK_SET);
	free(buff);

	return count;
}

//strtok the string and storage the result to struct m_ip
#if 1
void split_str(char *buf,struct m_ip stemp[])
{
	char *str1 = buf, *str2, *token, *subtoken;
        char *saveptr1, *saveptr2;
        int j = 0,cnt = 0;
	static int i = 0;
	char *temp = (char *)malloc(10);
       
	
	for (j = 1,str1 = buf; ; j++, str1 = NULL) 
	{
             token = strtok_r(str1,".", &saveptr1);
               if (token == NULL)
                   break;

               for (str2 = token; ; str2 = NULL) 
 	       {
                   subtoken = strtok_r(str2," ", &saveptr2);
                   if (subtoken == NULL)
                       break;
                   //printf("%d ",atoi(subtoken));
		  stemp[i].ip_dec[cnt++]  = atoi(subtoken);
		  //printf("%x",stemp[i].ip_dec[cnt-1]);
		 
		  memset(stemp[i].ip_h + (cnt - 1),0,4);
		  //copy the last byte to char ip_h[]
		  memcpy(stemp[i].ip_h + (cnt - 1),(char *)(&(stemp[i].ip_dec[cnt - 1])),sizeof(char));

               }
        }
	i++;
}
#endif


int get_bit_of_ip(struct m_ip bit_temp,int num_bit)
{
	int group = 0,n_bit = 0;
	group = 3 - num_bit / 8;
	n_bit = num_bit % 8;

	if(bit_temp.ip_dec[group] & 1 << n_bit)
		return 1;
	else
		return 0;
}

int get_one_colum_all_ip(struct m_ip src_ip[],int stor_ip_bit[32][5],int get_bit_time)
{
	static int j = 0;
	int i = 0;
	
	for(i = 0;i<count_ip;i++)
	{
		stor_ip_bit[i][get_bit_time+1] = get_bit_of_ip(src_ip[i],j);
	}
	j++;
}
#if 1
//statistic the same element
int num_of_the_same(int a[count_ip][5])
{
	int i = 0,j = 0,same_time = 0,temp = 0;
	printf("func:%s\n",__func__);
	for(i = 0;i < count_ip;i++)
	{
		printf("%d\n",a[i][0]);
	}
	
	for(i = 0;i<count_ip;i++)
	{
		temp = a[i][0];
		for(j = 0;j<count_ip;j++)
		{
			if(temp == a[j][0])
			{
				same_time ++;
			}
		}
		printf("same_time:%d\n",same_time);
		same_time = 0;
	}

	
		
}
#endif

#if 1
//verify whther the colum statisfy the need or not,if it is ok,then return 1 or return 0
int verify(int a[count_ip][5])
{
	int i = 0,j = 0,temp = 0;
	for(i = 0;i < count_ip;i++)
	{
		a[i][0] = a[i][1] + a[i][2] * 2 + a[i][3] * 2 * 2 + a[i][4]*2*2*2 + a[i][5] * 2*2*2*2; 
	}
	for(i = 0;i< count_ip;i++)
	{
		printf("%d\n",a[i][0]);
	}
	num_of_the_same(a);	
	return 1;
}
#endif

int get_flag_bit(struct m_ip src_ip[],int stor_flag_bit[])
{

	//printf("bit22:%d\n",get_bit_of_ip(src_ip[0],22));
#if 1
	int num_flag = 0;
	int stor_ip_bit[32][5]= {{0}};//stor one colum bit of each ip
	if(count_ip <5&&count_ip > 2)
	{
		num_flag = 2;
	}
	else if (count_ip < 9&&count_ip>4)
	{	
		num_flag = 3;
	}
	else if(count_ip > 8&&count_ip<17)
	{
		num_flag = 4;
	}
	else if (count_ip>16&&count_ip < 33)
	{
		num_flag = 5;
	}
	else
	{
		printf("count_ip:%d . num of ip bigger than 32\n",count_ip);
	}
	
	int i =0,j = 0;
	for(i = 0;i<num_flag;i++)
	{
		get_one_colum_all_ip(src_ip,stor_ip_bit,i);
	}
	
	for(j = 0;j<count_ip;j++)
	{
		for(i = 0;i<num_flag;i++)
		{
			printf("ip[%d]bit[%d]:%d  ",j,i,stor_ip_bit[j][i+1]);
		}
		printf("\n");
	}
	verify(stor_ip_bit);


#endif		
	



}

#if 0

int is_zero(int a,int b)
{
#if 1
	if(a & 1<< b)
		return 1;
	else
		return 0;
#endif	
}

//get the bit of bit_temp
int bit(struct m_ip bit_temp,int ip_nbit)
{
	int num = 0,n_bit = 0;
	
	num = 3 - ip_nbit / 8;
	n_bit = ip_nbit % 8;

	if(bit_temp.ip_dec[num] & 1 << n_bit)
		return 1;
	else
		return 0;
}


//statiscs the number of one,return the time that one repeat
#if 1
int is_valid(struct m_ip is_temp[num_ip],int ip_nbit)
{
	int num = 0,n_bit = 0;

	num = 3 - ip_nbit / 8;
	n_bit = ip_nbit % 8;

	int sum = is_zero(is_temp[0].ip_dec[num],n_bit) +
		  is_zero(is_temp[1].ip_dec[num],n_bit) +
		  is_zero(is_temp[2].ip_dec[num],n_bit) +
		  is_zero(is_temp[3].ip_dec[num],n_bit) +
		  is_zero(is_temp[4].ip_dec[num],n_bit) ;
	return sum;
}
#endif


//verify whther the colum statisfy the need or not,if it is ok,then return 1 or return 0
int verify(short int a[num_ip][4],int re_time)
{
	int valure = 0;
	int i = 0,j = 0,temp = 0;
	int repeat_time = 0;
	for(i = 0;i < num_ip;i++)
	{
		a[i][0] = a[i][1] + a[i][2] * 2 + a[i][3] * 2 * 2; 
	}
	//bubble sort
	for(i = 0;i < 5;i++)
	{
		for(j = i+1;j < 5;j++)
		{
			if(a[i][0] > a[j][0])
			{
				temp = a[i][0];
				a[i][0] = a[j][0];
				a[j][0] = temp;
			}
		}
	}
	#if 0
	//show the result of bubble
	for(i = 0;i<5;i++)
	{
		printf("%d ",a[i][0]);
	}
	putchar(10);
	#endif
	//statistics the repeat_time
#if 0
	i = 0;
	temp = a[i][0];
	while(1)
	{
		//printf("temp:%d a[i+1][0]:%d  ",temp,a[i+1][0]);
		if(temp == a[i+1][0])
		{
			repeat_time++;
		}
		else 
		{
			temp = a[i+1][0];
		} 
		i++;
		if(repeat_time > re_time)
		{
		//printf("repeat_time:%d\n",repeat_time);
			return 0;
		}
		if(i == num_ip - 1 )
		{
			break;
		}
	}
#endif
	temp = 0;
	for(j = 0;j < 8;j++)
	{
		for(i = 0;i<5;i++)
		{
			if(temp == a[i][0])
			{
				repeat_time ++;
			}
		}
		//printf("temp:%d repeat_time:%d \n",temp,repeat_time);
		if(repeat_time > re_time)
		{
			return 0;
			//break;
		}
		repeat_time = 0;
		temp++;
	}

return 1;

}


//get first colum
unsigned int get_fir_colum(struct m_ip bit_temp[num_ip],int colum,short int a[num_ip][4])
{
	static int rec_fir_i = 0;
	int i = 0,j = 0;
	int temp = 0;
	
	i = rec_fir_i;
	while(1)
	{
		//if the one_sum of i colum is bigger than five or smaller 
		//than zero,then give up this colum
		if(is_valid(bit_temp,i) < 5 && is_valid(bit_temp,i) > 0)
		{
			for(j = 0;j<num_ip;j++)
			{
				a[j][colum] = bit(bit_temp[j],i);
				//printf("%d",a[j][colum - 1] );
			}
			rec_fir_i = i;
			//printf("fir_i:%d  ",rec_fir_i);	
			#if 0
			for(temp = 0;temp < 5;temp++)
			{
				printf("%d ",a[temp][1]);
			}
			#endif
			//get_sec_colum(bit_temp,2,a,i);
			return i;
		}
		i++;
	}

}

//get second colum
unsigned int get_sec_colum(struct m_ip bit_temp[num_ip],int colum,short int a[num_ip][4],int fir_colum)
{
	//printf("fir_colum in sec:%d ",fir_colum);
	static int rec_sec_i = 0;
	int i = 0,j = 0;	

	//printf("rec_sec_i:%d\n",rec_sec_i);
	i = rec_sec_i;
	while(1)
	{
		//if the one_sum of i colum is bigger than five or smaller 
		//than zero,then give up this colum
		if(i == fir_colum)
		{
			i++;	
		}	
		if(is_valid(bit_temp,i) < 5 && is_valid(bit_temp,i) > 0)
		{
			for(j = 0;j<num_ip;j++)
			{
				a[j][colum] = bit(bit_temp[j],i);
			}

			rec_sec_i = i;

			if(!verify(a,2))
			{
				//printf("sec verify not ok\n");
				rec_sec_i++;
				get_sec_colum( bit_temp,colum,a,fir_colum);
			}

			i = fir_colum * 100 + rec_sec_i;

			//printf("2:ok fir_colum:%d sec_colum:%d \n",fir_colum,rec_sec_i);
			return i;
		}
		i++;
	}
}



//get second colum
unsigned int get_thir_colum(struct m_ip bit_temp[num_ip],int colum,short int a[num_ip][4],int fir_sec_colum)
{
	static int rec_thir_i = 0;
	int fir_colum = fir_sec_colum / 100,sec_colum = fir_sec_colum % 100;
	//printf("fir_colum:%d sec_colum:%d \n",fir_colum,sec_colum);
	int i = 0,j = 0,q = 0;	
	
	i = rec_thir_i;
	for(q = 0;q<32;q++)
	{
		if(i == fir_colum || i == sec_colum)
		{
			i++;
			if(i == sec_colum || fir_colum)
			{
				i++;
			}
		}	
		//if the one_sum of i colum is bigger than five or smaller 
		//than zero,then give up this colum
		if(is_valid(bit_temp,i) < 5 && is_valid(bit_temp,i) > 0)
		{
			//printf("thir_colum:%d \n",i);
			for(j = 0;j<num_ip;j++)
			{
				a[j][colum] = bit(bit_temp[j],i);
			 //printf("%d",a[j][colum - 1] );
			}
			
			if(!verify(a,1))
			{
				rec_thir_i ++;
				//printf("i:%d rec_thir_i:%d ",i,rec_thir_i);
				get_thir_colum( bit_temp,colum,a,fir_sec_colum);
			}
			else
			{	
			rec_thir_i = i;
			//printf("it is ok -->rec_thir_i::%d\n",rec_thir_i);
			i = fir_sec_colum * 100 + rec_thir_i;
			//printf("thir verify thir_i:%d\n",i);
			return i;
			break;
			}
		}
		i++;
		if(i > 31)
		{
			//get_fir_colum(bit_temp,1,a);
			break;
		}
	}
	//printf("please choose the first colum again\n");
	return 0;
}

//storage path index and path_as to struct
struct encrypt_ip stor_index_as(struct encrypt_ip ecy_ip,int fir,int sec,int thir,short int a[num_ip][4])
{
	int i = 0,j = 0;
	unsigned char temp = 0 << 16;
	ecy_ip.pi.index1 = fir;
	ecy_ip.pi.index2 = sec;
	ecy_ip.pi.index3 = thir;

#if 0
	for(i = 0;i<num_ip;i++)
	{
		printf("%d %d %d\n",a[]);
	}
#endif

	for(i = 0;i < num_ip;i++)
	{
		temp = a[i][1] << 2 | a[i][2]<<1 |a[i][3] << 0;
		//printf("i: %d bit1:%u bit2:%u bit3:%u temp:%d\n",i,a[i][1],a[i][2],a[i][3],temp);
		ecy_ip.pas[i].as = temp;	
		//printf("after stor:%d\n",ecy_ip.pas[i].as);
	}
	return ecy_ip;
}



#if 1
void check_right(struct m_ip is_temp[num_ip],int a,int b,int c)
{
	int num = 0,n_bit = 0;
	int i = 0,j = 0;
	int num_a = 0,num_b = 0,num_c = 0;
	int ipa_nbit = 0,ipb_nbit = 0,ipc_nbit = 0;

	//transfer the bit to array
	num_a = 3 - a/8;
	ipa_nbit = a%8;

	num_b = 3 - b/8;
	ipb_nbit = b%8;
	
	num_c = 3 - c/8;
	ipc_nbit = c%8;


	//printf each bit that choice of all the ip
	printf("ip1:%d %d %d\n",is_zero(is_temp[0].ip_dec[num_a],ipa_nbit),
			  	is_zero(is_temp[0].ip_dec[num_b],ipb_nbit),
			  	is_zero(is_temp[0].ip_dec[num_c],ipc_nbit));

	printf("ip2:%d %d %d\n",is_zero(is_temp[1].ip_dec[num_a],ipa_nbit),
			  	is_zero(is_temp[1].ip_dec[num_b],ipb_nbit),
			  	is_zero(is_temp[1].ip_dec[num_c],ipc_nbit));
	
	printf("ip3:%d %d %d\n",is_zero(is_temp[2].ip_dec[num_a],ipa_nbit),
			  	is_zero(is_temp[2].ip_dec[num_b],ipb_nbit),
			  	is_zero(is_temp[2].ip_dec[num_c],ipc_nbit));

	printf("ip4:%d %d %d\n",is_zero(is_temp[3].ip_dec[num_a],ipa_nbit),
			  	is_zero(is_temp[3].ip_dec[num_b],ipb_nbit),
			  	is_zero(is_temp[3].ip_dec[num_c],ipc_nbit));

	printf("ip5:%d %d %d\n",is_zero(is_temp[4].ip_dec[num_a],ipa_nbit),
			  	is_zero(is_temp[4].ip_dec[num_b],ipb_nbit),
			  	is_zero(is_temp[4].ip_dec[num_c],ipc_nbit));

}
#endif
#endif
