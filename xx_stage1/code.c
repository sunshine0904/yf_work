#include <stdio.h>
#include <string.h>

#define DEBUG 1

#include "code.h"

u8_t g_mask[BITS_NUM], bit_num;

void init(u8_t *bit_indx, u8_t n) {
  memset(g_mask, 0, BITS_NUM);
  memset(bit_indx, 0, BITS_NUM);
  for (bit_num = 0; (1 << bit_num) < n; bit_num++) ;
}

u8_t func(u8_t ptr, u8_t *tbl, ip_t *addrs, u8_t n) {
  u8_t tmp, flag, value[MAX_IP_NUM];
  int i, j, k;
  PRINTF("ptr = %u   n = %u\n", ptr, n);
  if (ptr == bit_num) { return 1; }
    
  for (i = 0; i < BITS_NUM; i++) {
    if (!g_mask[i]) {
      memset(value, 0, sizeof(value));
      
      PRINTF("ptrs: (");
      for (j = 0; j < ptr; j++) PRINTF("%d ", tbl[j]);
      PRINTF(")\n");

      PRINTF("%d: (", i); 
      for (k = 0; k < n; k++) {
        tmp = getbit(addrs[k], i);
	PRINTF("%d ", tmp);
        for (j = ptr - 1; j >= 0; j--) {
	  //	  PRINTF("tmp = %d\n", tmp);
          tmp <<= 1;
	  //	  PRINTF("tmp = %d\n", tmp);
          tmp |= getbit(addrs[k], tbl[j]);
	  //	  PRINTF("(%d %d %d) tmp = %d", i, k, j, tmp);
        } /* for j */
        value[tmp]++;
      } /* for k */
      PRINTF(")\n");
      
      for (j = 0; 
           j < MAX_IP_NUM && value[j] <= (1 << bit_num - ptr - 1); 
           j++) ;

      for (j = 0; j < MAX_IP_NUM; j++) 
	PRINTF("%d ", value[j]);
      PRINTF("\n");
      
      if (j == MAX_IP_NUM) {
        tbl[ptr] = i;
        g_mask[i] = 1;
        
        flag = func(ptr + 1, tbl, addrs, n);
        
        if (flag) { return flag; }
        else { tbl[ptr] = 0; g_mask[i] = 0; }
      } /* if (j == MAX_IP_NUM) */
    } /* if (!mask[i]) */
  } /* for i */
  
  return 0;
}
#define TEST 0
#if !TEST
int main() {
  // examples
  // ip_num: the number of ip addresses
  // addrs:  the array that stores the ip addresses
  u8_t ip_num = 11, bit_indx[BITS_NUM], flag, i, j, tmp;

#if 0
  ip_t addrs[MAX_IP_NUM] = {
    ip_arr2ip(192, 168, 1, 1),
    ip_arr2ip(192, 168, 1, 2),
    ip_arr2ip(192, 168, 1, 3),
    ip_arr2ip(192, 168, 1, 4),
    ip_arr2ip(192, 168, 1, 5),
    ip_arr2ip(241, 125, 23, 89),
    ip_arr2ip(123, 24, 56, 78),
    ip_arr2ip(1, 2, 3, 8),
    ip_arr2ip(0, 0, 0, 0),
    ip_arr2ip(255, 255, 255, 255),
    ip_arr2ip(17, 23, 3, 59)
  };
#endif
  ip_t addrs[MAX_IP_NUM] ={
 	ip_arr2ip(192,168,255,1),
	ip_arr2ip(211,192,255,20),
	ip_arr2ip(117,192,255,5),
	ip_arr2ip(169,192,255,15),
	ip_arr2ip(230,192,255,33),
	ip_arr2ip(168,125,11,2),
	ip_arr2ip(192,168,2,3),
	ip_arr2ip(192,168,5,6),
	ip_arr2ip(168,135,112,21),
	ip_arr2ip(192,168,6,54),
  };
  
  init(bit_indx, ip_num);
  PRINTF("bit_num = %u\n", bit_num);
  for (i = 0; i < BITS_NUM; i++) PRINTF("%d ", g_mask[i]);
  PRINTF("\n");
  for (i = 0; i < ip_num; i++) {
    PRINTF("%d: %u\n", i, addrs[i]);
  }
  
  flag = func(0, bit_indx, addrs, ip_num);
  if (flag) {
 
    PRINTF("bit_indx: (");
    for (j = 0; j < bit_num; j++) PRINTF("%d ", bit_indx[j]);
    PRINTF(")\n");

    for (i = 0; i < ip_num; i++) {
      PRINTIPADDR(addrs[i]);
      PRINTF(" -> ");
      
      PRINTF("0x");
      for (j = bit_num - 1; j >= 0; j--) {
	//        tmp |= getbit(addrs[i], bit_indx[j]);
	//        tmp <<= 1;
	PRINTF("%1d", getbit(addrs[i], bit_indx[j]));
      }
      PRINTF("\n");
    }
  } else {
    PRINTF("Find no result! ");
    PRINTF("Current result: ");
      
    for (i = 0; i < bit_num; i++) {
      PRINTF("%u ", bit_indx[i]);
    }
    PRINTF("\n");
  }
}
#else
int main() {
  unsigned int value = 0x12345678;
  int i = 0;

  for (i = 31; i >= 0; i--) {
    printf("%d", getbit(value, i));
    if (i % 4 == 0) printf(":");
  }
  printf("\n");

  return 0;
}
#endif /* TEST */
