#include <stdio.h>
#include <string.h>

#include "code2.h"

#define DEBUG 0

#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif /* DEBUG */

int func(ip_t tbl[], int n, u32_t indx[], u32_t value[]) {
  int i, j, k, ret;
#if DEBUG
  int s, t;
#endif /* DEBUG */
  u32_t mark[MAX_BIT_NUM];
  
  memset(value, 0, sizeof(value));
  memset(mark, 0, sizeof(mark));
  
  for (i = 1, ret = 0; i < n; i++) {
    PRINTF("i = %d: ", i);

    for (j = 0; j < ret; j++) {
      PRINTF("value[%d] = lor(%u, getbit(%u, %u))\n", i, value[i], tbl[i], indx[j]);
      value[i] = lor(value[i], getbit(tbl[i], indx[j]));
      PRINTF("value[%d] = %u\n", i, value[i]);
    }
    PRINTF("not_same() = %d\n", not_same(value[i], value, i));
    if (i > 1 && not_same(value[i], value, i)) continue;

    PRINTF("Index: ");
    for (s = 0; s < MAX_BIT_NUM; s++) PRINTF("%u ", indx[s]);
    PRINTF("\nValue: ");
    for (s = 0; s < n; s++) PRINTF("%u ", value[s]);
    PRINTF("\nMark: ");
    for (s = 0; s < MAX_BIT_NUM; s++) PRINTF("%u ", mark[s]);
    PRINTF("\n");
    
    for (j = 0; j < MAX_BIT_NUM; j++) {
      if (!mark[j]) {
        PRINTF("%2d: ", j);
        for (k = 0; k <= i; k++) {
          value[k] = lor(value[k], getbit(tbl[k], j));
          PRINTF("value[%d] = %u\t", k, value[k]);
        }
        PRINTF("\n");
        if (not_same(value[i], value, i)) {
          indx[ret++] = j;
	  mark[j] = 1;
          break;
        } else {
          for (k = 0; k <= i; k++) value[k] >>= 1;
        }
      }
    }

    PRINTF("%s\n", j == MAX_BIT_NUM ? "Not found" : "found");
  
  }
  
  return ret;
}

int not_same(u32_t value, u32_t tbl[], int n) {
  int i;
  
  for (i = 0; i < n && value != tbl[i]; i++) ;
  
  return i == n;
}

int main() {
  ip_t iptbl[] = {
/*
    ip2uint(192, 168, 1, 1),
    ip2uint(224, 0,   0, 1),
    ip2uint(123, 234, 5, 6),
    ip2uint(111, 222, 333, 444), 
    ip2uint(0, 0, 0, 0),
    ip2uint(255, 255, 255, 255)


    ip2uint(192, 168, 255, 1),
    ip2uint(192, 168, 245, 2),
    ip2uint(192, 193, 255, 1),
    ip2uint(193, 168, 255, 2),
    ip2uint(192, 169, 255, 1),
    ip2uint(192, 168, 233, 2),
    ip2uint(192, 167, 255, 1),
    ip2uint(191, 168, 255, 2),
    ip2uint(192, 168, 155, 9)

*/
    ip2uint(192, 168, 255, 1),
    ip2uint(192, 168, 245, 2),
    ip2uint(192, 193, 255, 1),
    ip2uint(193, 168, 255, 2),
    ip2uint(192, 169, 255, 1),
    ip2uint(192, 168, 233, 2),
    ip2uint(192, 167, 255, 1),
    ip2uint(191, 168, 255, 2),
    ip2uint(192, 168, 155, 9),

    ip2uint(182, 178, 255, 3),
    ip2uint(182, 178, 245, 4),
    ip2uint(182, 183, 255, 5),
    ip2uint(183, 178, 255, 78),
    ip2uint(182, 179, 255, 3),
    ip2uint(182, 178, 233, 4),
    ip2uint(182, 177, 255, 5),
    ip2uint(181, 178, 255, 78),
    ip2uint(182, 178, 155, 10),

    ip2uint(172, 188, 155, 5),
    ip2uint(172, 188, 145, 6),
    ip2uint(172, 183, 155, 7),
    ip2uint(173, 188, 155, 8),
    ip2uint(172, 189, 155, 5),
    ip2uint(172, 188, 133, 6),
    ip2uint(172, 187, 155, 7),
    ip2uint(171, 188, 155, 8),
    ip2uint(172, 188, 155, 11),

   #if 0
    ip2uint(162, 198, 255, 7),
    ip2uint(162, 198, 245, 8),
    ip2uint(162, 193, 255, 9),
    ip2uint(163, 198, 255, 10),
    ip2uint(162, 199, 255, 7),
    ip2uint(162, 198, 233, 8),
    ip2uint(162, 197, 255, 9),
    ip2uint(161, 198, 255, 10),
    ip2uint(162, 198, 155, 12)
#endif
  };
  u32_t indx[MAX_BIT_NUM];
  u32_t value[MAX_IP_NUM];
  int i, ipnum = 27, bitnum;
  
  memset(indx, 0, sizeof(indx));
  memset(value, 0, sizeof(value));
  
  bitnum = func(iptbl, ipnum, indx, value);
  
  printf("Result: (");
  for (i = 0; i < bitnum; i++) printf("%d ", indx[i]);
  printf(")\n");

  for (i = 0; i < ipnum; i++) {
    printf("[%d]", i);
    printaddr(iptbl[i]);
    printf(" ==> %d\n", value[i]);
  }
  
  return 0;
}
