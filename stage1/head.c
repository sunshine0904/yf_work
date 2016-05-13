#include <string.h>

#include "head.h"

#define DEBUG 0

#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif /* DEBUG */

int get_index(ip_t tbl[], int n, u32_t indx[], u32_t value[]) {
  int i, j, k, ret;
//#if DEBUG
  int s, t;
//#endif /* DEBUG */
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

int get_index_value(int i,int value[],int index[])
{
	return value[index[i]];
}
