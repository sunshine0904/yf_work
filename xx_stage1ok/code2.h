#ifndef CODE2_H_
#define CODE2_H_

#define MAX_IP_NUM        100
#define MAX_BIT_NUM       32

#define ip2uint(val1, val2, val3, val4) (\
  (val1 << 24) | (val2 << 16) | (val3 << 8) | (val4)) 
#define getbit(addr, n) ((addr & mask[n]) == mask[n])
#define lor(val1, val2) ((val1 << 1) | val2)
#define printaddr(addr) printf("%d.%d.%d.%d", \
  ((addr & 0xff000000) >> 24), ((addr & 0x00ff0000) >> 16), \
  ((addr & 0x0000ff00) >> 8),  (addr & 0x000000ff))

typedef unsigned int      u32_t;
typedef u32_t             ip_t;

ip_t mask[MAX_BIT_NUM] = {
  0x00000001, 0x00000002, 0x00000004, 0x00000008,
  0x00000010, 0x00000020, 0x00000040, 0x00000080,
  0x00000100, 0x00000200, 0x00000400, 0x00000800,
  0x00001000, 0x00002000, 0x00004000, 0x00008000,
  0x00010000, 0x00020000, 0x00040000, 0x00080000,
  0x00100000, 0x00200000, 0x00400000, 0x00800000,
  0x01000000, 0x02000000, 0x04000000, 0x08000000,
  0x10000000, 0x20000000, 0x40000000, 0x80000000
};

int func(ip_t tbl[], int n, u32_t indx[], u32_t value[]);
int not_same(u32_t value, u32_t tbl[], int n);

#endif /* CODE2_H_ */
