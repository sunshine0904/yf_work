CC:=gcc 
CFLAGS:=-w -g
OBJS:=stage3


stage3:aes_lib.h aes_lib.c head.h stage3.c
	$(CC)  $(CFLAGS) $^ -lpthread -o $@

.PHONY:clean

clean:
	-rm $(OBJS) *.gch a.out output.txt stage3.pcap stage3_cmp_cost.log

