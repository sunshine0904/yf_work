CC:=gcc
CFLAGS:=-w
OBJS:=stage2

all:$(OBJS)

stage2:head.h stage2.c
	$(CC) $(CFLAGS) $^ -o $@

.PHONY:clean

clean:
	-rm $(OBJS) *.gch mod10.pcap

