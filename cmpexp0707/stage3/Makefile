CC:=gcc
CFLAGS:=-w -g
OBJS:=stage3


stage3:sha1.h HMACSHA1.c head.h stage3.c
	$(CC) $(CFLAGS) $^ -o $@

.PHONY:clean

clean:
	-rm $(OBJS) *.gch a.out output.txt stage3.pcap

