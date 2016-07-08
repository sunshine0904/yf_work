CC:=gcc
CFLAGS:=-w -g
OBJS:=stage3

all:$(OBJS)

stage1:sha1.h HMACSHA1.c head.h stage3.c
	$(CC) $(CFLAGS) $^ -o $@

.PHONY:clean

clean:
	-rm $(OBJS) *.gch a.out output.txt

