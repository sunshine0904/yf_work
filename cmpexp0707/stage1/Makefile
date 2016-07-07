CC:=gcc
CFLAGS:=-w -g
OBJS:=stage1

all:$(OBJS)

stage1:sha1.h HMACSHA1.c stage1.c
	$(CC) $(CFLAGS) $^ -o $@

.PHONY:clean

clean:
	-rm $(OBJS) *.gch a.out output.txt

