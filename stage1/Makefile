CC:=gcc
CFLAGS:=-w -g
OBJS:=stage1

all:$(OBJS)

stage1:aes_lib.h aes_lib.c head.h head.c stage1.c
	$(CC) $(CFLAGS) $^ -o $@

.PHONY:clean

clean:
	-rm $(OBJS) *.gch output.txt

