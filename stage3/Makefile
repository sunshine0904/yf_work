CC:=gcc 
CFLAGS:=-w  
OBJS:=stage3 origin

all:$(OBJS)

stage3:aes_lib.h aes_lib.c head.h struct_head.c struct_head.h stage3.c
	$(CC) $(CFLAGS) $^ -lm -lpthread -o $@
origin:aes_lib.h aes_lib.c head.h struct_head.c struct_head.h origin.c
	$(CC) $(CFLAGS) $^ -lm -lpthread -o $@

.PHONY:clean

clean:
	-rm $(OBJS) *.gch


