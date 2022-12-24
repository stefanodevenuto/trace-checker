
CFLAGS=-g -O0 -lm -lkshark

all: bin/checker

clean:
	$(RM) -rf bin/*

bin/checker:
	$(CC) src/checker.c -o bin/checker $(CFLAGS)
