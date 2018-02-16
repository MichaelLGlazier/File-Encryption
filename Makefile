CC=gcc
CFLAGS= -g -pedantic-errors -Wall

default: 	
	gcc -g -pedantic-errors -Wall -std=c11 -o fcrypt fcrypt.c -lssl -lcrypto	
.PHONY: clean

clean:
	rm -rf fcrypt fcrypt.o