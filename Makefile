.PHONY: all

CC=gcc
CFLAGS=-Wall
LDLIBS=-lssl -lcrypto

all: digest

digest: digest.c

clean:
	rm -f digest
