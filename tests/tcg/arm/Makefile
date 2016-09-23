CROSS = arm-unknown-linux-gnueabi

tcg-tests += hello
hello: LIBS=-nostdlib -static

tcg-tests += test-arm-iwmmxt
test-arm-iwmmxt.o: CFLAGS=-march=iwmmxt -mabi=aapcs

include ../tcg.mak
