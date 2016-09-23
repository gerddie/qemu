# this file is also included by tests/tcg/x86_64/Makefile

CROSS_CC?=gcc -m32
CROSS_CXX?=g++ -m32

ifneq ($(TCG_ARCH),x86_64)
tcg-tests = hello
endif

hello: LIBS=-nostdlib -static

test-i386: LIBS=-lm
test-i386: test-i386.o test-i386-code16.o test-i386-vm86.o

.PHONY: run-test-i386
run-test-i386: test-i386
	./test-i386 > test-i386.ref
	$(QEMU) test-i386 > test-i386.out
	@if diff -u test-i386.ref test-i386.out ; then echo "Auto Test OK"; fi

tests += run-test-i386
cleanfiles += test-i386

.PHONY: run-test-i386-fprem
run-test-i386-fprem: test-i386-fprem
	./test-i386-fprem > test-i386-fprem.ref
	$(QEMU) test-i386-fprem > test-i386-fprem.out
	@if diff -u test-i386-fprem.ref test-i386-fprem.out ; then echo "Auto Test OK"; fi

tests += run-test-i386-fprem
cleanfiles += test-i386-fprem
cleanfiles +=  *.ref *.out

# this test requires root privileges and run forever..
run-runcom: runcom
	-$(QEMU) ./runcom $(SRC_PATH)/tests/pi_10.com

cleanfiles += runcom

include ../tcg.mak
