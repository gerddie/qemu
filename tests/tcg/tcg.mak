# this file is included by architecture subdir Makefile
# and contains generic rules and tests

BUILD_DIR?=../../..
include $(BUILD_DIR)/config-host.mak
include $(SRC_PATH)/rules.mak

TCG_ARCH=$(notdir $(CURDIR))
QEMU?=$(BUILD_DIR)/$(TCG_ARCH)-linux-user/qemu-$(TCG_ARCH)
CROSS?=$(TCG_ARCH)-linux-gnu
CROSS_CC?=$(CROSS)-cc
CROSS_CCAS?=$(CROSS_CC)

LD_PREFIX ?= $(shell $(CROSS_CC) --print-sysroot)
ifneq ($(LD_PREFIX),)
QEMU_FLAGS+=-L $(LD_PREFIX)
endif

CC=$(CROSS_CC)
CCAS=$(CROSS_CCAS)
LDFLAGS=$(CROSS_LDFLAGS)
CFLAGS=$(CROSS_CFLAGS)
LIBS=$(CROSS_LIBS)
QEMU_CFLAGS=
CXX=

$(call set-vpath, $(SRC_PATH)/tests/tcg)
$(call set-vpath, $(SRC_PATH)/tests/tcg/$(TCG_ARCH))

qemu = $(call quiet-command,MALLOC_PERTURB_=$${MALLOC_PERTURB_:-$$((RANDOM % 255 + 1))} \
	$(QEMU) $(QEMU_FLAGS) $1 $(if $(V),,>/dev/null), "TCG-$(TCG_ARCH) $2")

tcg-tests += linux-test
tcg-tests += testthread
tcg-tests += sha1
cleanfiles += $(tcg-tests)

tests += $(patsubst %, test-tcg-%, $(tcg-tests))

.PHONY: $(patsubst %, test-tcg-%, $(tcg-tests))
$(patsubst %, test-tcg-%, $(tcg-tests)): test-tcg-%: %
	$(call qemu,./$*,$*)

.PHONY: test-mmap
test-mmap: mmap
	$(call qemu,mmap,mmap)
	$(call qemu,-p 8192 mmap 8192,mmap 8192)
	$(call qemu,-p 16384 mmap 16384,mmap 16384)
	$(call qemu,-p 32768 mmap 32768,mmap 32768)

tests += test-mmap
cleanfiles += mmap

testthread: LIBS=-lpthread

.PHONY: test
test:

ifeq ($(strip $(call find-in-path,$(CC))),)
$(warning $(CC) not available, skipping TCG tests (you may set CROSS))
else
ifeq ($(strip $(call find-in-path,$(QEMU))),)
$(warning $(QEMU) not available, skipping TCG tests)
else
test: $(tests)
endif
endif

cleanfiles += *.o
cleanfiles += .gitignore

clean:
	rm -f $(cleanfiles)

ifneq ($(filter-out $(UNCHECKED_GOALS),$(MAKECMDGOALS)),$(if $(MAKECMDGOALS),,fail))
$(SRC_PATH)/tests/tcg/$(TCG_ARCH)/.gitignore:
	$(call quiet-command, echo "$(cleanfiles)" | xargs -n1 | sort > $@, \
	  " GEN $(@F)")
Makefile: $(SRC_PATH)/tests/tcg/$(TCG_ARCH)/.gitignore
endif

-include $(wildcard *.d)
