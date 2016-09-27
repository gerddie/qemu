include ../../config-host.mak
include $(SRC_PATH)/rules.mak

cleanfiles = *.out.bad *.notrun check.log check.time scratch/

# no default target
default:

clean:
	rm -rf $(cleanfiles)

$(SRC_PATH)/tests/qemu-iotests/.gitignore: $(MAKEFILE_LIST)
	$(call quiet-command, echo "$(cleanfiles)" | \
          xargs -n1 | sort > $@, " GEN $(@F)")

all gitignore: $(SRC_PATH)/tests/qemu-iotests/.gitignore
