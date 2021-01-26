SPDK_ROOT_DIR := $(abspath $(CURDIR)/../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk
include $(SPDK_ROOT_DIR)/mk/spdk.modules.mk
include $(SPDK_ROOT_DIR)/mk/spdk.app.mk

APP = bdev_odp_raid

C_SRCS := bdev_odp_raid.c

SPDK_LIB_LIST = event_bdev event_copy
SPDK_LIB_LIST += nvmf event log trace conf util bdev iscsi scsi copy rpc jsonrpc json thread log sock
SPDK_LIB_LIST += app_rpc log_rpc bdev_rpc vbdev_raid

LIBS += $(BLOCKDEV_MODULES_LINKER_ARGS) \
	$(COPY_MODULES_LINKER_ARGS) \
	$(NET_MODULES_LINKER_ARGS) \
	$(SPDK_LIB_LINKER_ARGS) $(ENV_LINKER_ARGS)
LIBS += -lcrypto -lodp-linux

all : $(APP)
	@:

$(APP) : $(OBJS) $(SPDK_LIB_FILES) $(BLOCKDEV_MODULES_FILES) $(LINKER_MODULES) $(ENV_LIBS)
	$(LINK_C)

clean:
	$(CLEAN_C) $(APP)

install: $(APP)
	$(INSTALL_APP)

include $(SPDK_ROOT_DIR)/mk/spdk.deps.mk
