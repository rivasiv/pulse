SPDK_ROOT_DIR := $(abspath $(CURDIR)/..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk
include $(SPDK_ROOT_DIR)/mk/spdk.modules.mk
include $(SPDK_ROOT_DIR)/mk/spdk.app.mk

APP = bdev_pls

C_SRCS := bdev_pls.c

SPDK_LIB_LIST = event_bdev event_copy event_iscsi event_net event_scsi event_nvmf
SPDK_LIB_LIST += nvmf event log trace conf util bdev iscsi scsi copy rpc jsonrpc json
SPDK_LIB_LIST += app_rpc log_rpc bdev_rpc

LIBS += $(BLOCKDEV_MODULES_LINKER_ARGS) \
	$(COPY_MODULES_LINKER_ARGS) \
	$(NET_MODULES_LINKER_ARGS) \
	$(SPDK_LIB_LINKER_ARGS) $(ENV_LINKER_ARGS)
LIBS += -lcrypto

all : $(APP)
	@:

$(APP) : $(OBJS) $(SPDK_LIB_FILES) $(BLOCKDEV_MODULES_FILES) $(LINKER_MODULES) $(ENV_LIBS)
	$(LINK_C)

clean:
	$(CLEAN_C) $(APP)

install: $(APP)
	$(INSTALL_APP)

include $(SPDK_ROOT_DIR)/mk/spdk.deps.mk
