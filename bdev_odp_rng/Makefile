SPDK_ROOT_DIR := /root/pktCaptSol/spdk
#SPDK_ROOT_DIR := $(abspath $(CURDIR)/../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk
include $(SPDK_ROOT_DIR)/mk/spdk.modules.mk


PULSEDEBUG = -g -DDEBUG=1 

COMMON_CFLAGS += $(PULSEDEBUG) -Wl,--no-as-needed

APP = bdev_odp_rng

C_SRCS := bdev_odp_rng.c

SPDK_LIB_LIST = $(ALL_MODULES_LIST)
SPDK_LIB_LIST += event_bdev event_accel event_nvmf event_net event_vmd
SPDK_LIB_LIST += nvme bdev_nvme nvmf event log trace conf thread util bdev accel rpc jsonrpc json net sock
SPDK_LIB_LIST += app_rpc log_rpc bdev_rpc notify

SYS_LIBS += -lcrypto -lodp-linux


include $(SPDK_ROOT_DIR)/mk/spdk.deps.mk
include $(SPDK_ROOT_DIR)/mk/spdk.app.mk
