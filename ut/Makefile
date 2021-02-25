SPDK_ROOT_DIR := /root/pktCaptSol2/spdk
#SPDK_ROOT_DIR := $(abspath $(CURDIR)/../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk
include $(SPDK_ROOT_DIR)/mk/spdk.modules.mk



PKG_CONFIG_PATH = $(SPDK_ROOT_DIR)/build/lib/pkgconfig
SPDK_LIB := $(shell PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)" pkg-config --libs spdk_nvme)
SPDK_LIB_BDEV_NVME := $(shell PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)" pkg-config --libs spdk_bdev_nvme)
DPDK_LIB := $(shell PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)" pkg-config --libs spdk_env_dpdk)

PULSEDEBUG = -g -DDEBUG=1 

CFLAGS += $(PULSEDEBUG) -Wl,--no-as-needed 

APP = spdk_init_test

C_SRCS := spdk_init_test.c

SPDK_LIB_LIST += $(ALL_MODULES_LIST) event_bdev nvmf


SYS_LIBS += -lodp-dpdk -Wl,--no-as-needed $(DPDK_LIB) $(SPDK_LIB) $(SPDK_LIB_BDEV_NVME) -Wl,--as-needed

include $(SPDK_ROOT_DIR)/mk/spdk.app.mk


