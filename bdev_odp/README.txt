run
-----
ODP_HW_TIMESTAMPS=1 SPDK_NOINIT=1 ./bdev_odp
ODP_HW_TIMESTAMPS=1 SPDK_NOINIT=1 ./bdev_odp [rwb]	- read, write, both (write is default)
ODP_HW_TIMESTAMPS=1 SPDK_NOINIT=1 ./bdev_odp b
time SPDK_NOINIT=1 ./bdev_odp_raid b			 - raid

run raid app
-----
SPDK_NOINIT=1 ./bdev_odp_raid

dump
-----
tcpdump --number --time-stamp-precision=nano -r dump.pcap
time tcpdump --number --time-stamp-precision=nano -r dumprbd.pcap > 1 

free pages
-----
hugefree.sh

use 4.9.X gcc
-----
PATH=/opt/rh/devtoolset-3/root/usr/bin:$PATH

coredump
-----
ulimit -c unlimited
sysctl -w kernel.core_pattern=core_%p_%t

setup spdk
-----
[root@paul spdkp]# sudo ./scripts/setup.sh
0000:04:00.0 (144d a804): nvme -> uio_pci_generic
0000:05:00.0 (144d a804): nvme -> uio_pci_generic
Active mountpoints on /dev/nvme2n1, so not binding PCI dev 0000:06:00.0


sequence to run raid app:
-----------
0. install and build ofed, dpdk, odp, spdk.

PATH=/opt/rh/devtoolset-3/root/usr/bin:$PATH
cd /root/spdkp
./scripts/setup.sh
cd repu1sion/bdev_odp
make -f Makefile_raid
SPDK_NOINIT=1 ./bdev_odp_raid b


count packets in pcap file
----------
./pcapframescnt dump.pcap


rbd
----------
rbd device list
SPDK_NOINIT=1 ./bdev_odp_rbd b
time ODP_PKTIO_DPDK_PARAMS="--socket-mem 16384" SPDK_NOINIT=1 ./bdev_odp_rbd w

