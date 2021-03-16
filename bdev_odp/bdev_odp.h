/*
*  bdev_odp.h
*  
*  @Purpose : bdev_odp utility header file
*  
*  @Copyright :
*  
*  @Author : 
*/


#ifndef BDEV_ODP_H
#define BDEV_ODP_H

// Some internal stuff used.
#include "../../module/bdev/nvme/bdev_nvme.h" 
#include "../../module/bdev/nvme/common.h"

#include "spdk/stdinc.h"
#include "spdk/bdev.h"
#include "spdk/accel_engine.h"
#include "spdk/conf.h"
#include "spdk/env.h"
#include "spdk/thread.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/queue.h"
#include "spdk/env_dpdk.h"
#include "spdk/event.h"

#include "spdk/stdinc.h"

#include "spdk/nvme.h"
#include "spdk/vmd.h"
#include "spdk/nvme_zns.h"

#define VERSION "0.971"
#define MB 1048576
#define K4 4096
#define SHM_PKT_POOL_BUF_SIZE  1856
#define SHM_PKT_POOL_SIZE      (512*2048)
#define NVME_MAX_BDEVS_PER_RPC 128
#define MAX_PACKET_SIZE 1600
#define DEVICE_NAME                 "PBlaze5"         // TBD : This should come from commadline or be detected in auto mode
#define SPDK_DEVICE_PCIE_ADDR       "0001:01:00.0"    // TBD : This should come from commadline or be detected in auto mode
#define TEST_SPDK_NVME_BDEV_NAME    "PBlaze5n1"       //This value comes from SPDK internals. Added here for testing purposes
#define NUM_THREADS 4
#define NUM_INPUT_Q 4
#define SPDK_RING_ELEM_NUM          1024   // 4096

#define EE_HEADER_SIZE 11
#define FILE_NAME "dump.pcap"
#define BUFFER_SIZE 1048576
//#define BUFFER_SIZE 1024
#define THREAD_OFFSET 0x100000000	//4Gb of offset for every thread 
#define THREAD_LIMIT 0x100000000	//space for every thread to write
//#define THREAD_LIMIT 0x900		//space for every thread to write
#define READ_LIMIT 0x100000000		//space for every thread to read

//OPTIONS
//#define DUMP_PACKET
//#define DEBUG
#define HL_DEBUGS			//high level debugs - on writing buffers and counting callbacks

#ifdef DEBUG
 #define debug(x...) printf(x)
#else
 #define debug(x...)
#endif

typedef enum {MODE_READ, MODE_WRITE, MODE_RW} mode_e;

/* Used to pass messages between fio threads */
struct pls_msg {
	spdk_msg_fn	cb_fn;
	void		*cb_arg;
};

//each thread contains its own target
typedef struct pls_target_s
{
	struct spdk_bdev	*bd;
	struct spdk_bdev_desc	*desc;
	struct spdk_io_channel	*ch;
	TAILQ_ENTRY(pls_target_s) link;
} pls_target_t;

typedef struct pls_thread_s
{
	uint32_t core;  //CPU core thread is assigned to

	bool finished;
	int idx;
	bool read_complete;		//flag, false when read callback not finished, else - tru
        unsigned char *buf;
	uint64_t offset;		//just for stats
	atomic_ulong a_offset;		//atomic offset for id 0 thread
	pthread_t pthread_desc;
        struct spdk_thread *thread; /* spdk thread context */
        struct spdk_ring *ring; /* ring for passing messages to this thread */
	pls_target_t pls_target;
	TAILQ_HEAD(, pls_poller) pollers; /* List of registered pollers on this thread */

} pls_thread_t;


struct rpc_bdev_nvme_attach_controller {
	char *name;
	char *trtype;
	char *adrfam;
	char *traddr;
	char *trsvcid;
	char *priority;
	char *subnqn;
	char *hostnqn;
	char *hostaddr;
	char *hostsvcid;
	bool prchk_reftag;
	bool prchk_guard;
	struct spdk_nvme_ctrlr_opts opts;
};

struct rpc_bdev_nvme_attach_controller_ctx {
	struct rpc_bdev_nvme_attach_controller req;
	uint32_t count;
	const char *names[NVME_MAX_BDEVS_PER_RPC];
//	struct spdk_jsonrpc_request *request;
};

/* A polling function */
struct pls_poller 
{
	spdk_poller_fn		cb_fn;
	void			*cb_arg;
	uint64_t		period_microseconds;
	TAILQ_ENTRY(pls_poller)	link;
};


#endif /*BDEV_ODP_H*/
