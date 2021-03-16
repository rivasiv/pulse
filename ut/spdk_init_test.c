
#include <stdio.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>

#include <rte_errno.h>

#include <odp_api.h>

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
#define NVME_MAX_BDEVS_PER_RPC 32
#define MAX_PACKET_SIZE 1600
#define DEVICE_NAME "PBlaze5"
#define NUM_THREADS 4
#define NUM_INPUT_Q 4

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

typedef struct global_s
{
	mode_e mode;
	char *pci_nvme_addr;
} global_t;

static global_t global = 
{
	.mode = MODE_WRITE,
	.pci_nvme_addr = "0001:01:00.0",
};

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

/* A polling function */
struct pls_poller 
{
	spdk_poller_fn		cb_fn;
	void			*cb_arg;
	uint64_t		period_microseconds;
	TAILQ_ENTRY(pls_poller)	link;
};

const char *names[NVME_MAX_BDEVS_PER_RPC];
pls_thread_t pls_ctrl_thread;
pls_thread_t pls_read_thread;
pls_thread_t pls_thread[NUM_THREADS];

//odp stuff -----
odp_instance_t odp_instance;
odp_pool_param_t params;
odp_pool_t pool;
odp_pktio_param_t pktio_param;
odp_pktio_t pktio;
odp_pktin_queue_param_t pktin_param;
odp_queue_t inq[NUM_INPUT_Q] = {0};	//keep handles to queues here

void hexdump(void*, unsigned int );

struct pcap_file_header* pls_pcap_gl_header(void);
int pls_pcap_file_create(char*);
int pls_pcap_create(void*);

int init(void);
void* init_thread(void*);
void* init_read_thread(void *arg);
int init_spdk(void);
int init_odp(void);

int deinit_spdk(void);

void hexdump(void *addr, unsigned int size)
{
        unsigned int i;
        /* move with 1 byte step */
        unsigned char *p = (unsigned char*)addr;

        //printf("addr : %p \n", addr);

        if (!size)
        {
                printf("bad size %u\n",size);
                return;
        }

        for (i = 0; i < size; i++)
        {
                if (!(i % 16))    /* 16 bytes on line */
                {
                        if (i)
                                printf("\n");
                        printf("0x%lX | ", (long unsigned int)(p+i)); /* print addr at the line begin */
                }
                printf("%02X ", p[i]); /* space here */
        }

        printf("\n");
}

static void pls_bdev_init_done( int rc, void *cb_arg)
{
	printf("\nNotice! bdev init is done(%d).\n", rc);
	*(bool *)cb_arg = true;
}

//------------------------------------------------------------------------------
//PCAP functions
//------------------------------------------------------------------------------
typedef int bpf_int32;
typedef u_int bpf_u_int32;

struct pcap_file_header 
{
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;     /* gmt to local correction */
        bpf_u_int32 sigfigs;    /* accuracy of timestamps */
        bpf_u_int32 snaplen;    /* max length saved portion of each pkt */
        bpf_u_int32 linktype;   /* data link type (LINKTYPE_*) */
};

typedef struct pcap_pkthdr_s 
{
        bpf_u_int32 ts_sec;         /* timestamp seconds */
        bpf_u_int32 ts_usec;        /* timestamp microseconds */
        bpf_u_int32 incl_len;       /* number of octets of packet saved in file */
        bpf_u_int32 orig_len;       /* actual length of packet */
} pcap_pkthdr_t;

//create global file pcap header
struct pcap_file_header* pls_pcap_gl_header(void)
{
	static struct pcap_file_header hdr;

	memset(&hdr, 0x0, sizeof(hdr));
	hdr.magic = 0xa1b23c4d;		//nanosecond magic. common magic: 0xa1b2c3d4
	hdr.version_major = 2;
	hdr.version_minor = 4;
	hdr.thiszone = 0;
	hdr.sigfigs = 0;
	hdr.snaplen = 65535;
	hdr.linktype = 1;		//ethernet

	return &hdr;
}

//@name - filename, @buf - OUT ptr to buffer. returns file descriptor
int pls_pcap_file_create(char *name)
{
	int rv, fd;
	void *p;
	unsigned int off = 0;

	debug("%s() called \n", __func__);

	rv = creat(name, 666);
	if (rv < 0)
	{
		printf("error during creating file\n");
		return rv;
	}

	p = malloc(MB);
	if (!p)
	{
		printf("error during ram allocation\n");
		rv = -1; return rv;
	}

	memset(p, 0x0, MB);
	memcpy(p, pls_pcap_gl_header(), sizeof(struct pcap_file_header));
	off += sizeof(struct pcap_file_header);

	printf("pcap global file header dump:\n");
	hexdump(p, sizeof(struct pcap_file_header));

	//buf = p;

	//writing pcap global header to file
	fd = rv;
	rv = write(fd, p, sizeof(struct pcap_file_header));
	if (rv < 0)
	{
		printf("write to file failed!\n");
		return rv;
	}

	return fd;
}

//general function, takes buf, parses it, creates pcap file, etc.
//if no pcap file - creates it, if exists - adds to the current
int pls_pcap_create(void *bf)
{
	int i, j, rv = 0;
	static int fd = 0;
	unsigned char *p = (unsigned char*)bf;
	static bool firstrun = true;
	bool new_packet = false;
	bool new_len = false;
	unsigned short len = 0;
	uint64_t ts = 0, t = 0;
	pcap_pkthdr_t pkthdr;

	//debug("%s() called \n", __func__);

	if (firstrun)
	{
		rv = pls_pcap_file_create(FILE_NAME);
		if (rv <= 0)
		{
			printf("failed to create file %s\n", FILE_NAME);
			return rv;
		}
		fd = rv;
		firstrun = false;
	}
	
	//parsing packets
	for (i = 0; i < BUFFER_SIZE; i++)
	{
		if (p[i] == 0xEE)
		{
			new_packet = true;
			continue;
		}
		if (new_packet)
		{
			//getting timestamp
			ts = 0;
			for (j = 0; j < 8; j++)
			{
				t = (uint64_t)p[i+j];
				ts |= t << 8*(7-j);
				//printf("j: %d, ts: 0x%lx \n", j, ts);
			}
			i += 8;

			len = p[i] << 8;
			i++;
			len |= p[i];
			new_packet = false;
			new_len = true; 
			debug("new packet len: %d , ts: %lu \n", len, ts);
			continue;
		}
		if (new_len)
		{
			memset(&pkthdr, 0x0, sizeof(pcap_pkthdr_t));
			pkthdr.incl_len = pkthdr.orig_len = len;
			pkthdr.ts_sec = (bpf_u_int32)(ts / 1000000000);
			pkthdr.ts_usec = (bpf_u_int32)(ts % 1000000000);
			debug("len: %u, ts_sec: %u, ts_usec: %u \n", 
				pkthdr.orig_len, pkthdr.ts_sec, pkthdr.ts_usec);
			rv = write(fd, &pkthdr, sizeof(pcap_pkthdr_t));
			if (rv < 0)
			{
				//printf("write to file failed!\n");
				return rv;
			}
			//write whole packet here
			rv = write(fd, p+i, len);
			if (rv < 0)
			{
				//printf("write to file failed!\n");
				return rv;
			}
			new_len = false;
		}
	}

	return 0;	//in case of error - we return rv before, so always 0 here
}

//------------------------------------------------------------------------------
atomic_ulong bytes_wrote = 0;

//this callback called when write is completed
static void pls_bdev_write_done_cb(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	static unsigned int cnt = 0;
	pls_thread_t *t = (pls_thread_t*)cb_arg;

	//printf("bdev write is done\n");
	if (success)
	{
		debug("write completed successfully\n");
		//cnt++;
		__atomic_fetch_add(&cnt, 1, __ATOMIC_SEQ_CST);

#if 0
		bytes_wrote += BUFFER_SIZE;
		now = time(0);
	        if (now > old)
                {


		}
#endif

	}
	else
		printf("write failed\n");

#ifdef HL_DEBUGS
	if (cnt % 1000 == 0)
		printf("have %u successful write callabacks. thread #%d, offset: 0x%lx \n",
			 cnt, t->idx, t->offset);
#endif
	debug("before freeing ram in callback at addr: %p \n", t->buf); 
	spdk_dma_free(t->buf);
	debug("after freeing ram in callback at addr: %p \n", t->buf); 
	t->buf = NULL;

	//important to free bdev_io request, or it will lead to pool overflow (65K)
	spdk_bdev_free_io(bdev_io);
}

//this callback called when read is completed
static void pls_bdev_read_done_cb(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	static unsigned int cnt = 0;
	pls_thread_t *t = (pls_thread_t*)cb_arg;

	printf("bdev read is done\n");
	if (success)
	{
		t->read_complete = true;
		__atomic_fetch_add(&cnt, 1, __ATOMIC_SEQ_CST);
		//debug("read completed successfully\n");
	}
	else
		printf("read failed\n");

#ifdef HL_DEBUGS
	if (cnt % 1000 == 0)
		printf("have %u successful read callabacks. thread #%d, offset: 0x%lx \n",
			 cnt, t->idx, t->offset);
#endif
	spdk_bdev_free_io(bdev_io);
}

static size_t pls_poll_thread(pls_thread_t *thread)
{
	struct pls_msg *msg;
	struct pls_poller *p, *tmp;
	size_t count;

	printf("%s() called \n", __func__);

	/* Process new events */
	count = spdk_ring_dequeue(thread->ring, (void **)&msg, 1);
	if (count > 0) {
		printf("\n Called poller in pls_poll_thread \n");
		msg->cb_fn(msg->cb_arg);
		free(msg);
	}

	/* Call all pollers */
	TAILQ_FOREACH_SAFE(p, &thread->pollers, link, tmp) {
		printf("\n Called poller in pls_poll_thread \n");
		p->cb_fn(p->cb_arg);
	}

	printf("%s() exited \n", __func__);

	return count;
}

//This is pass message function for spdk_allocate_thread
//typedef void (*spdk_msg_fn)(void *ctx);
static void pls_send_msg(spdk_msg_fn fn, void *ctx, void *thread_ctx)
{
        pls_thread_t *thread = thread_ctx;
        struct pls_msg *msg;
        size_t count;

		printf("%s() called \n", __func__);

        msg = calloc(1, sizeof(*msg));
        assert(msg != NULL);

        msg->cb_fn = fn;
        msg->cb_arg = ctx;

        count = spdk_ring_enqueue(thread->ring, (void **)&msg, 1, NULL);
        if (count != 1) {
                SPDK_ERRLOG("Unable to send message to thread %p. rc: %lu\n", thread, count);
        }
}
#if 0
static struct spdk_poller* pls_start_poller(void *thread_ctx, spdk_poller_fn fn,
                      			    void *arg, uint64_t period_microseconds)
{
	pls_thread_t *thread = thread_ctx;
	struct pls_poller *poller;

	printf("%s() called \n", __func__);

	poller = calloc(1, sizeof(*poller));
	if (!poller) 
	{
	    SPDK_ERRLOG("Unable to allocate poller\n");
		return NULL;
	}

	poller->cb_fn = fn;
	poller->cb_arg = arg;
	poller->period_microseconds = period_microseconds;

	TAILQ_INSERT_TAIL(&thread->pollers, poller, link);

    return (struct spdk_poller *)poller;
}

static void pls_stop_poller(struct spdk_poller *poller, void *thread_ctx)
{
	struct pls_poller *lpoller;
	pls_thread_t *thread = thread_ctx;

	printf("%s() called \n", __func__);

	lpoller = (struct pls_poller *)poller;

	TAILQ_REMOVE(&thread->pollers, lpoller, link);

	free(lpoller);
}
#endif /*0*/

/* Register pollers per thresd.
 *
 *  @{Params} :
 *     @{in} void *thread_ctx      : Currently pass the thread context,
 *  						    	 it may be catched from spdk, but receiving as parameter
 *  								 saves extra function calls.
 * 
 *   @{Return} : None
 * 
 * */
static void pulse_pollers_register(void *thread_ctx)
{

	pls_thread_t *thread = thread_ctx;
	struct pls_poller *poller;

	printf("%s() called \n", __func__);

	poller = calloc(1, sizeof(*poller));
	if (!poller) 
	{
	    SPDK_ERRLOG("Unable to allocate poller\n");
		return NULL;
	}

    //If I am correct this is not needed at all.

//	poller->cb_fn = pls_send_msg;
//	poller->cb_arg = arg;
//	poller->period_microseconds = period_microseconds;

//    poller = spdk_poller_register(pls_send_msg, NULL, 0);

	TAILQ_INSERT_TAIL(&thread->pollers, poller, link);

  /*Our app isn't event driven, as SPDK suppose. So do not return callback to continue.*/
}

/* Reports status of created bde over NVME device. 
 *
 *  @{Params} :
 *     @{in} void *cb_ctx      : Context structure with info we wand passthru the creation process
 *     @{in} size_t bdev_count : Count of bdev devices
 *     @{in} int rc            : Return code propagated. Errno codes with '-' used.
 * 
 *   @{Return} : None
 * 
 * */

static void
tracepulspdk_bdev_nvme_attach_controller_done (void *cb_ctx, size_t bdev_count, int rc)
{
	size_t i;

    printf("\n\ntracepulspdk_bdev_nvme_attach_controller_done %d\n\n", bdev_count);

	if (cb_ctx != NULL) {
		printf("Error! %s: SPDK bdev wrong context.\n", __FUNCTION__);
		return;
	}

	if (rc < 0) {
		printf("Error! %s: SPDK bdev returns error %d(%s).\n", __FUNCTION__, -errno, strerror(-errno));
		return;
	}

	for (i = 0; i < bdev_count; i++) {
		printf("Notice! %s: SPDK bdev %s added!\n", __FUNCTION__, names[i]);
	}

    return;
}

/*
 *  SPDK thread functions 
 */
static int
pls_reactor_thread_op(struct spdk_thread *thread, enum spdk_thread_op op)
{

    debug("Debug! Entered %s.", __FUNCTION__ );

	switch (op) {
		case SPDK_THREAD_OP_NEW:
			printf("\nReachecd scheduler\n");

			/*TBD : Action on thread create. For now I am not sure if we need to add something here */

			return 0; 
		case SPDK_THREAD_OP_RESCHED:
			printf("\nShouldn't be here");
			return -1;
		default:
			return -ENOTSUP;
	}

	return 0;
}

static bool
pls_reactor_thread_op_supported(enum spdk_thread_op op)
{
    debug("Debug! Entered %s.\n", __FUNCTION__ );

	switch (op) {
		case SPDK_THREAD_OP_NEW:
			return true;
		case SPDK_THREAD_OP_RESCHED:
			return false;            // for now I do not see a need to reshedule something. 
		default:
			return false;
	}

	return false;
}

/*
 *   NVME probe callback.  
 *  
 */
static bool pulse_bdev_nvme_probe_cb(void *cb_ctx, const struct spdk_nvme_transport_id *trid, struct spdk_nvme_ctrlr_opts *opts)
{
	printf("\nSPDK_INIT: Probe to NVMe Controller at %s \n", trid->traddr);

	return true;
}

/*
 *  NVME attach callback  
 *  
 */
static void pulse_bdev_nvme_attach_cb(void *cb_ctx, const struct spdk_nvme_transport_id *trid, struct spdk_nvme_ctrlr *ctrlr, const struct spdk_nvme_ctrlr_opts *opts)
{
	struct trid_entry       *trid_entry = cb_ctx;
	struct spdk_pci_addr    pci_addr;
	struct spdk_pci_device  *pci_dev;
	struct spdk_pci_id      pci_id;

	printf("\nSPDK_INIT: Attach to NVMe Controller at %s \n", trid->traddr);

	if (trid->trtype != SPDK_NVME_TRANSPORT_PCIE) {
		printf("Attached to NVMe over Fabrics controller at %s:%s: %s\n",
		       trid->traddr, trid->trsvcid,
		       trid->subnqn);
	} else {
		if (spdk_pci_addr_parse(&pci_addr, trid->traddr)) {
			return;
		}

		pci_dev = spdk_nvme_ctrlr_get_pci_device(ctrlr);
		if (!pci_dev) {
			return;
		}

		pci_id = spdk_pci_device_get_id(pci_dev);

		printf("Attached to NVMe Controller at %s [%04x:%04x]\n",
		       trid->traddr,
		       pci_id.vendor_id, pci_id.device_id);
	}

//	register_ctrlr(ctrlr, trid_entry);
}

int main(int argc, char *argv[])
{
	int rc;
	struct spdk_env_opts opts;

	/*
	 * SPDK relies on an abstraction around the local environment
	 * named env that handles memory allocation and PCI device operations.
	 * This library must be initialized first.
	 *
	 */
	spdk_env_opts_init(&opts);
	opts.name = "spdk_test";
	opts.shm_id = 0;
	if (spdk_env_init(&opts) < 0) {
		printf("Unable to initialize SPDK env\n");
		return 1;
	}

	printf("Initializing NVMe Controllers\n");

#if 0  //Auto search 
/*	if (g_vmd && spdk_vmd_init()) {
		fprintf(stderr, "Failed to initialize VMD."
			" Some NVMe devices can be unavailable.\n");
	}*/

	/*
	 * Start the SPDK NVMe enumeration process.  probe_cb will be called
	 *  for each NVMe controller found, giving our application a choice on
	 *  whether to attach to each controller.  attach_cb will then be
	 *  called for each controller after the SPDK NVMe driver has completed
	 *  initializing the controller we chose to attach.
	 */
	rc = spdk_nvme_probe(NULL, NULL, pulse_bdev_nvme_probe_cb, pulse_bdev_nvme_attach_cb, NULL);
	if (rc != 0) {
		printf("spdk_nvme_probe() failed\n");
		return 1;
	}
#endif
 
#if 1 // Connect to exact device 

	struct spdk_nvme_ctrlr_opts bdev_opts;
	struct spdk_nvme_transport_id trid = {};
	size_t count = NVME_MAX_BDEVS_PER_RPC;
	struct spdk_nvme_host_id hostid = {};
	uint32_t prchk_flags = 0;	


    trid.trtype = SPDK_NVME_TRANSPORT_PCIE;
	trid.adrfam = 0;
	memcpy(trid.traddr, global.pci_nvme_addr, strlen(global.pci_nvme_addr));
	snprintf(&trid.trstring[0], SPDK_NVMF_TRSTRING_MAX_LEN, "%s", SPDK_NVME_TRANSPORT_NAME_PCIE);

	    // Check we are able to connect to device. 
	if (spdk_nvme_probe(&trid, &trid, pulse_bdev_nvme_probe_cb, pulse_bdev_nvme_attach_cb, NULL) != 0) {
		printf("SPDK_INIT: spdk_nvme_probe() failed for transport address '%s'\n",
			trid.traddr);
		return -1;
	}
#endif 

  return 0;
}
