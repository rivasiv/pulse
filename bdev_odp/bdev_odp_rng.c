//we have to call spdk_allocate_thread() for every thread and we should
//continue to do IO from this thread

#include <stdio.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>

#include <odp_api.h>

#include "../lib/bdev/nvme/bdev_nvme.h"

#include "spdk/stdinc.h"
#include "spdk/bdev.h"
#include "spdk/copy_engine.h"
#include "spdk/conf.h"
#include "spdk/env.h"
#include "spdk/io_channel.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/queue.h"

#define VERSION "0.98"
#define MB 1048576
#define K4 4096
#define SHM_PKT_POOL_BUF_SIZE  1856
#define SHM_PKT_POOL_SIZE      (512*2048)
#define NVME_MAX_BDEVS_PER_RPC 32
#define MAX_PACKET_SIZE 1600
#define DEVICE_NAME "s4msung"
#define DEVICE_NAME_NQN "s4msungnqn"
#define NUM_THREADS 4
#define NUM_INPUT_Q 4

#define EE_HEADER_SIZE 11
#define FILE_NAME "dump.pcap"
#define BUFFER_SIZE 1048576
//#define BUFFER_SIZE 1024
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
	uint32_t block_size;
	uint64_t num_blocks;
	uint64_t max_offset; 
	atomic_ulong overwrap_cnt;
	atomic_ulong offset;		//global atomic offset for whole device
	atomic_ulong wrote_offset;	//global atomic offset already guaranteed wrote
} global_t;

static global_t global = 
{
	.mode = MODE_WRITE,
	.pci_nvme_addr = "0000:02:00.0",
	.block_size = 0,
	.num_blocks = 0,
	.max_offset = 0,
	.overwrap_cnt = 0,
	.offset = 0,
	.wrote_offset = 0,
};

/* Used to pass messages between fio threads */
struct pls_msg {
	spdk_thread_fn	cb_fn;
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
	bool finished;
	int idx;
	bool read_complete;		//flag, false when read callback not finished, else - tru
        unsigned char *buf;
	uint64_t offset;		//just for stats
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

static void pls_bdev_init_done(void *cb_arg, int rc)
{
	printf("bdev init is done\n");
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
		if (global.wrote_offset < t->offset)
			global.wrote_offset = t->offset;
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

	//printf("bdev read is done\n");
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

	//printf("%s() called \n", __func__);

	/* Process new events */
	count = spdk_ring_dequeue(thread->ring, (void **)&msg, 1);
	if (count > 0) {
		msg->cb_fn(msg->cb_arg);
		free(msg);
	}

	/* Call all pollers */
	TAILQ_FOREACH_SAFE(p, &thread->pollers, link, tmp) {
		p->cb_fn(p->cb_arg);
	}

	//printf("%s() exited \n", __func__);

	return count;
}

//This is pass message function for spdk_allocate_thread
//typedef void (*spdk_thread_fn)(void *ctx);
static void pls_send_msg(spdk_thread_fn fn, void *ctx, void *thread_ctx)
{
        pls_thread_t *thread = thread_ctx;
        struct pls_msg *msg;
        size_t count;

	printf("%s() called \n", __func__);

        msg = calloc(1, sizeof(*msg));
        assert(msg != NULL);

        msg->cb_fn = fn;
        msg->cb_arg = ctx;

        count = spdk_ring_enqueue(thread->ring, (void **)&msg, 1);
        if (count != 1) {
                SPDK_ERRLOG("Unable to send message to thread %p. rc: %lu\n", thread, count);
        }
}

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

int init_spdk(void)
{
	int rv = 0;
	//struct spdk_conf *config;
	struct spdk_env_opts opts;
	bool done = false;
	size_t cnt;

	//this identifies an unique endpoint on an NVMe fabric
	struct spdk_nvme_transport_id trid = {};
	size_t count = NVME_MAX_BDEVS_PER_RPC;
	int i;

	printf("%s() called \n", __func__);

	/* Parse the SPDK configuration file */

	//just allocate mem via calloc
	//
#if 0
	config = spdk_conf_allocate();
	if (!config) {
		SPDK_ERRLOG("Unable to allocate configuration file\n");
		return -1;
	}

	//read user file to init spdk_conf struct
	rv = spdk_conf_read(config, "bdev_pls.conf");
	if (rv != 0) {
		SPDK_ERRLOG("Invalid configuration file format\n");
		spdk_conf_free(config);
		return -1;
	}
	if (spdk_conf_first_section(config) == NULL) {
		SPDK_ERRLOG("Invalid configuration file format\n");
		spdk_conf_free(config);
		return -1;
	}
	spdk_conf_set_as_default(config);
#endif

	/* Initialize the environment library */
	spdk_env_opts_init(&opts);
	opts.name = "bdev_pls";

	if (spdk_env_init(&opts) < 0) {
		SPDK_ERRLOG("Unable to initialize SPDK env\n");
		//spdk_conf_free(config);
		return -1;
	}
	spdk_unaffinitize_thread();

	//ring init (calls rte_ring_create() from DPDK inside)
	pls_ctrl_thread.ring = spdk_ring_create(SPDK_RING_TYPE_MP_SC, 4096, SPDK_ENV_SOCKET_ID_ANY);
	if (!pls_ctrl_thread.ring) 
	{
		SPDK_ERRLOG("failed to allocate ring\n");
		return -1;
	}

	// Initializes the calling(current) thread for I/O channel allocation
	/* typedef void (*spdk_thread_pass_msg)(spdk_thread_fn fn, void *ctx,
				     void *thread_ctx); */
	
	pls_ctrl_thread.thread = spdk_allocate_thread(pls_send_msg, pls_start_poller,
                                 pls_stop_poller, &pls_ctrl_thread, "pls_ctrl_thread");

        if (!pls_ctrl_thread.thread) 
	{
                spdk_ring_free(pls_ctrl_thread.ring);
                SPDK_ERRLOG("failed to allocate thread\n");
                return -1;
        }

	TAILQ_INIT(&pls_ctrl_thread.pollers);

	/* Initialize the copy engine */
	spdk_copy_engine_initialize();

	/* Initialize the bdev layer */
	spdk_bdev_initialize(pls_bdev_init_done, &done);

	/* First, poll until initialization is done. */
	do {
		pls_poll_thread(&pls_ctrl_thread);
	} while (!done);

	/*
	 * Continue polling until there are no more events.
	 * This handles any final events posted by pollers.
	 */
	do {
		cnt = pls_poll_thread(&pls_ctrl_thread);
	} while (cnt > 0);


	//create device
	/*
	spdk_bdev_nvme_create(struct spdk_nvme_transport_id *trid,
		      const char *base_name,
		      const char **names, size_t *count)
	*/
	//fill up trid.
	trid.trtype = SPDK_NVME_TRANSPORT_PCIE;
	trid.adrfam = 0;
	memcpy(trid.traddr, global.pci_nvme_addr, strlen(global.pci_nvme_addr));
	
	printf("creating bdev device...\n");
	//in names returns names of created devices, in count returns number of devices
	//5th param hostnqn - host NVMe Qualified Name. used only for nvmeof.
	//unused for local pcie connected devices
	rv = spdk_bdev_nvme_create(&trid, DEVICE_NAME, names, &count, DEVICE_NAME_NQN);
	if (rv)
	{
		printf("error: can't create bdev device!\n");
		return -1;
	}
	for (i = 0; i < (int)count; i++) 
	{
		printf("#%d: device %s created \n", i, names[i]);
	}

	return rv;
}

int init_odp(void)
{
	int rv = 0;
	char devname[] = "0";	//XXX - make it parameter or so

	rv = odp_init_global(&odp_instance, NULL, NULL);
	if (rv) exit(1);
	rv = odp_init_local(odp_instance, ODP_THREAD_CONTROL);
	if (rv) exit(1);
	
	odp_pool_param_init(&params);
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_SIZE/SHM_PKT_POOL_BUF_SIZE;
	params.type        = ODP_POOL_PACKET;
	pool = odp_pool_create("packet_pool", &params);
	if (pool == ODP_POOL_INVALID) exit(1);

	odp_pktio_param_init(&pktio_param);

	pktio_param.in_mode = ODP_PKTIN_MODE_QUEUE;
	printf("setting queue mode\n");
	pktio = odp_pktio_open(devname, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) exit(1);

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.op_mode     = ODP_PKTIO_OP_MT;
	pktin_param.hash_enable = 1;
	pktin_param.num_queues  = NUM_INPUT_Q;

	odp_pktin_queue_config(pktio, &pktin_param);
	odp_pktout_queue_config(pktio, NULL);

	return rv;
}

void* init_read_thread(void *arg)
{
	int rv = 0;
	uint64_t nbytes = BUFFER_SIZE;
	pls_thread_t *t = &pls_read_thread;
	uint64_t offset;
	static uint64_t readbytes = 0;
	void *bf;

	offset = 0;

	t->ring = spdk_ring_create(SPDK_RING_TYPE_MP_SC, 4096, SPDK_ENV_SOCKET_ID_ANY);
	if (!t->ring) 
	{
		printf("failed to allocate ring\n");
		rv = -1; return NULL;
	}

	// Initializes the calling(current) thread for I/O channel allocation
	/* typedef void (*spdk_thread_pass_msg)(spdk_thread_fn fn, void *ctx,
				     void *thread_ctx); */
	
	t->thread = spdk_allocate_thread(pls_send_msg, pls_start_poller,
                                 pls_stop_poller, (void*)t, "pls_reader_thread");

        if (!t->thread) 
	{
                spdk_ring_free(t->ring);
                SPDK_ERRLOG("failed to allocate thread\n");
                return NULL;
        }

	TAILQ_INIT(&t->pollers);

	t->pls_target.bd = spdk_bdev_get_by_name(names[0]); //XXX - we always try to open device with idx 0
	if (!t->pls_target.bd)
	{
		printf("failed to get device\n");
		rv = 1; return NULL;
	}
	else
		printf("got device with name %s\n", names[0]);

	//returns a descriptor
	rv = spdk_bdev_open(t->pls_target.bd, 1, NULL, NULL, &t->pls_target.desc);
	if (rv)
	{
		printf("failed to open device\n");
		return NULL;
	}

	printf("open io channel\n");
	t->pls_target.ch = spdk_bdev_get_io_channel(t->pls_target.desc);
	if (!t->pls_target.ch) 
	{
		printf("Unable to get I/O channel for bdev.\n");
		spdk_bdev_close(t->pls_target.desc);
		rv = -1; return NULL;
	}

	sleep(3);	//need to wait till we write some data
	printf("read thread started\n");

	while(1)
	{
		bf = spdk_dma_zmalloc(nbytes, 0, NULL);
		if (!bf)
		{
			printf("failed to allocate RAM for reading\n");
			return NULL;
		}
		t->read_complete = false;

		//wait here till threads do some writing
		if (global.mode == MODE_RW)
		{
			if (global.overwrap_cnt == 0)
			{
				while (offset + BUFFER_SIZE >= global.wrote_offset)
				{
					printf("read wait. read_offset: 0x%lx , wr0te_offset: 0x%lx \n",
						offset, global.wrote_offset);
					usleep(100000);		
				}
			}

			printf("read now. read_offset: 0x%lx , wr0te_offset: 0x%lx \n",
				offset, global.wrote_offset);
		}

		rv = spdk_bdev_read(t->pls_target.desc, t->pls_target.ch,
			bf, offset, nbytes, pls_bdev_read_done_cb, t);
		//printf("after spdk read\n");
		if (rv)
			printf("spdk_bdev_read failed\n");
		else
		{
			offset += nbytes;
			readbytes += nbytes;
			//printf("spdk_bdev_read NO errors\n");
		}
		//need to wait for bdev read completion first
		while(t->read_complete == false)
		{
			usleep(10);
		}

		//parsing packets here and creating pcap
		//in bf pointer we have buf with data read
		//writing to .pcap file is also here
		int r = pls_pcap_create(bf);
		if (r)
		{
			printf("error creating pcap\n");
		}

		//print dump
		//hexdump(bf, 2048);

		spdk_dma_free(bf);
	}

	return NULL;
}

void* init_thread(void *arg)
{
	int rv = 0;
	uint64_t nbytes = BUFFER_SIZE;
	pls_thread_t *t = (pls_thread_t*)arg;
	uint64_t offset;
	uint64_t position = 0;
	int pkt_len;
	unsigned short len;
	//void *bf;
	//odp
	odp_event_t ev;
	odp_packet_t pkt;
	odp_time_t time;

	//printf("%s() called from thread #%d. offset: 0x%lx\n", __func__, t->idx, offset);

	t->ring = spdk_ring_create(SPDK_RING_TYPE_MP_SC, 4096, SPDK_ENV_SOCKET_ID_ANY);
	if (!t->ring) 
	{
		printf("failed to allocate ring\n");
		rv = -1; return NULL;
	}

	// Initializes the calling(current) thread for I/O channel allocation
	/* typedef void (*spdk_thread_pass_msg)(spdk_thread_fn fn, void *ctx,
				     void *thread_ctx); */
	
	t->thread = spdk_allocate_thread(pls_send_msg, pls_start_poller,
                                 pls_stop_poller, (void*)t, "pls_writer_thread");

        if (!t->thread) 
	{
                spdk_ring_free(t->ring);
                SPDK_ERRLOG("failed to allocate thread\n");
                return NULL;
        }

	TAILQ_INIT(&t->pollers);

	t->pls_target.bd = spdk_bdev_get_by_name(names[0]); //XXX - we always try to open device with idx 0
	if (!t->pls_target.bd)
	{
		printf("failed to get device\n");
		rv = 1; return NULL;
	}
	else
		printf("got device with name %s\n", names[0]);

	//returns a descriptor
	rv = spdk_bdev_open(t->pls_target.bd, 1, NULL, NULL, &t->pls_target.desc);
	if (rv)
	{
		printf("failed to open device\n");
		return NULL;
	}

	//get device size
	if (t->idx == 0)
	{
		global.block_size = spdk_bdev_get_block_size(t->pls_target.bd);
		global.num_blocks = spdk_bdev_get_num_blocks(t->pls_target.bd);
		printf("device block size is: %u bytes, num blocks: %lu\n", 
			global.block_size, global.num_blocks);
		global.max_offset = global.block_size * global.num_blocks - 1;
		printf("max offset(bytes): 0x%lx\n", global.max_offset);
	}

	printf("open io channel\n");
	t->pls_target.ch = spdk_bdev_get_io_channel(t->pls_target.desc);
	if (!t->pls_target.ch) 
	{
		printf("Unable to get I/O channel for bdev.\n");
		spdk_bdev_close(t->pls_target.desc);
		rv = -1; return NULL;
	}

	printf("spdk thread init done.\n");

	//odp thread init
	rv = odp_init_local(odp_instance, ODP_THREAD_WORKER);

#if 0
	if (global.mode == MODE_READ)
	{
		if (t->idx == 0)
			goto read;
		else
			return NULL;
	}
#endif

	while(1)
	{
		//1. if no buffer - allocate it
		if (!t->buf)
		{
			t->buf = spdk_dma_zmalloc(nbytes, 0x100000, NULL); //last param - ptr to phys addr(OUT)
			if (!t->buf) 
			{
				printf("ERROR: write buffer allocation failed\n");
				return NULL;
			}
			debug("allocated spdk dma buffer with addr: %p\n", t->buf);
		}

		//2. get packet from queue
		ev = odp_queue_deq(inq[t->idx]);
		//debug("got event\n");
		pkt = odp_packet_from_event(ev);
		//debug("got packet from event\n");
		if (!odp_packet_is_valid(pkt))
			continue;
		pkt_len = (int)odp_packet_len(pkt);
		//getting timestamp
		rv = odp_packet_has_ts(pkt);
#if 0
		if (rv)
			printf("packet HAS a timestamp\n");
		else
			printf("packet has NO timestamp\n");
#endif

		//converting HW timestamp to system time
		if (rv)
		{
			time = odp_packet_ts(pkt);
			debug("odp packet timestamp is %lu \n", time.nsec);
		}
		else
			time.nsec = 0;

#ifdef DUMP_PACKET
		debug("got packet with len: %d\n", pkt_len);
		hexdump(odp_packet_l2_ptr(pkt, NULL), pkt_len);
#endif
		if (pkt_len > MAX_PACKET_SIZE)
		{
			printf("dropping big packet with size: %d \n", pkt_len);
			continue;
		}

		//in position we count num of bytes copied into buffer. 
		if (pkt_len)
		{
			if (position + pkt_len + EE_HEADER_SIZE < nbytes)
			{
				//debug("copying packet\n");
				//creating raw format header. 0xEE - magic byte (1byte)
				t->buf[position++] = 0xEE;
				//timestamp in uint64_t saved as big endian (8bytes)
				t->buf[position++] = time.nsec >> 56 & 0xFF;
				t->buf[position++] = time.nsec >> 48 & 0xFF;
				t->buf[position++] = time.nsec >> 40 & 0xFF;
				t->buf[position++] = time.nsec >> 32 & 0xFF;
				t->buf[position++] = time.nsec >> 24 & 0xFF;
				t->buf[position++] = time.nsec >> 16 & 0xFF;
				t->buf[position++] = time.nsec >> 8 & 0xFF;
				t->buf[position++] = time.nsec & 0xFF;
				
				//packet len (2bytes)
				len = (unsigned short)pkt_len;
				t->buf[position++] = len >> 8;
				t->buf[position++] = len & 0x00FF;
				//copying odp packet 
				memcpy(t->buf+position, odp_packet_l2_ptr(pkt, NULL), pkt_len);
#ifdef DUMP_PACKET
				hexdump(t->buf+position-EE_HEADER_SIZE , pkt_len+EE_HEADER_SIZE);
#endif
				odp_schedule_release_atomic();
				position += pkt_len;
			}
			else
			{
				//get global atomic offset value, increase it before writing.
				//t->offset used  in read/write callbacks
				t->offset = offset = global.offset;
				global.offset += nbytes;

				//overwrap
				if (global.offset > global.max_offset)
				{
					global.offset = 0;
					t->offset = offset = global.offset;
					global.offset += nbytes;
					global.overwrap_cnt++;
					printf("overwrap is done. now overwraps: %lu \n", global.overwrap_cnt);
				}

				rv = spdk_bdev_write(t->pls_target.desc, t->pls_target.ch, 
					t->buf, offset, nbytes, pls_bdev_write_done_cb, t);
				if (rv)
					printf("#%d spdk_bdev_write failed, offset: 0x%lx, size: %lu\n",
						t->idx, offset, nbytes);
#ifdef HL_DEBUGS
				else
					printf("writing %lu bytes from thread# #%d, offset: 0x%lx\n",
						nbytes, t->idx, offset);
#endif

				//need to wait for bdev write completion first
				while(t->buf)
				{
					usleep(10);
				}
				position = 0;

				//allocate new buffer and place packet to it
				t->buf = spdk_dma_zmalloc(nbytes, 0x100000, NULL);
				if (!t->buf) 
				{
					printf("ERROR: write buffer allocation failed\n");
					return NULL;
				}
				debug("allocated spdk dma buffer with addr: %p\n", t->buf);

				memcpy(t->buf+position, odp_packet_l2_ptr(pkt, NULL), pkt_len);
				odp_schedule_release_atomic();
				position += pkt_len;
			}
		}
		odp_packet_free(pkt);
	}

	return NULL;
}

//first param - mode. could be: r,w,b (read, write, both)
int main(int argc, char *argv[])
{
	int rv = 0;
	int i;
	size_t count;
	char mode = 'w';
	bool all_finished;

	printf("version: %s\n", VERSION);

	if (argc == 2)
	{
		mode = argv[1][0];
		printf("param: %c \n", mode);
	}
	
	switch (mode)
	{
		case 'w':
			global.mode = MODE_WRITE;
			break;
		case 'r':
			global.mode = MODE_READ;
			break;
		case 'b':
			global.mode = MODE_RW;
			break;
		default:
			global.mode = MODE_WRITE;
			break;
	}
	printf("global.mode: %d \n", global.mode);

	//enable logging
	spdk_log_set_print_level(SPDK_LOG_DEBUG);
	spdk_log_set_level(SPDK_LOG_DEBUG);
	spdk_log_open();

	rv = init_odp();
	if (rv)
	{
		printf("odp init failed. exiting\n");
		exit(1);
	}

	rv = init_spdk();
	if (rv)
	{
		printf("init failed. exiting\n");
		exit(1);
	}

	// do odp init and create write threads only in these modes
	if (global.mode == MODE_RW || global.mode == MODE_WRITE)
	{
		rv = odp_pktio_start(pktio);
		if (rv) exit(1);

		rv = odp_pktin_event_queue(pktio, inq, NUM_INPUT_Q);
		printf("num of input queues configured: %d \n", rv);

		for (i = 0; i < NUM_THREADS; i++)
		{
			pls_thread[i].idx = i;
			rv = pthread_create(&pls_thread[i].pthread_desc, NULL, init_thread, &pls_thread[i]);
			if (rv)
			{
				printf("thread creation failed. exiting\n");
				exit(1);
			}
		}
		sleep(1);
	}

	//creating read thread for RW or READ mode, to read in parallel
	if (global.mode == MODE_RW || global.mode == MODE_READ)
	{
		rv = pthread_create(&pls_read_thread.pthread_desc, NULL, init_read_thread, NULL);
		if (rv)
		{
			printf("reading thread creation failed. exiting\n");
			exit(1);
		}
	}

	sleep(1);

	//need this poll loop to get callbacks after I/O completions
	while(1)
	{
		if (global.mode == MODE_RW || global.mode == MODE_WRITE)
		{
			for (i = 0; i < NUM_THREADS; i++)
			{
				count = pls_poll_thread(&pls_thread[i]);
				if (count)
					printf("got %zu messages from thread %d\n", count, i);
			}
		}
		//poll read thread
		if (global.mode != MODE_WRITE)
		{
			pls_poll_thread(&pls_read_thread);
			if (global.mode == MODE_READ)
			{
				rv = pthread_tryjoin_np(pls_read_thread.pthread_desc, NULL);
				if (!rv)
					exit(0);
			}
		}

		if (global.mode == MODE_WRITE)
		{
			for (i = 0; i < NUM_THREADS; i++)
			{
				rv = pthread_tryjoin_np(pls_thread[i].pthread_desc, NULL);
				if (rv)
				{
					//printf("thread #%d not finished\n", i);
					continue;
				}
				else
				{
					pls_thread[i].finished = true;
					printf("thread #%d finished\n", i);
				}
			}
			all_finished = true;
			for (i = 0; i < NUM_THREADS; i++)
			{
				if (!pls_thread[i].finished)
				{
					all_finished = false;
					break;
				}
				else
					continue;
			}
			if (all_finished)
			{
				printf("all writing threads are finished now\n");
				exit(0);
			}
		}
		usleep(10);
	}
#if 0
	if (global.mode == MODE_WRITE)
	{
		for (i = 0; i < NUM_THREADS; i++)
		{
			pthread_join(pls_thread[i].pthread_desc, NULL);
		}
		printf("all writing threads are finished now\n");
		exit(0);
	}
#endif

	while(1)
	{
		usleep(10);
	}

	return rv;
}
