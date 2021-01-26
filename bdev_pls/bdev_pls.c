//we have to call spdk_allocate_thread() for every thread and we should
//continue to do IO from this thread


#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>

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

#define MB 1048576
#define K4 4096
#define NVME_MAX_BDEVS_PER_RPC 32
#define DEVICE_NAME "s4msung"
#define NUM_THREADS 4

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
	int idx;
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

char *pci_nvme_addr = "0000:02:00.0";
const char *names[NVME_MAX_BDEVS_PER_RPC];
pls_thread_t pls_ctrl_thread;
pls_thread_t pls_thread[NUM_THREADS];

int init(void);
void* init_thread(void*);

static void pls_bdev_init_done(void *cb_arg, int rc)
{
	printf("bdev init is done\n");
	*(bool *)cb_arg = true;
}

//this callback called when write is completed
static void pls_bdev_write_done_cb(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	printf("bdev write is done\n");
	if (success)
		printf("write completed successfully\n");
	else
		printf("write failed\n");

	spdk_dma_free(cb_arg);
}

//this callback called when read is completed
static void pls_bdev_read_done_cb(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	printf("bdev read is done\n");
	if (success)
		printf("read completed successfully\n");
	else
		printf("read failed\n");

	printf("%.*s \n", 16, (char*)cb_arg);
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

static void
pls_stop_poller(struct spdk_poller *poller, void *thread_ctx)
{
	struct pls_poller *lpoller;
	pls_thread_t *thread = thread_ctx;

	printf("%s() called \n", __func__);

	lpoller = (struct pls_poller *)poller;

	TAILQ_REMOVE(&thread->pollers, lpoller, link);

	free(lpoller);
}

int init(void)
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
	memcpy(trid.traddr, pci_nvme_addr, strlen(pci_nvme_addr));
	
	printf("creating bdev device...\n");
	//in names returns names of created devices, in count returns number of devices
	rv = spdk_bdev_nvme_create(&trid, DEVICE_NAME, names, &count);
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

void* init_thread(void *arg)
{
	int rv = 0;
	void *buf;
	uint64_t nbytes = K4;
	pls_thread_t *t = (pls_thread_t*)arg;
	uint64_t offset;
	int i;

	//init offset
	offset = t->idx * 0x10000000;
	printf("%s() called from thread #%d. offset: 0x%lx\n", __func__, t->idx, offset);

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
                                 pls_stop_poller, (void*)t, "pls_worker_thread");

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

	printf("thread init done.\n");

	i = 0;
	while(1)
	{
		buf = spdk_dma_zmalloc(nbytes, 0, NULL); //last param - ptr to phys addr(OUT)
		if (buf)
		{
			printf("writing data from thread# #%d, iteration: %d, offset: 0x%lx\n", t->idx, i, offset);
			memset(buf, 0xFA, nbytes);
			rv = spdk_bdev_write(t->pls_target.desc, t->pls_target.ch, 
				buf, offset, nbytes, pls_bdev_write_done_cb, buf);
			if (rv)
				printf("spdk_bdev_write failed\n");

			offset += nbytes;
		}
		else
			printf("failed to allocate dma buffer \n");
		i++;
		if (i == 10)
			break;

		usleep(10);
	}

	//wait before reading data back
	sleep(3);

	//reading data back to check is it correctly wrote
	printf("now trying to read data back\n");
	offset = t->idx * 0x10000000;
	void *bf = spdk_dma_malloc(nbytes, 0, NULL);
	char *p;
	if (!bf)
		printf("failed to allocate RAM for reading\n");
	else
		memset(bf, 0xff, nbytes);
	rv = spdk_bdev_read(t->pls_target.desc, t->pls_target.ch,
		bf, offset, nbytes, pls_bdev_read_done_cb, bf);
	printf("after spdk read\n");
	if (rv)
		printf("spdk_bdev_read failed\n");
	else
		printf("spdk_bdev_read NO errors\n");

	sleep(5);
	p = (char*)bf;
	printf("dump: 0x%x%x%x%x \n", p[0], p[1], p[2], p[3]);
	while(1)
	{
		usleep(10);
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	int rv = 0;
	int i;
	size_t count;

	//enable logging
	spdk_log_set_print_level(SPDK_LOG_DEBUG);
	spdk_log_set_level(SPDK_LOG_DEBUG);
	spdk_log_open();

	rv = init();
	if (rv)
	{
		printf("init failed. exiting\n");
		exit(1);
	}

	for (i = 0; i < NUM_THREADS; i++)
	{
		pls_thread[i].idx = i;
		rv = pthread_create(&pls_thread[i].pthread_desc, NULL, init_thread, &pls_thread[i]);
		if (rv)
		{
			printf("open_dev failed. exiting\n");
			exit(1);
		}
	}

	sleep(3);
	while(1)
	{
		for (i = 0; i < NUM_THREADS; i++)
		{
			count = pls_poll_thread(&pls_thread[i]);
			if (count)
				printf("got %zu messages from thread %d\n", count, i);
		}

		usleep(10);
	}

	return rv;
}
