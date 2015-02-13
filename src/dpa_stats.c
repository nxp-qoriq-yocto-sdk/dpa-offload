/* Copyright (c) 2011-2013 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * DPA Stats user space library implementation
 */

#include <of.h>
#include <error.h>
#include <pthread.h>
#include <search.h>
#include <compat.h>
#include <dma_mem.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fsl_qman.h>
#include <fsl_usd.h>

#include "fsl_dpa_stats.h"
#include "dpa_stats_ioctl.h"
#include "dpa_stats.h"

#define DPA_STATS_DEV_FILE_NAME	  "/dev/dpa_stats"

#define NUM_EVENTS_IN_READ	5
#define STATS_VAL_SIZE		4

/*
 * The device data structure is necessary so that the dpa_classifier library
 * can translate the "fmlib" handles into FM driver handles.
 */
typedef struct t_Device {
	uintptr_t	id;
	int		fd;
	void		*h_UserPriv;
	uint32_t	owners;
} t_Device;

struct us_thread_data {
	pthread_t		id;
	struct list_head	node;
};

static int dpa_stats_devfd = -1;
pthread_t event_thread;
pthread_t control_thread;
pthread_t wk_thread;
volatile unsigned int us_threads = 0;
volatile bool us_main_thread = false;
volatile bool dpa_stats_shutdown = false;
struct us_thread_data us_thread[MAX_NUM_OF_THREADS];
struct list_head us_thread_list;
static pthread_cond_t us_main_thread_wake_up = PTHREAD_COND_INITIALIZER;

/* Mutex to insure safe access to worker threads counter */
static pthread_mutex_t us_thread_list_access = PTHREAD_MUTEX_INITIALIZER;
/* Mutex to insure safe access to asynchronous mixed requests list */
static pthread_mutex_t async_ks_reqs_lock = PTHREAD_MUTEX_INITIALIZER;

/* Global dpa_stats component */
struct dpa_stats *gbl_dpa_stats;

void *dpa_stats_event_thread(void *arg);
void *dpa_stats_worker_thread(void *arg);
void us_req_queue_busy(const struct fifo_q *q);
static int alloc_cnt_cb(struct dpa_stats *dpa_stats,
			struct dpa_stats_cnt_cb *cnt_cb);

int *copy_array(int const *src, size_t len)
{
	int *dst = malloc(len * sizeof(int));
	if (!dst)
		return NULL;
	memcpy(dst, src, len * sizeof(int));
	return dst;
}

enum req_type type_of_request(struct dpa_stats *dpa_stats,
			      int *cnts_ids, int cnts_ids_len)
{
	uint32_t i = 0;
	int found = 0;

	for (i = 0; i < cnts_ids_len; i++) {
		if (dpa_stats->cnts_cb[cnts_ids[i]].id !=
						DPA_OFFLD_INVALID_OBJECT_ID)
			found++;
	}

	if (found == 0)
		return KS_CNTS_ONLY;
	else
		if (found == cnts_ids_len)
			return US_CNTS_ONLY;
		else
			return MIXED_CNTS;
}

static void get_cnt_64bit_stats(struct dpa_stats_req *req_cb,
				struct stats_info *stats_info,
				void *stats, uint32_t idx, uint32_t mbr_off)
{
	uint64_t stats_val;
	uint32_t j = 0;

	for (j = 0; j < stats_info->stats_num; j++) {
		/* Get statistics value */
		stats_val = *((uint64_t *)(stats + stats_info->stats_off[j]));

		/* Check for rollover */
		if (stats_val < stats_info->last_stats[idx][j])
			stats_info->stats[idx][j] +=
				((unsigned long int)0xffffffff -
				stats_info->last_stats[idx][j]) + stats_val;
		else
			stats_info->stats[idx][j] += stats_val -
				stats_info->last_stats[idx][j];

		/* Store the current value as the last read value */
		stats_info->last_stats[idx][j] = stats_val;

		/* Write the memory location */
		*(uint32_t *)(req_cb->request_area + mbr_off + j *
			STATS_VAL_SIZE) = (uint32_t)stats_info->stats[idx][j];

		if (stats_info->reset)
			stats_info->stats[idx][j] = 0;
	}
}

static int get_cnt_traffic_mng_cq(struct dpa_stats_req *req,
				  struct dpa_stats_cnt_cb *cnt_cb,
				  unsigned int cnt_off)
{
	uint32_t mbr_off = 0, i;
	uint64_t stats_val[2];
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		/* Compute the corresponding offset for the counter member */
		mbr_off = cnt_off + i * cnt_cb->info.stats_num * STATS_VAL_SIZE;

		/* Retrieve statistics for the current member */
		err = qman_ceetm_cq_get_dequeue_statistics(
				(struct qm_ceetm_cq *)cnt_cb->obj[i], 0,
				&stats_val[1], &stats_val[0]);
		if (err < 0) {
			error(0, EINVAL, "Cannot retrieve Traffic Manager Class"
				" Queue statistics for counter id %d\n",
				cnt_cb->id);
			return -EINVAL;
		}
		get_cnt_64bit_stats(req, &cnt_cb->info, &stats_val, i, mbr_off);
	}
	return 0;
}

int get_cnt_traffic_mng_ccg(struct dpa_stats_req *req,
			    struct dpa_stats_cnt_cb *cnt_cb,
			    unsigned int cnt_off)
{
	uint32_t mbr_off = 0, i = 0;
	uint64_t stats_val[2];
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		/* Compute the corresponding offset for the counter member */
		mbr_off = cnt_off + i * cnt_cb->info.stats_num * STATS_VAL_SIZE;
		/* Retrieve statistics for the current member */
		err = qman_ceetm_ccg_get_reject_statistics(
				(struct qm_ceetm_ccg *)cnt_cb->obj[i], 0,
				&stats_val[1], &stats_val[0]);
		if (err < 0) {
			error(0, EINVAL, "Cannot retrieve Traffic Manager Class"
				" Congestion Group statistics for counter id "
				"%d\n", cnt_cb->id);
			return -EINVAL;
		}
		get_cnt_64bit_stats(req, &cnt_cb->info, &stats_val, i, mbr_off);
	}
	return 0;
}


int check_cnt_traffic_mng_cq(struct qm_ceetm_cq *cq, int id)
{
	u64 bytes, frames;
	int err = 0;

	if (!cq) {
		error(0, EINVAL, "Parameter traffic_mng handle qm_ceetm_cq "
			"cannot be NULL for counter id %d", id);
		return -EINVAL;
	}
	err = qman_ceetm_cq_get_dequeue_statistics(cq, 0, &frames, &bytes);
	if (err != 0) {
		/* Invalid object provided */
		error(0, err, "Invalid Traffic Manager qm_ceetm_cq object for "
			"counter id %d\n", id);
		dpa_stats_remove_counter(id);
	}

	return err;
}

int check_cnt_traffic_mng_ccg(struct qm_ceetm_ccg *ccg, int id)
{
	u64 bytes, frames;
	int err = 0;

	if (!ccg) {
		error(0, EINVAL, "Parameter traffic_mng handle qm_ceetm_ccg "
			"cannot be NULL for counter id %d", id);
		return -EINVAL;
	}
	err = qman_ceetm_ccg_get_reject_statistics(ccg, 0, &frames, &bytes);

	if (err != 0) {
		/* Invalid object provided */
		error(0, err, "Invalid Traffic Manager qm_ceetm_ccg object for "
			"counter id %d\n", id);
		dpa_stats_remove_counter(id);
	}

	return err;
}

static int alloc_cnt_traffic_mng(struct dpa_stats_cnt_cb *cnt_cb,
				    enum dpa_stats_cnt_sel cnt_sel)
{
	int err;

	if (cnt_sel == DPA_STATS_CNT_NUM_OF_BYTES ||
	    cnt_sel == DPA_STATS_CNT_NUM_OF_PACKETS) {
		cnt_cb->info.stats_num = 1;
	} else if (cnt_sel == DPA_STATS_CNT_NUM_ALL) {
		cnt_cb->info.stats_num = 2;
	} else {
		error(0, EINVAL, "Parameter cnt_sel %d must be in range (%d - "
		      "%d) for counter id %d\n", cnt_sel,
		      DPA_STATS_CNT_NUM_OF_BYTES,
		      DPA_STATS_CNT_NUM_ALL, cnt_cb->id);
		return -EINVAL;
	}

	err = alloc_cnt_cb(gbl_dpa_stats, cnt_cb);
	if (err < 0) {
		error(0, ENOMEM,
			"Failed to allocate counter control block for counter id=%d.\n",
			cnt_cb->id);
		return err;
	}

	if (cnt_sel == DPA_STATS_CNT_NUM_OF_BYTES ||
	    cnt_sel == DPA_STATS_CNT_NUM_OF_PACKETS) {
		cnt_cb->info.stats_off[0] = cnt_sel * sizeof(uint64_t);
	} else { /* can only be DPA_STATS_CNT_NUM_ALL */
		cnt_cb->info.stats_off[0] = DPA_STATS_CNT_NUM_OF_BYTES;
		cnt_cb->info.stats_off[1] =
			DPA_STATS_CNT_NUM_OF_PACKETS * sizeof(uint64_t);
	}

	return 0;
}

int dpa_stats_lib_init(void)
{
	int err = 0;

	if (dpa_stats_devfd >= 0) {
		error(0, EEXIST, "DPA Stats library is already initialized\n");
		return -EEXIST;
	}

	dpa_stats_devfd = open(DPA_STATS_DEV_FILE_NAME, O_RDWR);
	if (dpa_stats_devfd < 0) {
		error(0, errno, "Could not open /dev/dpa_stats\n");
		return -errno;
	}

	/* Initialize the thread for reading events: */
	err = pthread_create(&event_thread, NULL, dpa_stats_event_thread, NULL);
	if (err != 0) {
		error(0, err, "Cannot create new event thread\n");
		return err;
	}

	return err;
}

void dpa_stats_lib_exit(void)
{
	if (dpa_stats_devfd < 0)
		return;
	close(dpa_stats_devfd);
	dpa_stats_devfd = -1;
}

static inline int block_sched_cnts(struct dpa_stats *dpa_stats,
				   int *cnts_ids, int cnts_ids_len)
{
	int ret, i;

	ret = pthread_mutex_lock(&dpa_stats->sched_cnt_lock);
	if (ret)
		return ret;
	for (i = 0; i < cnts_ids_len; i++)
		dpa_stats->sched_cnt_ids[cnts_ids[i]] = true;
	return pthread_mutex_unlock(&dpa_stats->sched_cnt_lock);
}

static inline int unblock_sched_cnts(struct dpa_stats *dpa_stats,
				     int *cnts_ids, int cnts_ids_len)
{
	int i, ret = 0;

	ret = pthread_mutex_lock(&dpa_stats->sched_cnt_lock);
	if (ret)
		return ret;
	for (i = 0; i < cnts_ids_len; i++)
		dpa_stats->sched_cnt_ids[cnts_ids[i]] = false;
	return pthread_mutex_unlock(&dpa_stats->sched_cnt_lock);
}

static int alloc_cnt_cb(struct dpa_stats *dpa_stats,
			struct dpa_stats_cnt_cb *cnt_cb)
{
	int i = 0;

	/* Allocate array of statistics offsets */
	cnt_cb->info.stats_off = malloc(cnt_cb->info.stats_num *
					sizeof(*cnt_cb->info.stats_off));
	if (!cnt_cb->info.stats_off) {
		error(0, ENOMEM, "Cannot allocate memory to store array of "
			"statistics offsets\n");
		return -ENOMEM;
	}
	/* Allocate array of currently read statistics */
	cnt_cb->info.stats = calloc(cnt_cb->members_num, sizeof(uint64_t *));
	if (!cnt_cb->info.stats) {
		error(0, ENOMEM, "Cannot allocate memory to store array of "
			"statistics for all members\n");
		return -ENOMEM;
	}
	for (i = 0; i < cnt_cb->members_num; i++) {
		cnt_cb->info.stats[i] = calloc(cnt_cb->info.stats_num,
					       sizeof(uint64_t));
		if (!cnt_cb->info.stats[i]) {
			error(0, ENOMEM, "Cannot allocate memory to store "
				"array of statistics for %d member\n", i);
			return -ENOMEM;
		}
	}

	/* Allocate array of previously read statistics */
	cnt_cb->info.last_stats = calloc(cnt_cb->members_num,
					 sizeof(uint64_t *));
	if (!cnt_cb->info.last_stats) {
		error(0, ENOMEM, "Cannot allocate memory to store array of "
			"previous read statistics for all members\n");
		return -ENOMEM;
	}
	for (i = 0; i < cnt_cb->members_num; i++) {
		cnt_cb->info.last_stats[i] = calloc(cnt_cb->info.stats_num,
						    sizeof(uint64_t));
		if (!cnt_cb->info.last_stats[i]) {
			error(0, ENOMEM, "Cannot allocate memory to store array "
			     "of previous read statistics for %d member\n", i);
			return -ENOMEM;
		}
	}

	return 0;
}

static int init_resources(struct dpa_stats *dpa_stats)
{
	uint32_t i;
	int err;

	/* Initialize list of 'in-progress' asynchronous requests */
	INIT_LIST_HEAD(&dpa_stats->async_ks_reqs);

	INIT_LIST_HEAD(&us_thread_list);

	/* Allocate request internal structure */
	dpa_stats->req = calloc(DPA_STATS_MAX_NUM_OF_REQUESTS - 1,
				sizeof(*dpa_stats->req));
	if (!dpa_stats->req) {
		error(0, ENOMEM, "Cannot allocate memory for "
				 "synchronous request internal structure\n");
		return -ENOMEM;
	}

	err = fifo_create(&dpa_stats->req_queue,
					DPA_STATS_MAX_NUM_OF_REQUESTS - 1);
	if (err != 0) {
		error(0, -err, "Failed to create stats requests queue");
		return err;
	}
	for (i = 0; i < DPA_STATS_MAX_NUM_OF_REQUESTS - 1; i++) {
		err = fifo_add(&dpa_stats->req_queue, &dpa_stats->req[i]);
		if (err != 0) {
			error(0, -err,
				"Failed to populate stats requests queue");
			return err;
		}
	}

	err = fifo_create(&dpa_stats->async_us_req_queue,
					DPA_STATS_MAX_NUM_OF_REQUESTS - 1);
	if (err != 0) {
		error(0, -err, "Failed to create stats requests queue");
		return err;
	}
	err = fifo_set_alert(&dpa_stats->async_us_req_queue,
				REQUESTS_THRESHOLD,
				us_req_queue_busy);
	if (err != 0) {
		error(0, -err, "Failed to configure stats requests queue");
		return err;
	}

	/* Allocate array to store counter ids that are scheduled for retrieve*/
	dpa_stats->sched_cnt_ids = calloc(dpa_stats->config.max_counters,
					  sizeof(bool));
	if (!dpa_stats->sched_cnt_ids) {
		error(0, ENOMEM, "Cannot allocate memory to store %d scheduled "
			"counter ids\n", dpa_stats->config.max_counters);
		return -ENOMEM;
	}

	/* Allocate array to store counters control blocks */
	dpa_stats->cnts_cb = calloc(dpa_stats->config.max_counters,
				    sizeof(struct dpa_stats_cnt_cb));
	if (!dpa_stats->cnts_cb) {
		error(0, ENOMEM, "Cannot allocate memory to store %d internal "
		      "counter structures\n", dpa_stats->config.max_counters);
		return -ENOMEM;
	}

	/* Mark all the counters as being 'kernel-space' counters */
	for (i = 0; i < dpa_stats->config.max_counters; i++) {
		/* Initialize counter lock */
		pthread_mutex_init(&dpa_stats->cnts_cb[i].lock, NULL);
		/* Store dpa_stats instance */
		dpa_stats->cnts_cb[i].dpa_stats = dpa_stats;
		/* Mark the counter as being 'kernel-space' counter */
		dpa_stats->cnts_cb[i].id = DPA_OFFLD_INVALID_OBJECT_ID;
	}

	/* Initialize user space worker threads control blocks: */
	for (i = 0; i < MAX_NUM_OF_THREADS; i++)
		list_add_tail(&us_thread[i].node, &us_thread_list);

	/* Initialize mutex required to protect access to scheduled counters */
	err = pthread_mutex_init(&dpa_stats->sched_cnt_lock, NULL);
	if (err != 0)
		error(0, err, "Failed to initialize DPA Stats mutex");

	return err;
}

static int free_resources(struct dpa_stats *dpa_stats)
{
	uint32_t i, j;
	int err;

	/* Wake up the main worker thread (if it exists) so that it shuts down */
	dpa_stats_shutdown = true;
	if (us_main_thread)
		us_req_queue_busy(&dpa_stats->async_us_req_queue);

	if (dpa_stats->cnts_cb) {
		for (i = 0; i < dpa_stats->config.max_counters; i++) {
			if (dpa_stats->cnts_cb[i].id != DPA_OFFLD_INVALID_OBJECT_ID) {
				for (j = 0; j < dpa_stats->cnts_cb[i].members_num; j++) {
					free(dpa_stats->cnts_cb[i].info.stats[j]);
					free(dpa_stats->cnts_cb[i].info.last_stats[j]);
				}
				free(dpa_stats->cnts_cb[i].info.stats_off);
				free(dpa_stats->cnts_cb[i].info.stats);
				free(dpa_stats->cnts_cb[i].info.last_stats);
			}
		}
	}
	if (dpa_stats->req)
		free(dpa_stats->req);

	fifo_destroy(&dpa_stats->req_queue);

	fifo_destroy(&dpa_stats->async_us_req_queue);

	if (dpa_stats->sched_cnt_ids)
		free(dpa_stats->sched_cnt_ids);

	/* Destroy mutex required to protect access to scheduled counters */
	err = pthread_mutex_destroy(&dpa_stats->sched_cnt_lock);
	if (err != 0)
		error(0, err, "Failed to destroy DPA Stats mutex");

	/* Wait until all async request processing threads die: */
	while (us_threads) {};

	free(dpa_stats);
	gbl_dpa_stats = NULL;

	return 0;
}

static int check_us_get_counters_params(struct dpa_stats *dpa_stats,
					struct dpa_stats_cnt_request_params prm,
					int *cnts_len)
{
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	int cnt_id, ret = 0;
	uint32_t i = 0;

	/* Check user-provided cnts_len pointer */
	if (!cnts_len) {
		error(0, EINVAL, "Parameter cnts_len cannot be NULL\n");
		return -EINVAL;
	}

	/* Check user-provided params.cnts_ids pointer */
	if (!prm.cnts_ids) {
		error(0, EINVAL, "Parameter cnts_ids cannot be NULL\n");
		return -EINVAL;
	}

	*cnts_len = 0;

	for (i = 0; i < prm.cnts_ids_len; i++) {
		if (prm.cnts_ids[i] == DPA_OFFLD_INVALID_OBJECT_ID) {
			error(0, EINVAL, "Counter id (cnt_ids[%d]) %d is not initialized\n",
					i, prm.cnts_ids[i]);
			return -EINVAL;
		}
	}

	/* Calculate number of bytes occupied by the counters */
	for (i = 0; i < prm.cnts_ids_len; i++) {
		cnt_id = prm.cnts_ids[i];

		/* Get counter's control block */
		cnt_cb = &dpa_stats->cnts_cb[cnt_id];

		/* Acquire counter lock */
		ret = pthread_mutex_lock(&cnt_cb->lock);
		if (ret)
			return ret;

		/* Check if counter control block is initialized */
		if (cnt_cb->id == DPA_OFFLD_INVALID_OBJECT_ID) {
			error(0, EINVAL, "Counter id (cnt_ids[%d]) %d is "
				"not initialized\n", i, cnt_id);
			ret = pthread_mutex_unlock(&cnt_cb->lock);
			if (ret)
				return ret;

			return -EINVAL;
		}

		*cnts_len += cnt_cb->bytes_num;
		ret = pthread_mutex_unlock(&cnt_cb->lock);
		if (ret)
			return ret;
	}

	/* Check user-provided parameters */
	if ((prm.storage_area_offset + *cnts_len) >
		dpa_stats->config.storage_area_len) {
		error(0, EINVAL, "Parameter storage_area_offset %d and counters"
			" length %d exceeds configured storage_area_len %d\n",
			prm.storage_area_offset, *cnts_len,
			dpa_stats->config.storage_area_len);
		return -EINVAL;
	}
	return 0;
}

static int treat_us_cnts_request(struct dpa_stats *dpa_stats,
				 struct dpa_stats_req *req_cb)
{
	struct dpa_stats_cnt_request_params params = req_cb->config;
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	uint32_t i = 0;
	int err = 0;

	for (i = 0; i < params.cnts_ids_len; i++) {
		/* Get counter's control block */
		cnt_cb = &dpa_stats->cnts_cb[req_cb->cnt_ids[i]];

		/* Acquire counter lock */
		err = pthread_mutex_lock(&cnt_cb->lock);
		if (err)
			return err;

		cnt_cb->info.reset = req_cb->config.reset_cnts;

		/* Call counter's retrieve function */
		err = cnt_cb->f_get_cnt_stats(req_cb, cnt_cb,
							req_cb->bytes_num);
		if (err < 0) {
			error(0, EINVAL, "Cannot retrieve statistics for "
			      "counter id %d\n", req_cb->cnt_ids[i]);

			err = pthread_mutex_unlock(&cnt_cb->lock);
			if (err)
				return err;
			err = unblock_sched_cnts(dpa_stats,
					req_cb->cnt_ids, params.cnts_ids_len);
			if (err < 0)
				return err;
			return -EINVAL;
		}

		/*
		 * Update number of bytes and number of counters
		 * successfully written so far
		 */
		req_cb->bytes_num += cnt_cb->bytes_num;
		req_cb->cnts_num += 1;

		err = pthread_mutex_unlock(&cnt_cb->lock);
		if (err)
			return err;
	}
	return unblock_sched_cnts(dpa_stats,
				 req_cb->cnt_ids, params.cnts_ids_len);
}

static int treat_mixed_cnts_request(struct dpa_stats *dpa_stats,
				    struct dpa_stats_req *req_cb)
{
	struct dpa_stats_cnt_request_params params = req_cb->config;
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	uint32_t i = 0;
	int err = 0;

	for (i = 0; i < params.cnts_ids_len; i++) {
		/* Get counter's control block */
		cnt_cb = &dpa_stats->cnts_cb[req_cb->cnt_ids[i]];

		/* Acquire counter lock */
		err = pthread_mutex_lock(&cnt_cb->lock);
		if (err)
			return err;

		/* If counter is kernel-space, it was already treated */
		if (cnt_cb->id == DPA_OFFLD_INVALID_OBJECT_ID) {
			err = pthread_mutex_unlock(&cnt_cb->lock);
			if (err)
				return err;
			continue;
		}

		cnt_cb->info.reset = req_cb->config.reset_cnts;

		/* Call counter's retrieve function */
		err = cnt_cb->f_get_cnt_stats(req_cb, cnt_cb,
							req_cb->cnt_off[i]);
		if (err < 0) {
			error(0, EINVAL, "Cannot retrieve statistics for "
			      "counter id %d\n", req_cb->cnt_ids[i]);
			err = pthread_mutex_unlock(&cnt_cb->lock);
			if (err)
				return err;

			err = unblock_sched_cnts(dpa_stats,
					req_cb->cnt_ids, params.cnts_ids_len);
			if (err < 0)
				return err;
			return -EINVAL;
		}
		err = pthread_mutex_unlock(&cnt_cb->lock);
		if (err)
			return err;
	}
	return unblock_sched_cnts(dpa_stats,
				  req_cb->cnt_ids, params.cnts_ids_len);
}

static int process_async_req(struct dpa_stats_event_params *ev)
{
	struct dpa_stats *dpa_stats = NULL;
	struct dpa_stats_req *async_req = NULL;
	struct list_head *pos;
	bool found = false;
	int err = 0;

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return -EINVAL;
	}
	dpa_stats = gbl_dpa_stats;

	BUG_ON(list_empty(&dpa_stats->async_ks_reqs));

	/* Search in the request group the request event */
	err = pthread_mutex_lock(&async_ks_reqs_lock);
	if (err)
		return err;

	list_for_each(pos, &dpa_stats->async_ks_reqs) {
		async_req = list_entry(pos, struct dpa_stats_req, node);

		if (async_req->config.storage_area_offset ==
				ev->storage_area_offset) {
			list_del(&async_req->node);
			found = true;
			break;
		}
	}
	err = pthread_mutex_unlock(&async_ks_reqs_lock);
	if (err)
		return err;

	if (!found) {
		error(0, EINVAL, "Cannot find event in the event list\n");
		return -EINVAL;
	}

	if (async_req->type == MIXED_CNTS) {
		/*
		 * Because the kernel-space counters of the request have been
		 * treated, remove the request from the kernel-space list and
		 * add it in the user-space list
		 */
		async_req->cnts_num = ev->cnts_written;
		async_req->bytes_num = ev->bytes_written;
		err = fifo_add(&dpa_stats->async_us_req_queue, async_req);
		if (err < 0)
			return err;

		/* If there are no worker threads alive, wake one up. */
		if (us_threads == 0)
			us_req_queue_busy(&dpa_stats->async_us_req_queue);
	} else {
		/*
		 * All the counters were treated, return the nodes to their
		 * pools
		 */
		free(async_req->cnt_off);
		free(async_req->cnt_ids);
		async_req->cnt_off = NULL;
		async_req->cnt_ids = NULL;
		err = fifo_add(&dpa_stats->req_queue, async_req);
		if (err) {
			error(0, -err, "Failed to recycle stats request\n");
			return err;
		}
		ev->request_done(ev->dpa_stats_id,
				 ev->storage_area_offset,
				 ev->cnts_written,
				 ev->bytes_written);
	}

	return 0;
}

static int fill_req_params(struct dpa_stats			*dpa_stats,
			   struct dpa_stats_cnt_request_params  prm,
			   dpa_stats_request_cb			request_done,
			   struct dpa_stats_req			**req_cb)
{
	struct dpa_stats_req *req = NULL;
	uint32_t i = 0;

	req = (struct dpa_stats_req*) fifo_try_get(&dpa_stats->req_queue);
	if (!req) {
		error(0, EDOM, "Reached maximum supported number of "
		      "simultaneous requests\n");
		return -EDOM;
	}

	/* Initialize and save user-provided parameters */
	memset(req, 0, sizeof(*req));
	req->config.cnts_ids = prm.cnts_ids;
	req->config.reset_cnts = prm.reset_cnts;
	req->config.storage_area_offset = prm.storage_area_offset;
	req->config.cnts_ids_len = prm.cnts_ids_len;
	req->request_done = request_done;

	/* Set memory area where the request should write */
	req->request_area = dpa_stats->storage_area + prm.storage_area_offset;

	for(i = 0; i < prm.cnts_ids_len; i++)
		if(prm.cnts_ids[i] >= dpa_stats->config.max_counters) {
			error(0, EINVAL, "Counter id (cnt_ids[%d]) %d is greater than maximum counters %d\n",
			i, prm.cnts_ids[i], dpa_stats->config.max_counters);
			return -EINVAL;
		}
	/* Synchronous request: store the provided pointer to array of ids */
	if (!request_done)
		req->cnt_ids = prm.cnts_ids;
	else {
		/*
		 * Asynchronous request: allocate an equal size array and copy
		 * the contents from the user-provided array of counters ids
		 */
		req->cnt_ids = copy_array(prm.cnts_ids, prm.cnts_ids_len);
		if (!req->cnt_ids) {
			error(0, ENOMEM, "Cannot copy array of counters ids\n");
			return -ENOMEM;
		}
	}

	/* Allocate and fill the counters offsets array */
	req->cnt_off = copy_array(prm.cnts_ids, prm.cnts_ids_len);
	if (!req->cnt_off) {
		error(0, ENOMEM, "Cannot copy array of counters ids\n");
		return -ENOMEM;
	}

	/* Determine and store the type of the request */
	req->type = type_of_request(dpa_stats, req->cnt_ids, prm.cnts_ids_len);

	*req_cb = req;

	return 0;
}

static int set_cnt_traffic_mng_cb(
		struct dpa_stats *dpa_stats,
		const struct dpa_stats_cnt_params *params, int id)
{
	struct dpa_stats_cnt_cb *cnt_cb = &dpa_stats->cnts_cb[id];
	int err;

	/* Check user-provided parameters */
	switch (params->traffic_mng_params.src) {
	case DPA_STATS_CNT_TRAFFIC_CLASS:
		cnt_cb->f_get_cnt_stats = get_cnt_traffic_mng_cq;
		err = check_cnt_traffic_mng_cq((struct qm_ceetm_cq *)
				params->traffic_mng_params.traffic_mng, id);
		if (err != 0)
			return -err;
		break;
	case DPA_STATS_CNT_TRAFFIC_CG:
		cnt_cb->f_get_cnt_stats = get_cnt_traffic_mng_ccg;
		err = check_cnt_traffic_mng_ccg((struct qm_ceetm_ccg *)
				params->traffic_mng_params.traffic_mng, id);
		if (err != 0)
			return -err;
		break;
	default:
		break;
	}

	/* Mark counter structure as 'being used' and fill parameters */
	cnt_cb->id = id;
	cnt_cb->sel = params->traffic_mng_params.cnt_sel;
	cnt_cb->members_num = 1;
	cnt_cb->type = params->type;
	cnt_cb->dpa_stats = dpa_stats;

	cnt_cb->obj[0] = params->traffic_mng_params.traffic_mng;

	/* Allocate resources for Traffic Manager counter selection */
	alloc_cnt_traffic_mng(cnt_cb, cnt_cb->sel);

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = cnt_cb->members_num *
				STATS_VAL_SIZE * cnt_cb->info.stats_num;
	return 0;
}

static int set_cls_cnt_traffic_mng_cb(
		struct dpa_stats *dpa_stats,
		const struct dpa_stats_cls_cnt_params *params, int id)
{
	struct dpa_stats_cnt_cb *cnt_cb = &dpa_stats->cnts_cb[id];
	int err;
	uint32_t i;

	/* Check user-provided parameters */
	switch (params->traffic_mng_params.src) {
	case DPA_STATS_CNT_TRAFFIC_CLASS:
		cnt_cb->f_get_cnt_stats = get_cnt_traffic_mng_cq;
		for (i = 0; i < params->class_members; i++) {
			err = check_cnt_traffic_mng_cq((struct qm_ceetm_cq *)
				params->traffic_mng_params.traffic_mng[i], id);
			if (err != 0)
				return -err;
		}
		break;
	case DPA_STATS_CNT_TRAFFIC_CG:
		cnt_cb->f_get_cnt_stats = get_cnt_traffic_mng_ccg;
		for (i = 0; i < params->class_members; i++) {
			err = check_cnt_traffic_mng_ccg((struct qm_ceetm_ccg *)
				params->traffic_mng_params.traffic_mng[i], id);
			if (err != 0)
				return -err;
		}
		break;
	default:
		break;
	}

	/* Mark counter structure as 'being used' and fill parameters */
	cnt_cb->id = id;
	cnt_cb->sel = params->traffic_mng_params.cnt_sel;
	cnt_cb->members_num = params->class_members;
	cnt_cb->type = params->type;
	cnt_cb->dpa_stats = dpa_stats;

	for (i = 0; i < cnt_cb->members_num; i++)
		cnt_cb->obj[i] = params->traffic_mng_params.traffic_mng[i];

	/* Allocate resources for Traffic Manager counter selection */
	alloc_cnt_traffic_mng(cnt_cb, cnt_cb->sel);

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = cnt_cb->members_num *
				STATS_VAL_SIZE * cnt_cb->info.stats_num;
	return 0;
}

int dpa_stats_init(const struct dpa_stats_params *params, int *dpa_stats_id)
{
	struct ioc_dpa_stats_params prm;
	struct dma_mem *map;
	struct dpa_stats *dpa_stats = NULL;
	int err = 0;

	if (!params || !dpa_stats_id) {
		error(0, EINVAL, "Invalid input parameters\n");
		return -EINVAL;
	}

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized3\n");
		return -ENODEV;
	}

	memset(&prm, 0, sizeof(prm));

	/* Check if the user-provided storage area is DMA mapped */
	map = dma_mem_findv(params->storage_area);
	if (!map) {
		prm.stg_area_mapped = false;
		prm.virt_stg_area = params->storage_area;
	} else {
		prm.stg_area_mapped = true;
		prm.phys_stg_area = dma_mem_vtop(map, params->storage_area);
	}

	prm.dpa_stats_id = 0;
	prm.max_counters = params->max_counters;
	prm.storage_area_len = params->storage_area_len;

	/* Allocate dpa stats internal structure */
	dpa_stats = malloc(sizeof(*dpa_stats));
	if (!dpa_stats) {
		error(0, ENOMEM, "Cannot allocate memory for internal DPA "
		     "Stats structure.\n");
		return -ENOMEM;
	}
	memset(dpa_stats, 0, sizeof(*dpa_stats));

	/* Save storage-area and config parameters */
	dpa_stats->storage_area = params->storage_area;
	dpa_stats->config = *params;

	/* Allocate and initialize internal structures */
	err = init_resources(dpa_stats);
	if (err < 0) {
		free_resources(dpa_stats);
		return err;
	}

	if (ioctl(dpa_stats_devfd, DPA_STATS_IOC_INIT, &prm) < 0) {
		error(0, errno, "Couldn't initialize the DPA Stats instance\n");
		free_resources(dpa_stats);
		return -errno;
	}
	*dpa_stats_id = prm.dpa_stats_id;

	gbl_dpa_stats = dpa_stats;

	return 0;
}

int dpa_stats_free(int dpa_stats_id)
{
	struct dpa_stats *dpa_stats = NULL;

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	if (dpa_stats_id < 0) {
		error(0, EINVAL, "Invalid DPA Stats identifier\n");
		return -EINVAL;
	}

	if (ioctl(dpa_stats_devfd, DPA_STATS_IOC_FREE, &dpa_stats_id) < 0) {
		error(0, errno, "Could not free the DPA Stats instance\n");
		return -errno;
	}

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return -EINVAL;
	}
	dpa_stats = gbl_dpa_stats;

	return free_resources(dpa_stats);
}

int dpa_stats_create_counter(int dpa_stats_id,
			     const struct dpa_stats_cnt_params *cnt_params,
			     int *dpa_stats_cnt_id)
{
	struct ioc_dpa_stats_cnt_params prm;
	struct dpa_stats *dpa_stats = NULL;
	struct t_Device *dev;
	bool is_us_cnt = false;
	uint32_t err = 0;

	if (dpa_stats_id < 0 || !cnt_params || !dpa_stats_cnt_id) {
		error(0, EINVAL, "Invalid input parameters\n");
		return -EINVAL;
	}

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return -EINVAL;
	}
	dpa_stats = gbl_dpa_stats;

	memset(&prm, 0, sizeof(prm));
	memcpy(&prm.cnt_params, cnt_params, sizeof(prm.cnt_params));

	switch (cnt_params->type) {
	case DPA_STATS_CNT_CLASSIF_NODE:
		/* Translate Cc node handle to FMD type of handles */
		dev = (t_Device *)cnt_params->classif_node_params.cc_node;
		prm.cnt_params.classif_node_params.cc_node = (void *)dev->id;
		break;
	case DPA_STATS_CNT_REASS:
		/* Translate Manip node handle to FMD type of handles */
		dev = (t_Device *)cnt_params->reass_params.reass;
		prm.cnt_params.reass_params.reass = (void *)dev->id;
		break;
	case DPA_STATS_CNT_FRAG:
		/* Translate Manip node handle to FMD type of handles */
		dev = (t_Device *)cnt_params->frag_params.frag;
		prm.cnt_params.frag_params.frag = (void *)dev->id;
		break;
	case DPA_STATS_CNT_POLICER:
		/* Translate Policer node handle to FMD type of handles */
		dev = (t_Device *)cnt_params->plcr_params.plcr;
		prm.cnt_params.plcr_params.plcr = (void *)dev->id;
		break;
	case DPA_STATS_CNT_TRAFFIC_MNG:
		/* Notify the driver that counter is managed in user-space */
		prm.cnt_params.traffic_mng_params.cnt_sel |= DPA_STATS_US_CNT;
		is_us_cnt = true;
		break;
	default:
		break;
	}

	if (ioctl(dpa_stats_devfd, DPA_STATS_IOC_CREATE_COUNTER, &prm) < 0) {
		error(0, errno, "Could not create counter\n");
		return -errno;
	}

	if (prm.cnt_id >= 0)
		*dpa_stats_cnt_id = prm.cnt_id;

	if (is_us_cnt) {
		/* Create user-space counter */
		switch (cnt_params->type) {
		case DPA_STATS_CNT_TRAFFIC_MNG:
			err = set_cnt_traffic_mng_cb(dpa_stats,
						     cnt_params, prm.cnt_id);
			if (err != 0) {
				error(0, EINVAL, "Cannot create Traffic Manager"
					" counter id %d\n", prm.cnt_id);
				return -EINVAL;
			}
			break;
		default:
			break;
		}
	}

	return 0;
}

int dpa_stats_create_class_counter(int dpa_stats_id,
			      const struct dpa_stats_cls_cnt_params *cnt_params,
			      int *dpa_stats_cnt_id)
{
	struct ioc_dpa_stats_cls_cnt_params prm;
	struct dpa_stats *dpa_stats = NULL;
	struct t_Device *dev;
	uint32_t i = 0, err = 0;
	bool is_us_cnt = false;

	if (dpa_stats_id < 0 || !cnt_params || !dpa_stats_cnt_id) {
		error(0, EINVAL, "Invalid input parameters\n");
		return -EINVAL;
	}

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return -EINVAL;
	}
	dpa_stats = gbl_dpa_stats;

	memset(&prm, 0, sizeof(prm));
	memcpy(&prm.cnt_params, cnt_params, sizeof(*cnt_params));

	switch (cnt_params->type) {
	case DPA_STATS_CNT_CLASSIF_NODE:
		/* Translate Cc node handle to FMD type of handles */
		dev = (t_Device *)cnt_params->classif_node_params.cc_node;
		prm.cnt_params.classif_node_params.cc_node = (void *)dev->id;
		break;
	case DPA_STATS_CNT_REASS:
		for (i = 0; i < cnt_params->class_members; i++) {
			/* Translate Manip node handle to FMD type of handle */
			dev = (t_Device *)cnt_params->reass_params.reass[i];
			prm.cnt_params.reass_params.reass[i] = (void *)dev->id;
		}
		break;
	case DPA_STATS_CNT_FRAG:
		for (i = 0; i < cnt_params->class_members; i++) {
			/* Translate Manip node handle to FMD type of handle */
			dev = (t_Device *)cnt_params->frag_params.frag[i];
			prm.cnt_params.frag_params.frag[i] = (void *)dev->id;
		}
		break;
	case DPA_STATS_CNT_POLICER:
		for (i = 0; i < cnt_params->class_members; i++) {
			/* Translate Policer node handle to FMD type handles */
			dev = (t_Device *)cnt_params->plcr_params.plcr[i];
			prm.cnt_params.plcr_params.plcr[i] = (void *)dev->id;
		}
		break;
	case DPA_STATS_CNT_TRAFFIC_MNG:
		/* Notify the driver that counter is managed in user-space */
		prm.cnt_params.traffic_mng_params.cnt_sel |= DPA_STATS_US_CNT;
		is_us_cnt = true;
		break;
	default:
		break;
	}

	if (ioctl(dpa_stats_devfd,
		  DPA_STATS_IOC_CREATE_CLASS_COUNTER, &prm) < 0) {
		error(0, errno, "Could not create class counter\n");
		return -errno;
	}

	if (prm.cnt_id >= 0)
		*dpa_stats_cnt_id = prm.cnt_id;

	if (is_us_cnt) {
		/* Create user-space counter */
		switch (cnt_params->type) {
		case DPA_STATS_CNT_TRAFFIC_MNG:
			err = set_cls_cnt_traffic_mng_cb(dpa_stats,
							cnt_params, prm.cnt_id);
			if (err != 0) {
				error(0, EINVAL, "Cannot create Traffic Manager"
				      " counter id %d\n", prm.cnt_id);
				return -EINVAL;
			}
			break;
		default:
			break;
		}
	}

	return 0;
}

int dpa_stats_modify_class_counter(int dpa_stats_cnt_id,
		const struct dpa_stats_cls_member_params *params,
		int member_index)
{
	struct ioc_dpa_stats_cls_member_params prm;

	if (dpa_stats_cnt_id < 0 || !params || member_index < 0) {
		error(0, EINVAL, "Invalid input parameters\n");
		return -EINVAL;
	}

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	prm.cnt_id = dpa_stats_cnt_id;
	prm.member_index = member_index;

	memcpy(&prm.params, params, sizeof(*params));

	if (ioctl(dpa_stats_devfd,
		  DPA_STATS_IOC_MODIFY_CLASS_COUNTER, &prm) < 0) {
		error(0, errno, "Could not modify class counter\n");
		return -errno;
	}
	return 0;
}

int dpa_stats_remove_counter(int dpa_stats_cnt_id)
{
	struct dpa_stats *dpa_stats = NULL;
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	int i, ret;

	if (dpa_stats_cnt_id < 0) {
		error(0, EINVAL, "Invalid input parameter\n");
		return -EINVAL;
	}

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return -EINVAL;
	}
	dpa_stats = gbl_dpa_stats;
	cnt_cb = &dpa_stats->cnts_cb[dpa_stats_cnt_id];

	if (ioctl(dpa_stats_devfd,
		  DPA_STATS_IOC_REMOVE_COUNTER, &dpa_stats_cnt_id) < 0) {
		error(0, errno, "Could not remove this counter\n");
		return -errno;
	}

	/* Counter scheduled for the retrieve mechanism can't be removed */
	ret = pthread_mutex_lock(&dpa_stats->sched_cnt_lock);
	if (ret)
		return ret;

	if (dpa_stats->sched_cnt_ids[dpa_stats_cnt_id]) {
		error(0, errno, "Counter id %d is in use\n", dpa_stats_cnt_id);
		ret = pthread_mutex_unlock(&dpa_stats->sched_cnt_lock);
		if (ret)
			return ret;
		return -EBUSY;
	}
	ret = pthread_mutex_unlock(&dpa_stats->sched_cnt_lock);
	if (ret)
		return ret;

	if (cnt_cb->id != DPA_OFFLD_INVALID_OBJECT_ID) {
		/* Mark the equivalent 'user-space' counter structure as invalid */
		cnt_cb->id = DPA_OFFLD_INVALID_OBJECT_ID;

		for (i = 0; i < cnt_cb->members_num; i++) {
			free(cnt_cb->info.stats[i]);
			free(cnt_cb->info.last_stats[i]);
		}
		cnt_cb->members_num = 0;

		free(cnt_cb->info.stats);
		free(cnt_cb->info.last_stats);
		free(cnt_cb->info.stats_off);
		cnt_cb->info.stats	= NULL;
		cnt_cb->info.last_stats	= NULL;
		cnt_cb->info.stats_off	= NULL;
	}

	return 0;
}

int dpa_stats_get_counters(struct dpa_stats_cnt_request_params params,
			   int *cnts_len,
			   dpa_stats_request_cb request_done)
{
	struct ioc_dpa_stats_cnt_request_params ioc_prm;
	struct dpa_stats *dpa_stats = NULL;
	struct dpa_stats_req *req = NULL;
	int ret = 0;

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -EAGAIN;
	}

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return -EINVAL;
	}
	dpa_stats = gbl_dpa_stats;

	/* Obtain a new request internal structure and fill it */
	ret = fill_req_params(dpa_stats, params, request_done, &req);
	if (ret < 0)
		return ret;

	memcpy(&ioc_prm.req_params, &params, sizeof(params));
	ioc_prm.cnts_len = *cnts_len;
	ioc_prm.request_done = request_done;
	ioc_prm.req_params.cnts_ids = req->cnt_off;

	/* If counters request is asynchronous */
	if ((request_done) && (req->type != US_CNTS_ONLY)) {
		/*
		 * The request is not only for user-space counters,
		 * so add it in the list that treats only us requests
		 */
		ret = pthread_mutex_lock(&async_ks_reqs_lock);
		if (ret)
			return ret;
		list_add_tail(&req->node, &dpa_stats->async_ks_reqs);
		ret = pthread_mutex_unlock(&async_ks_reqs_lock);
		if (ret)
			return ret;
	}

	/* If request is 'us' type, then we need to check the parameters*/
	if (req->type == US_CNTS_ONLY) {
		/* Check user-provided parameters */
		ret = check_us_get_counters_params(dpa_stats, params, cnts_len);
		if (ret < 0)
			return ret;

		if (!request_done) {
			/* Synchronous request */
			ret = block_sched_cnts(dpa_stats, params.cnts_ids,
				params.cnts_ids_len);
			if (ret < 0)
				return ret;

			ret =  treat_us_cnts_request(dpa_stats, req);
			if (ret < 0)
				return ret;

			/* Provide to the user the number of written bytes */
			*cnts_len = req->bytes_num;

			/*
			 * Return the request structure to the available
			 * requests pool
			 */
			free(req->cnt_off);
			req->cnt_off = NULL;
			ret = fifo_add(&dpa_stats->req_queue, req);
			if (ret < 0)
				return ret;
		} else {
			/*
			 * The request is only for user-space counters, so add
			 * it to the queue which treats only user-space requests
			 */
			ret = fifo_add(&dpa_stats->async_us_req_queue, req);
			if (ret < 0)
				return ret;

			/* If there are no worker threads alive, wake one up. */
			if (us_threads == 0)
				us_req_queue_busy(&dpa_stats->async_us_req_queue);
		}
		return 0;
	}

	if (ioctl(dpa_stats_devfd, DPA_STATS_IOC_GET_COUNTERS, &ioc_prm) < 0) {
		error(0, errno, "Could not create request\n");
		ret = -errno;
	}

	/* Provide to the user the number of written bytes */
	*cnts_len = ioc_prm.cnts_len;

	if (!request_done) {
		if (req->type == MIXED_CNTS) {
			ret = treat_mixed_cnts_request(dpa_stats, req);
			if (ret < 0)
				return ret;
		}

		free(req->cnt_off);
		req->cnt_off = NULL;
		ret = fifo_add(&dpa_stats->req_queue, req);
	}

	return ret;
}

int dpa_stats_reset_counters(int *cnts_ids, unsigned int cnts_ids_len)
{
	struct ioc_dpa_stats_cnts_reset_params ioc_prm;
	struct dpa_stats *dpa_stats = NULL;
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	uint32_t i, j;
	int ret;

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -EAGAIN;
	}

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return -EINVAL;
	}
	dpa_stats = gbl_dpa_stats;

	ioc_prm.cnts_ids = cnts_ids;
	ioc_prm.cnts_ids_len = cnts_ids_len;

	if (ioctl(dpa_stats_devfd,
		  DPA_STATS_IOC_RESET_COUNTERS, &ioc_prm) < 0) {
		error(0, errno, "Could not reset counters\n");
		return -errno;
	}

	ret = block_sched_cnts(dpa_stats, cnts_ids, cnts_ids_len);
	if (ret < 0)
		return ret;

	/* Reset stored statistics for all 'user-space' counters */
	for (i = 0; i < ioc_prm.cnts_ids_len; i++) {
		cnt_cb = &dpa_stats->cnts_cb[cnts_ids[i]];
		/* Acquire counter lock */
		ret = pthread_mutex_trylock(&cnt_cb->lock);
		if (ret) {
			int err;

			error(0, ret, "Counter id (cnt_ids[%d]) %d is in use\n",
				i, cnts_ids[i]);
			err = unblock_sched_cnts(dpa_stats,
					   cnts_ids, cnts_ids_len);
			if (err < 0)
				return err;
			return ret;
		}

		if (cnt_cb->id == DPA_OFFLD_INVALID_OBJECT_ID) {
			ret = pthread_mutex_unlock(&cnt_cb->lock);
			if (ret)
				return ret;
			continue;
		}
		/* Reset stored statistics values */
		for (j = 0; j < cnt_cb->members_num; j++)
			memset(cnt_cb->info.stats[j], 0,
				cnt_cb->info.stats_num * sizeof(uint64_t));
		ret = pthread_mutex_unlock(&cnt_cb->lock);
		if (ret)
			return ret;
	}
	return unblock_sched_cnts(dpa_stats, cnts_ids, cnts_ids_len);
}

void *dpa_stats_event_thread(void *arg)
{
	char buffer[NUM_EVENTS_IN_READ * sizeof(struct dpa_stats_event_params)];
	struct dpa_stats_event_params   *event_prm  = NULL;
	ssize_t buff_sz = 0;
	int err;

	/*
	* Read NUM_EVENTS_IN_READ from the advanced config interface.
	* This call is blocking and will put the thread to sleep if
	* there are no events available. It will return one or more
	* events if there are available.
	*/
	do {
		buff_sz = read(dpa_stats_devfd, buffer, (NUM_EVENTS_IN_READ *
				sizeof(*event_prm)));

		if (buff_sz < 0) {
			error(0, EINVAL, "Could not read information from "
				"buffer\n");
			return NULL;
		}
		event_prm  = (struct dpa_stats_event_params *)buffer;

		/* Dispatch events */
		while (buff_sz >= sizeof(struct dpa_stats_event_params)) {
			err = process_async_req(event_prm);
			if (err < 0) {
				error(0, EINVAL, "Could not find and process "
					"asynchronous request\n");
				return NULL;
			}
			event_prm++;
			buff_sz -= sizeof(struct dpa_stats_event_params);
		}
	} while (1);
}

void us_req_queue_busy(const struct fifo_q *q)
{
	pthread_attr_t worker_thread_attributes;
	struct us_thread_data *new_us_thread;
	int ret;

	ret = pthread_mutex_lock(&us_thread_list_access);
	if (ret)
		error(0, ret,
			"Failed to acquire US worker threads counter lock");

	/* If we can still create worker threads... */
	if (us_threads >= MAX_NUM_OF_THREADS) {
		ret = pthread_mutex_unlock(&us_thread_list_access);
		if (ret)
			error(0, ret,
				"Failed to release US worker threads counter lock");
		return;
	}

	/* Create a new worker thread */
	new_us_thread = list_entry(us_thread_list.next,
			struct us_thread_data, node);
	list_del(&new_us_thread->node);

	us_threads++;
	if ((us_threads <= 1) && (us_main_thread)) {
		/*
		 * The first/last worker thread never dies. It is only put to
		 * sleep waiting for requests to arrive in the queue, so just
		 * wake it up.
		 */
		pthread_cond_signal(&us_main_thread_wake_up);
	} else {
		/* Set worker thread as "detached". */
		pthread_attr_init(&worker_thread_attributes);
		pthread_attr_setdetachstate(&worker_thread_attributes,
				PTHREAD_CREATE_DETACHED);
		ret = pthread_create(&new_us_thread->id,
			&worker_thread_attributes,
			dpa_stats_worker_thread,
			new_us_thread);
		if (ret != 0) {
			int err = pthread_mutex_unlock(&us_thread_list_access);
			if (err)
				error(0, err,
					"Failed to release US worker threads counter lock");
			error(0, ret, "Failed to create new worker thread");
			return;
		}
	}
	us_main_thread = true;
	ret = pthread_mutex_unlock(&us_thread_list_access);
	if (ret)
		error(0, ret,
			"Failed to release US worker threads counter lock");
}

void *dpa_stats_worker_thread(void *arg)
{
	struct us_thread_data *this_thread = (struct us_thread_data *)arg;
	struct dpa_stats *dpa_stats;
	struct dpa_stats_req *req;
	cpu_set_t cpuset;
	int ret;
	int cpu = 0;

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return NULL;
	}
	dpa_stats = gbl_dpa_stats;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);

	ret = pthread_setaffinity_np(
			this_thread->id, sizeof(cpu_set_t), &cpuset);
	if (ret) {
		error(0, ret, "(%d): Fail: pthread_setaffinity_np()\n", cpu);
		return NULL;
	}

	ret = qman_thread_init();
	if (ret) {
		error(0, ret, "(%d): Fail: qman_thread_init()\n", cpu);
		return NULL;
	}

	/*
	 * This lock is necessary to balance the "unlock" from the "while"
	 * loop.
	 */
	ret = pthread_mutex_lock(&us_thread_list_access);
	if (ret) {
		error(0, ret,
			"Failed to lock the number of available US threads");
		return NULL;
	}
	do {
		ret = pthread_mutex_unlock(&us_thread_list_access);
		if (ret) {
			error(0, ret,
				"Failed to release US thread number lock\n");
			return NULL;
		}
		while ((req = (struct dpa_stats_req *)
			fifo_try_get(&dpa_stats->async_us_req_queue)) != NULL) {

			if (req->type == US_CNTS_ONLY)
				/* Treat every counter from the request */
				ret = treat_us_cnts_request(dpa_stats, req);
			else
				/* Treat only user-space counters */
				ret = treat_mixed_cnts_request(dpa_stats, req);
			if (ret < 0) {
				error(0, EINVAL, "Cannot obtain counter values "
					"in asynchronous mode\n");
				req->bytes_num = ret;
			}

			/* Call user-provided callback */
			req->request_done(0,
				req->config.storage_area_offset,
				req->cnts_num,
				req->bytes_num);

			/* Return the asynchronous request in the pool */
			free(req->cnt_off);
			free(req->cnt_ids);
			req->cnt_off = NULL;
			req->cnt_ids = NULL;
			ret = fifo_add(&dpa_stats->req_queue, req);
			if (ret) {
				error(0, -ret,
					"Failed to recycle stats request\n");
				return NULL;
			}
		}

		ret = pthread_mutex_lock(&us_thread_list_access);
		if (ret) {
			error(0, ret,
				"Failed to lock the number of available US threads");
			return NULL;
		}

		/*
		 * If this is the last worker thread alive, sleep until new work
		 * arrives
		 */
		if (us_threads <= 1) {
			us_threads--;
			list_add(&this_thread->node, &us_thread_list);
			ret = pthread_cond_wait(&us_main_thread_wake_up,
				&us_thread_list_access);
			if (ret) {
				error(0, ret, "Failed to wait for new work");
				return NULL;
			}
		}
	}
	while ((us_threads <= 1) && (!dpa_stats_shutdown));

	ret = qman_thread_finish();
	if (ret)
		error(0, ret, "Failed to shut down QMan thread");

	us_threads--;
	list_add(&this_thread->node, &us_thread_list);
	ret = pthread_mutex_unlock(&us_thread_list_access);
	if (ret) {
		error(0, ret, "Failed to release US thread number lock\n");
		return NULL;
	}

	pthread_exit(NULL);

	return NULL;
}
