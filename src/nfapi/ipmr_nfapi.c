/* Copyright (c) 2014 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
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

#include <stdint.h>

#include <fsl_fman.h>
#include <mem_cache.h>
#include <usdpaa_netcfg.h>

#include "init_nfapi.h"
#include "ipmr_nfapi.h"

int get_shmac_tx(char *ifname)
{
	int i;
	struct fm_eth_port_cfg *port_cfg;
	struct net_if *_if;

	for (i = 0; i < gbl_init->netcfg->num_ethports; i++) {
		port_cfg = &gbl_init->netcfg->port_cfg[i];
		if (strcmp(port_cfg->fman_if->shared_mac_info.shared_mac_name,
			   ifname))
			continue;

		list_for_each_entry(_if, &gbl_init->ifs, node) {
			if (_if->cfg->fman_if == port_cfg->fman_if)
				return qman_fq_fqid(_if->tx_fqs);
		}
	}
	return 0;
}

/*
 * set enqueue action for the entry in the group interface ccnode, towards
 * the interface's Rx fqid
 */
int set_action(int iif,  struct dpa_cls_tbl_action *act)
{
	int i;
	char ifname[IFNAMSIZ];
	struct fm_eth_port_cfg *port_cfg;
	uint32_t rx_def = 0;

	memset(act, 0, sizeof(*act));
	act->enable_statistics = false;
	act->enq_params.hmd = DPA_OFFLD_INVALID_OBJECT_ID;
	act->type = DPA_CLS_TBL_ACTION_ENQ;
	act->enq_params.override_fqid = true;

	if (!gbl_init->netcfg)
		return -EINVAL;

	if(!if_indextoname(iif, ifname))
		return -ENXIO;

	for (i = 0; i < gbl_init->netcfg->num_ethports; i++) {
		port_cfg = &gbl_init->netcfg->port_cfg[i];
		if (!strcmp(port_cfg->fman_if->shared_mac_info.shared_mac_name,
			    ifname)) {
			rx_def = port_cfg->fman_if->fqid_rx_def;
			break;
		}
	}

	if (!rx_def)
		return -EINVAL;

	act->enq_params.new_fqid = rx_def;
	return 0;
}

void nfapi_group_free(struct nfapi_grp_iif_t *group,
		      struct nfapi_grp_iif_table_t *gt)
{
	mem_cache_free(gt->free_entries, group);
	return;
}

int nfapi_group_table_init(struct nfapi_grp_iif_table_t *table)
{

	struct nfapi_grp_iif_bucket_t *bucket;
	uint32_t entries;
	int i;

	memset(table, 0, sizeof(struct nfapi_grp_iif_table_t));
	table->free_entries =
		mem_cache_create(sizeof(struct nfapi_grp_iif_t),
				 GROUP_POOL_SIZE);

	if (unlikely(table->free_entries == NULL))
		return -ENOMEM;

	entries = mem_cache_refill(table->free_entries, GROUP_POOL_SIZE);
	if (unlikely(entries != GROUP_POOL_SIZE))
		return -ENOMEM;

	for (i = 0; i < GROUP_TABLE_BUCKETS; i++) {
		bucket = table->buckets + i;
		bucket->head = NULL;
		bucket->id = i;
	}
	INIT_LIST_HEAD(&table->iif_group_list);

	return 0;
}

struct nfapi_grp_iif_t *nfapi_group_create(struct nfapi_grp_iif_table_t *table)
{
	struct nfapi_grp_iif_t *iif_group;
	if (!table)
		return NULL;

	iif_group = mem_cache_alloc(table->free_entries);

	return iif_group;

}

static inline uint32_t compute_hash(const void *key, uint32_t key_len,
				   uint32_t mask)
{
	uint64_t result;

	result = fman_crc64_init();
	result = fman_crc64_update(result, (void *)key, key_len);
	result = fman_crc64_finish(result);
	return ((uint32_t) result) & mask;
}


static struct nfapi_grp_iif_bucket_t
*__group_find_bucket(struct nfapi_grp_iif_table_t *gt,
		     const uint32_t *key, uint32_t keylen)
{
	uint32_t hash;
	if (!gt)
		return NULL;

	hash = compute_hash(key, keylen, GROUP_HASH_MASK);
	if (unlikely(hash >= GROUP_TABLE_BUCKETS))
		return NULL;
	return &(gt->buckets[hash]);
}

static struct nfapi_grp_iif_t **__group_find(
			struct nfapi_grp_iif_bucket_t *bucket,
			const uint32_t *key, uint32_t keylen)
{
	struct nfapi_grp_iif_t **gptr;
	struct nfapi_grp_iif_t *g;
	uint32_t group_key[5];
	int idx;

	gptr = &(bucket->head);
	if (unlikely(gptr == NULL))
		return NULL;
	g = *gptr;
	memset(group_key, 0, sizeof(group_key));
	while (g != NULL) {
		memcpy(group_key, g->addr, g->group_tbl->addr_len);
		idx = (g->group_tbl->addr_len / sizeof(group_key[0]));
		memcpy(group_key + idx, &g->ifid, sizeof(g->ifid));
		if (!memcmp(group_key, key, keylen))
			break;
		else
			gptr = &(g->next);
		g = *gptr;
	}

	return gptr;
}

static bool __group_delete(struct nfapi_grp_iif_table_t *gt,
			   struct nfapi_grp_iif_t **gptr)
{
	struct nfapi_grp_iif_t *g;

	if (!gt)
		return false;

	g = *gptr;
	if (g != NULL) {
		*gptr = g->next;
		nfapi_group_free(g, gt);
	}
	return (g != NULL);
}

static bool __group_add(struct nfapi_grp_iif_table_t *gt,
			struct nfapi_grp_iif_t **cur_ptr,
			struct nfapi_grp_iif_t *new_g, bool replace)
{
	struct nfapi_grp_iif_t *current;
	uint32_t count;

	if (!gt)
		return false;

	count = gt->entries + 1;
	current = *cur_ptr;
	/* If there is an existing n, replace it */
	if (current != NULL) {
		if (replace == true) {
			new_g->next = current->next;
			if (false == __group_delete(gt, cur_ptr))
				return false;
		} else {
			return false;
		}
	} else {
		/* If there is not an existing n, check if there is room */
		if (likely(count < GROUP_TABLE_MAX_ENTRIES)) {
			(gt->entries)++;
			new_g->next = NULL;
		} else {
			return false;
		}
	}
	*cur_ptr = new_g;
	return true;
}

static struct nfapi_grp_iif_t *__group_lookup(
		struct nfapi_grp_iif_bucket_t *bucket,
		const uint32_t *key, uint32_t keylen)
{
	struct nfapi_grp_iif_t *group;
	struct nfapi_grp_iif_t **cur_ptr;

	cur_ptr = __group_find(bucket, key, keylen);
	if (unlikely(cur_ptr == NULL))
		return NULL;

	group = *cur_ptr;
	return group;
}


bool nfapi_group_add(struct nfapi_grp_iif_table_t *gt,
		   struct nfapi_grp_iif_t *new_g)
{
	struct nfapi_grp_iif_bucket_t *bucket;
	struct nfapi_grp_iif_t **cur_ptr;
	uint32_t group_key[5];
	bool retval;
	int idx;

	if (!gt)
		return false;

	memset(group_key, 0, sizeof(group_key));
	memcpy(group_key, new_g->addr, gt->addr_len);
	idx = (gt->addr_len / sizeof(group_key[0]));
	memcpy(group_key + idx, &new_g->ifid, sizeof(new_g->ifid));

	bucket = __group_find_bucket(gt, group_key, sizeof(group_key));

	if (unlikely(bucket == NULL))
		return false;

	cur_ptr = __group_find(bucket, group_key, sizeof(group_key));
	if (unlikely(cur_ptr == NULL))
		return false;

	retval = __group_add(gt, cur_ptr, new_g, false);
	return retval;
}

bool nfapi_group_remove(struct nfapi_grp_iif_table_t *gt,
			uint32_t *key,
			uint32_t keylen)
{
	struct nfapi_grp_iif_bucket_t *bucket;
	struct nfapi_grp_iif_t **cur_ptr;
	bool retval;

	if (!gt)
		return false;

	bucket = __group_find_bucket(gt, key, keylen);
	if (unlikely(bucket == NULL))
		return false;

	cur_ptr = __group_find(bucket, key, keylen);
	if (unlikely(cur_ptr == NULL))
		return false;

	retval = __group_delete(gt, cur_ptr);
	return retval;

}

struct nfapi_grp_iif_t *nfapi_group_lookup(struct nfapi_grp_iif_table_t *grt,
					const uint32_t *key,
					uint32_t keylen)
{
	struct nfapi_grp_iif_bucket_t *bucket;
	struct nfapi_grp_iif_t *group;

	if (!grt)
		return NULL;

	bucket = __group_find_bucket(grt, key, keylen);
	if (unlikely(bucket == NULL))
		return NULL;

	group = __group_lookup(bucket, key, keylen);
	return group;
}

int nfapi_mrt_init(struct nfapi_mr_table_t *table)
{
	struct nfapi_mfc_bucket_t *bucket;
	uint32_t entries;
	int i;

	memset(table, 0, sizeof(struct nfapi_mr_table_t));
	table->free_entries =
		mem_cache_create(sizeof(struct nfapi_mfc_t),
				 MFC_POOL_SIZE);

	if (unlikely(table->free_entries == NULL))
		return -ENOMEM;

	entries = mem_cache_refill(table->free_entries, MFC_POOL_SIZE);
	if (unlikely(entries != MFC_POOL_SIZE))
		return -ENOMEM;

	for (i = 0; i < MFC_TABLE_BUCKETS; i++) {
		bucket = table->buckets + i;
		bucket->head = NULL;
		bucket->id = i;
	}

	INIT_LIST_HEAD(&table->vif_list);
	INIT_LIST_HEAD(&table->mfc_list);

	for(i = 0; i < NF_IP4_MCFWD_MAX_VIFS; i++)
		INIT_LIST_HEAD(&table->vif_table[i].mr_list);

	return 0;
}

struct nfapi_mfc_t *nfapi_mfc_create(struct nfapi_mr_table_t *mt)
{
	struct nfapi_mfc_t *new_mfc;
	if (!mt)
		return NULL;

	new_mfc = mem_cache_alloc(mt->free_entries);

	return new_mfc;
}

struct nfapi_mfc_bucket_t *__mfc_find_bucket(struct nfapi_mr_table_t *mt,
					   const uint32_t *key, uint32_t keylen)
{
	uint32_t hash;
	if (!mt)
		return NULL;

	hash = compute_hash(key, keylen, MFC_HASH_MASK);
	if (unlikely(hash >= MFC_TABLE_BUCKETS))
		return NULL;

	return &(mt->buckets[hash]);
}

static struct nfapi_mfc_t **__mfc_find(
			struct nfapi_mfc_bucket_t *bucket,
			const uint32_t *key, uint32_t keylen)
{
	struct nfapi_mfc_t **mptr;
	struct nfapi_mfc_t *m;
	uint32_t rt_key[8];
	int idx;

	mptr = &(bucket->head);
	if (unlikely(mptr == NULL))
		return NULL;

	m = *mptr;
	memset(rt_key, 0, sizeof(rt_key));
	while (m != NULL) {
		memcpy(rt_key, m->mfc_origin, m->mrt->addr_len);
		idx = (m->mrt->addr_len / sizeof(rt_key[0]));
		memcpy(rt_key + idx, &m->mfc_mcastgrp, m->mrt->addr_len);
		if (!memcmp(rt_key, key, keylen))
			break;
		else
			mptr = &(m->next);
		m = *mptr;
	}

	return mptr;
}

static struct nfapi_mfc_t *__mfc_lookup(
		struct nfapi_mfc_bucket_t *bucket,
		const uint32_t *key, uint32_t keylen)
{
	struct nfapi_mfc_t *mfc;
	struct nfapi_mfc_t **cur_ptr;

	cur_ptr = __mfc_find(bucket, key, keylen);
	if (unlikely(cur_ptr == NULL))
		return NULL;

	mfc = *cur_ptr;
	return mfc;
}


struct nfapi_mfc_t *nfapi_mfc_lookup(struct nfapi_mr_table_t *mt,
				     const uint32_t *key,
				     uint32_t keylen)
{
	struct nfapi_mfc_bucket_t *bucket;
	struct nfapi_mfc_t *mfc;

	if (!mt)
		return NULL;

	bucket = __mfc_find_bucket(mt, key, keylen);
	if (unlikely(bucket == NULL))
		return NULL;

	mfc = __mfc_lookup(bucket, key, keylen);
	return mfc;
}

void nfapi_mfc_free(struct nfapi_mfc_t *mfc,
		      struct nfapi_mr_table_t *mt)
{
	mem_cache_free(mt->free_entries, mfc);
	return;
}

static bool __mfc_delete(struct nfapi_mr_table_t *mt,
			   struct nfapi_mfc_t **mptr)
{
	struct nfapi_mfc_t *m;

	if (!mt)
		return false;

	m = *mptr;
	if (m != NULL) {
		*mptr = m->next;
		nfapi_mfc_free(m, mt);
	}
	return (m != NULL);
}

static bool __mfc_add(struct nfapi_mr_table_t *mt,
		      struct nfapi_mfc_t **cur_ptr,
		      struct nfapi_mfc_t *new_m, bool replace)
{
	struct nfapi_mfc_t *current;
	uint32_t count;

	if (!mt)
		return false;

	count = mt->entries + 1;
	current = *cur_ptr;
	/* If there is an existing n, replace it */
	if (current != NULL) {
		if (replace == true) {
			new_m->next = current->next;
			if (false == __mfc_delete(mt, cur_ptr))
				return false;
		} else {
			return false;
		}
	} else {
		/* If there is not an existing n, check if there is room */
		if (likely(count < MFC_TABLE_MAX_ENTRIES)) {
			(mt->entries)++;
			new_m->next = NULL;
		} else {
			return false;
		}
	}
	*cur_ptr = new_m;
	return true;
}

bool nfapi_mfc_add(struct nfapi_mr_table_t *mt, struct nfapi_mfc_t *new_res)
{
	struct nfapi_mfc_bucket_t *bucket;
	struct nfapi_mfc_t **cur_ptr;
	uint32_t key[8];
	bool retval;
	int idx;

	if (!mt)
		return false;

	memset(key, 0, sizeof(key));
	memcpy(key, new_res->mfc_origin, mt->addr_len);
	idx = (mt->addr_len / sizeof(key[0]));
	memcpy(key + idx, &new_res->mfc_mcastgrp, mt->addr_len);

	bucket = __mfc_find_bucket(mt, key, sizeof(key));

	if (unlikely(bucket == NULL))
		return false;

	cur_ptr = __mfc_find(bucket, key, sizeof(key));
	if (unlikely(cur_ptr == NULL))
		return false;

	retval = __mfc_add(mt, cur_ptr, new_res, false);
	return retval;
}

bool nfapi_mfc_remove(struct nfapi_mr_table_t *mt, uint32_t *key,
		      uint32_t keylen)
{
	struct nfapi_mfc_bucket_t *bucket;
	struct nfapi_mfc_t **cur_ptr;
	bool retval;

	if (!mt)
		return false;

	bucket = __mfc_find_bucket(mt, key, keylen);
	if (unlikely(bucket == NULL))
		return false;

	cur_ptr = __mfc_find(bucket, key, keylen);
	if (unlikely(cur_ptr == NULL))
		return false;

	retval = __mfc_delete(mt, cur_ptr);
	return retval;
}

int nfapi_manip_init(struct nfapi_fwd_manip_table_t *table)
{
	struct nfapi_fwd_manip_bucket_t *bucket;
	uint32_t entries;
	int i;

	memset(table, 0, sizeof(struct nfapi_fwd_manip_table_t));
	table->free_entries =
		mem_cache_create(sizeof(struct nfapi_fwd_manip_t),
				 MANIP_POOL_SIZE);

	if (unlikely(table->free_entries == NULL))
		return -ENOMEM;

	entries = mem_cache_refill(table->free_entries, MANIP_POOL_SIZE);
	if (unlikely(entries != MANIP_POOL_SIZE))
		return -ENOMEM;

	for (i = 0; i < MANIP_TABLE_BUCKETS; i++) {
		bucket = table->buckets + i;
		bucket->head = NULL;
		bucket->id = i;
	}

	return 0;
}

struct nfapi_fwd_manip_t *nfapi_manip_create(struct nfapi_fwd_manip_table_t *mt)
{
	struct nfapi_fwd_manip_t *new_me;
	if (!mt)
		return NULL;

	new_me = mem_cache_alloc(mt->free_entries);

	return new_me;
}

struct nfapi_fwd_manip_bucket_t *__manip_find_bucket(
		struct nfapi_fwd_manip_table_t *mt,
		const uint32_t *key, uint32_t keylen)
{
	uint32_t hash;
	if (!mt)
		return NULL;

	hash = compute_hash(key, keylen, MANIP_HASH_MASK);
	if (unlikely(hash >= MANIP_TABLE_BUCKETS))
		return NULL;

	return &(mt->buckets[hash]);
}

static struct nfapi_fwd_manip_t **__manip_find(
			struct nfapi_fwd_manip_bucket_t *bucket,
			const uint32_t *key, uint32_t keylen)
{
	struct nfapi_fwd_manip_t **mptr;
	struct nfapi_fwd_manip_t *m;
	uint32_t rt_key[5];

	mptr = &(bucket->head);
	if (unlikely(mptr == NULL))
		return NULL;

	m = *mptr;
	memset(rt_key, 0, sizeof(rt_key));
	while (m != NULL) {
		memcpy(rt_key, &m->link, sizeof(m->link));
		memcpy(rt_key + 1, &m->mcastgrp, m->manip_table->addr_len);
		if (!memcmp(rt_key, key, keylen))
			break;
		else
			mptr = &(m->next);
		m = *mptr;
	}

	return mptr;
}

static struct nfapi_fwd_manip_t *__manip_lookup(
		struct nfapi_fwd_manip_bucket_t *bucket,
		const uint32_t *key, uint32_t keylen)
{
	struct nfapi_fwd_manip_t *m;
	struct nfapi_fwd_manip_t **cur_ptr;

	cur_ptr = __manip_find(bucket, key, keylen);
	if (unlikely(cur_ptr == NULL))
		return NULL;

	m = *cur_ptr;
	return m;
}


struct nfapi_fwd_manip_t *nfapi_manip_lookup(struct nfapi_fwd_manip_table_t *mt,
				     const uint32_t *key,
				     uint32_t keylen)
{
	struct nfapi_fwd_manip_bucket_t *bucket;
	struct nfapi_fwd_manip_t *m;

	if (!mt)
		return NULL;

	bucket = __manip_find_bucket(mt, key, keylen);
	if (unlikely(bucket == NULL))
		return NULL;

	m = __manip_lookup(bucket, key, keylen);
	return m;
}

void nfapi_manip_free(struct nfapi_fwd_manip_t *m,
		      struct nfapi_fwd_manip_table_t *mt)
{
	mem_cache_free(mt->free_entries, m);
	return;
}

static bool __manip_delete(struct nfapi_fwd_manip_table_t *mt,
			   struct nfapi_fwd_manip_t **mptr)
{
	struct nfapi_fwd_manip_t *m;

	if (!mt)
		return false;

	m = *mptr;
	if (m != NULL) {
		*mptr = m->next;
		nfapi_manip_free(m, mt);
	}
	return (m != NULL);
}

static bool __manip_add(struct nfapi_fwd_manip_table_t *mt,
		      struct nfapi_fwd_manip_t **cur_ptr,
		      struct nfapi_fwd_manip_t *new_m, bool replace)
{
	struct nfapi_fwd_manip_t *current;
	uint32_t count;

	if (!mt)
		return false;

	count = mt->entries + 1;
	current = *cur_ptr;
	/* If there is an existing n, replace it */
	if (current != NULL) {
		if (replace == true) {
			new_m->next = current->next;
			if (false == __manip_delete(mt, cur_ptr))
				return false;
		} else {
			return false;
		}
	} else {
		/* If there is not an existing n, check if there is room */
		if (likely(count < MANIP_TABLE_MAX_ENTRIES)) {
			(mt->entries)++;
			new_m->next = NULL;
		} else {
			return false;
		}
	}
	*cur_ptr = new_m;
	return true;
}

bool nfapi_manip_add(struct nfapi_fwd_manip_table_t *mt,
		     struct nfapi_fwd_manip_t *new_res)
{
	struct nfapi_fwd_manip_bucket_t *bucket;
	struct nfapi_fwd_manip_t **cur_ptr;
	uint32_t key[5];
	bool retval;

	if (!mt)
		return false;

	memset(key, 0, sizeof(key));
	memcpy(key, &new_res->link, sizeof(new_res->link));
	memcpy(key + 1, &new_res->mcastgrp, mt->addr_len);

	bucket = __manip_find_bucket(mt, key, sizeof(key));

	if (unlikely(bucket == NULL))
		return false;

	cur_ptr = __manip_find(bucket, key, sizeof(key));
	if (unlikely(cur_ptr == NULL))
		return false;

	retval = __manip_add(mt, cur_ptr, new_res, false);
	return retval;
}

bool nfapi_manip_remove(struct nfapi_fwd_manip_table_t *mt, uint32_t *key,
		      uint32_t keylen)
{
	struct nfapi_fwd_manip_bucket_t *bucket;
	struct nfapi_fwd_manip_t **cur_ptr;
	bool retval;

	if (!mt)
		return false;

	bucket = __manip_find_bucket(mt, key, keylen);
	if (unlikely(bucket == NULL))
		return false;

	cur_ptr = __manip_find(bucket, key, keylen);
	if (unlikely(cur_ptr == NULL))
		return false;

	retval = __manip_delete(mt, cur_ptr);
	return retval;
}

