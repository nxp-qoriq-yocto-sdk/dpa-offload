/* Copyright (c) 2015 Freescale Semiconductor, Inc.
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

#include <mem_cache.h>

#include "fsl_dpa_offload.h"
#include "fsl_dpa_classifier.h"

#include "ipfwd.h"
#include "fib_nfapi.h"
#include "rule_nfapi.h"
#include "ipmr_nfapi.h"

int nfapi_neigh_table_init(struct nfapi_neigh_table_t *table)
{
	struct nfapi_neigh_bucket_t *bucket;
	uint32_t entries;
	int i;

	table->free_entries =
		mem_cache_create(sizeof(struct nfapi_neigh_t),
				 NEIGH_POOL_SIZE);

	if (unlikely(table->free_entries == NULL))
		return -ENOMEM;

	table->rt_free_entries =
		mem_cache_create(sizeof(struct nfapi_rt_id),
				 RT_POOL_SIZE);
	if (unlikely(table->rt_free_entries == NULL))
		return -ENOMEM;

	entries = mem_cache_refill(table->free_entries, NEIGH_POOL_SIZE);
	if (unlikely(entries != NEIGH_POOL_SIZE))
		return -ENOMEM;

	entries = mem_cache_refill(table->rt_free_entries, RT_POOL_SIZE);
	if (unlikely(entries != RT_POOL_SIZE))
		return -ENOMEM;

	table->rt_entries = 0;
	table->entries = 0;
	for (i = 0; i < NEIGH_TABLE_BUCKETS; i++) {
		bucket = table->buckets + i;
		bucket->head = NULL;
		bucket->id = i;
	}

	INIT_LIST_HEAD(&table->neigh_list);

	return 0;
}

struct nfapi_neigh_t *nfapi_neigh_create(struct nfapi_neigh_table_t *nt)
{
	struct nfapi_neigh_t *neigh;
	if (!nt)
		return NULL;

	neigh = mem_cache_alloc(nt->free_entries);
	return neigh;
}

struct nfapi_neigh_t *nfapi_neigh_init(struct nfapi_neigh_table_t *nt,
				       struct nfapi_neigh_t *n,
				       uint32_t *key)
{
	if (!nt)
		return NULL;

	n->next = NULL;
	n->nt = nt;
	memcpy(n->ip_address, key, nt->proto_len);
	key += (nt->proto_len / sizeof(key[0]));
	memcpy(&n->ifid, key, sizeof(n->ifid));
	memset(n->hmd, DPA_OFFLD_INVALID_OBJECT_ID, sizeof(n->hmd));
	n->tx_fqid = 0;
	n->rt_list_head = NULL;
	n->rt_list_tail = NULL;
	n->refcnt = 0;
	return n;
}

static struct nfapi_neigh_bucket_t
*__neigh_find_bucket(struct nfapi_neigh_table_t *nt,
		     const uint32_t *key, uint32_t keylen)
{
	uint32_t hash;
	if (!nt)
		return NULL;

	hash = compute_neigh_hash(key, keylen);
	if (unlikely(hash >= NEIGH_TABLE_BUCKETS))
		return NULL;
	return &(nt->buckets[hash]);
}


static struct nfapi_neigh_t **__neigh_find(struct nfapi_neigh_bucket_t *bucket,
				           const uint32_t *key, uint32_t keylen)
{
	struct nfapi_neigh_t **nptr;
	struct nfapi_neigh_t *n;
	uint32_t neigh_key[5];
	int idx;

	nptr = &(bucket->head);
	if (unlikely(nptr == NULL))
		return NULL;
	n = *nptr;
	memset(neigh_key, 0, sizeof(neigh_key));
	while (n != NULL) {
		memcpy(neigh_key, n->ip_address, n->nt->proto_len);
		idx = (n->nt->proto_len / sizeof(neigh_key[0]));
		memcpy(neigh_key + idx, &n->ifid, sizeof(n->ifid));
		if (!memcmp(neigh_key, key, keylen))
			break;
		else
			nptr = &(n->next);
		n = *nptr;
	}

	return nptr;
}

void neigh_free(struct nfapi_neigh_t *n,
		struct nfapi_neigh_table_t *nt)
{
	mem_cache_free(nt->free_entries, n);
}

static bool __neigh_delete(struct nfapi_neigh_table_t *nt,
			   struct nfapi_neigh_t **nptr)
{
	struct nfapi_neigh_t *n;

	if (!nt)
		return false;
	n = *nptr;
	if (n != NULL) {
		*nptr = n->next;
		neigh_free(n, nt);
	}
	return (n != NULL);
}

static bool __neigh_add(struct nfapi_neigh_table_t *nt,
			struct nfapi_neigh_t **cur_ptr,
			struct nfapi_neigh_t *new_n, bool replace)
{
	struct nfapi_neigh_t *current;
	uint32_t count;

	if (!nt)
		return false;

	count = nt->entries + 1;
	current = *cur_ptr;
	/* If there is an existing n, replace it */
	if (current != NULL) {
		if (replace == true) {
			new_n->next = current->next;
			if (false == __neigh_delete(nt, cur_ptr))
				return false;
		} else {
			return false;
		}
	} else {
		/* If there is not an existing n, check if there is room */
		if (likely(count < NEIGH_TABLE_MAX_ENTRIES)) {
			(nt->entries)++;
			new_n->next = NULL;
		} else {
			return false;
		}
	}
	*cur_ptr = new_n;
	return true;
}

static struct nfapi_neigh_t *__neigh_lookup(struct nfapi_neigh_bucket_t *bucket,
				      const uint32_t *key, uint32_t keylen)
{
	struct nfapi_neigh_t *n;
	struct nfapi_neigh_t **cur_ptr;

	cur_ptr = __neigh_find(bucket, key, keylen);
	if (unlikely(cur_ptr == NULL))
		return NULL;
	n = *cur_ptr;
	return n;
}

bool nfapi_neigh_add(struct nfapi_neigh_table_t *nt,
		     struct nfapi_neigh_t *new_n)
{
	struct nfapi_neigh_bucket_t *bucket;
	struct nfapi_neigh_t **cur_ptr;
	bool retval;
	uint32_t neigh_key[5];
	int idx;

	if (!nt)
		return false;

	memset(neigh_key, 0, sizeof(neigh_key));
	memcpy(neigh_key, new_n->ip_address, nt->proto_len);
	idx = (nt->proto_len / sizeof(neigh_key[0]));
	memcpy(neigh_key + idx, &new_n->ifid, sizeof(new_n->ifid));
	bucket = __neigh_find_bucket(nt, neigh_key, sizeof(neigh_key));

	if (unlikely(bucket == NULL))
		return false;

	cur_ptr = __neigh_find(bucket, neigh_key, sizeof(neigh_key));
	if (unlikely(cur_ptr == NULL))
		return false;

	retval = __neigh_add(nt, cur_ptr, new_n, false);
	return retval;
}

bool nfapi_neigh_remove(struct nfapi_neigh_table_t *nt,
			uint32_t *key, uint32_t keylen)
{
	struct nfapi_neigh_bucket_t *bucket;
	struct nfapi_neigh_t **cur_ptr;
	bool retval;

	if (!nt)
		return NULL;
	bucket = __neigh_find_bucket(nt, key, keylen);
	if (unlikely(bucket == NULL))
		return false;
	cur_ptr = __neigh_find(bucket, key, keylen);
	if (unlikely(cur_ptr == NULL))
		return false;
	retval = __neigh_delete(nt, cur_ptr);
	return retval;
}

struct nfapi_neigh_t *nfapi_neigh_lookup(struct nfapi_neigh_table_t *nt,
					 const uint32_t *key,
					 uint32_t keylen)
{
	struct nfapi_neigh_bucket_t *bucket;
	struct nfapi_neigh_t *n;

	if (!nt)
		return NULL;
	bucket = __neigh_find_bucket(nt, key, keylen);
	if (unlikely(bucket == NULL))
		return NULL;
	n = __neigh_lookup(bucket, key, keylen);
	return n;
}
