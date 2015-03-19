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

#include <mem_cache.h>

#include "fib_nfapi.h"

int nfapi_fib_hash_table_init(struct nfapi_fib_hash_table_t *table)
{

	struct nfapi_hash_bucket_t *bucket;
	uint32_t entries;
	int i;

	table->free_entries =
		mem_cache_create(sizeof(struct nfapi_fib_table_t),
				FIB_TABLE_POOL_SIZE);

	if (unlikely(table->free_entries == NULL))
		return -ENOMEM;

	entries = mem_cache_refill(table->free_entries, FIB_TABLE_POOL_SIZE);
	if (unlikely(entries != FIB_TABLE_POOL_SIZE))
		return -ENOMEM;

	for (i = 0; i < HASH_TABLE_BUCKETS; i++) {
		bucket = table->buckets + i;
		bucket->head = NULL;
		bucket->id = i;
	}
	return 0;
}

struct nfapi_fib_table_t *nfapi_fib_table_create(
				struct nfapi_fib_hash_table_t *hash_tbl)
{
	struct nfapi_fib_table_t *fib_table;
	if (!hash_tbl)
		return NULL;

	fib_table = mem_cache_alloc(hash_tbl->free_entries);

	return fib_table;
}

struct nfapi_fib_table_t *nfapi_fib_table_init(
				    struct nfapi_fib_hash_table_t *hash_tbl,
				    struct nfapi_fib_table_t *fib_table,
				    const uint32_t *key, int family)
{
	if (!hash_tbl)
		return NULL;

	memset(fib_table, 0, sizeof(struct nfapi_fib_table_t));
	fib_table->rt_table_no = *key;
	fib_table->family = family;
	fib_table->entries = 0;
	INIT_LIST_HEAD(&fib_table->route_list);

	return fib_table;
}

void nfapi_fib_table_free(struct nfapi_fib_table_t *fib_table,
			  struct nfapi_fib_hash_table_t *hash_tbl)
{
	mem_cache_free(hash_tbl->free_entries, fib_table);
	return;
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

static struct nfapi_hash_bucket_t
*__fib_table_find_bucket(struct nfapi_fib_hash_table_t *hash_tbl,
		         const uint32_t *key, uint32_t keylen)
{
	uint32_t hash;
	if (!hash_tbl)
		return NULL;

	hash = compute_hash(key, keylen, HASH_MASK);
	if (unlikely(hash >= HASH_TABLE_BUCKETS))
		return NULL;

	return &(hash_tbl->buckets[hash]);
}

static struct nfapi_fib_table_t **__fib_table_find(
				     struct nfapi_hash_bucket_t *bucket,
				     const uint32_t *key, uint32_t keylen)
{
	struct nfapi_fib_table_t **nptr;
	struct nfapi_fib_table_t *fib_table;

	nptr = &(bucket->head);
	if (unlikely(nptr == NULL))
		return NULL;

	fib_table = *nptr;
	while (fib_table != NULL) {
		if (!memcmp(&fib_table->rt_table_no, key, keylen))
			break;
		else
			nptr = &(fib_table->next);
		fib_table = *nptr;
	}

	return nptr;
}

static bool __fib_table_delete(struct nfapi_fib_hash_table_t *hash_tbl,
			   struct nfapi_fib_table_t **nptr)
{
	struct nfapi_fib_table_t *fib_table;

	if (!hash_tbl)
		return false;

	fib_table = *nptr;
	if (fib_table != NULL) {
		*nptr = fib_table->next;
		nfapi_fib_table_free(fib_table, hash_tbl);
	}
	return (fib_table != NULL);
}

static bool __fib_table_add(struct nfapi_fib_hash_table_t *hash_tbl,
			struct nfapi_fib_table_t **cur_ptr,
			struct nfapi_fib_table_t *new_fib_table, bool replace)
{
	struct nfapi_fib_table_t *current;
	uint32_t count;

	if (!hash_tbl)
		return false;

	count = hash_tbl->entries + 1;
	current = *cur_ptr;
	if (current != NULL) {
		if (replace == true) {
			new_fib_table->next = current->next;
			if (false == __fib_table_delete(hash_tbl, cur_ptr))
				return false;
		} else {
			return false;
		}
	} else {
		/* If there is not an existing n, check if there is room */
		if (likely(count < HASH_TABLE_MAX_ENTRIES)) {
			(hash_tbl->entries)++;
			new_fib_table->next = NULL;
		} else {
			return false;
		}
	}
	*cur_ptr = new_fib_table;
	return true;
}

static struct nfapi_fib_table_t *__fib_table_lookup(
				      struct nfapi_hash_bucket_t *bucket,
				      const uint32_t *key, uint32_t keylen)
{
	struct nfapi_fib_table_t *fib_table;
	struct nfapi_fib_table_t **cur_ptr;

	cur_ptr = __fib_table_find(bucket, key, keylen);
	if (unlikely(cur_ptr == NULL))
		return NULL;

	fib_table = *cur_ptr;
	return fib_table;
}

bool nfapi_fib_table_add(struct nfapi_fib_hash_table_t *hash_tbl,
		   struct nfapi_fib_table_t *new_fib_table)
{
	struct nfapi_hash_bucket_t *bucket;
	struct nfapi_fib_table_t **cur_ptr;
	bool retval;

	if (!hash_tbl)
		return false;

	bucket = __fib_table_find_bucket(hash_tbl,
				  &new_fib_table->rt_table_no,
				   sizeof(new_fib_table->rt_table_no));

	if (unlikely(bucket == NULL))
		return false;

	cur_ptr = __fib_table_find(bucket, &new_fib_table->rt_table_no,
				  sizeof(new_fib_table->rt_table_no));
	if (unlikely(cur_ptr == NULL))
		return false;

	retval = __fib_table_add(hash_tbl, cur_ptr, new_fib_table, false);
	return retval;
}

bool nfapi_fib_table_remove(struct nfapi_fib_hash_table_t *hash_tbl,
			   const uint32_t *key,
			   uint32_t keylen)
{
	struct nfapi_hash_bucket_t *bucket;
	struct nfapi_fib_table_t **cur_ptr;
	bool retval;

	if (!hash_tbl)
		return false;

	bucket = __fib_table_find_bucket(hash_tbl, key, keylen);
	if (unlikely(bucket == NULL))
		return false;

	cur_ptr = __fib_table_find(bucket, key, keylen);
	if (unlikely(cur_ptr == NULL))
		return false;

	retval = __fib_table_delete(hash_tbl, cur_ptr);
	return retval;

}

struct nfapi_fib_table_t *nfapi_fib_table_lookup(
					struct nfapi_fib_hash_table_t *hash_tbl,
					const uint32_t *key,
					uint32_t keylen)
{
	struct nfapi_hash_bucket_t *bucket;
	struct nfapi_fib_table_t *fib_table;

	if (!hash_tbl)
		return NULL;

	bucket = __fib_table_find_bucket(hash_tbl, key, keylen);
	if (unlikely(bucket == NULL))
		return NULL;

	fib_table = __fib_table_lookup(bucket, key, keylen);
	return fib_table;
}

static struct nfapi_route_bucket_t
*__rt_find_bucket(struct nfapi_fib_table_t *fib_table,
		  uint32_t *key, uint32_t keylen)
{
	uint32_t hash;
	if (!fib_table)
		return NULL;

	hash = compute_hash(key, keylen, RT_MASK);
	if (unlikely(hash >= RT_BUCKETS))
		return NULL;

	return &(fib_table->buckets[hash]);
}

struct nfapi_rt_id **__rt_find(struct nfapi_route_bucket_t *bucket,
	 uint32_t *key,
	 uint32_t keylen,
	 int family)
{
	struct nfapi_rt_id **nptr;
	struct nfapi_rt_id *rt;
	uint32_t rt_key[9];

	nptr = &(bucket->head);
	if (unlikely(nptr == NULL))
		return NULL;

	rt = *nptr;
	memset(rt_key, 0, sizeof(rt_key));
	while (rt != NULL) {
		if (family == AF_INET) {
			memcpy(&rt_key[1], &rt->rt_entry.dst_addr,
				sizeof(struct in_addr));
			memcpy(&rt_key[2],&rt->rt_entry.tos, sizeof(uint8_t));
		}else {
			memcpy(&rt_key[4], rt->rt_entry6.dst_addr.w_addr,
				sizeof(struct in6_addr));
			memcpy(&rt_key[8],&rt->rt_entry6.tc, sizeof(uint8_t));
		}
		if (!memcmp(key, rt_key, keylen))
			break;
		else
			nptr = &(rt->rt_next);
		rt = *nptr;
	}

	return nptr;

}

static struct nfapi_rt_id *__neigh_rt_remove(struct nfapi_neigh_table_t *nt,
					     struct nfapi_neigh_t *n,
					     struct nfapi_rt_id *rt_id)
{
	struct nfapi_rt_id *curr, *prev;
	if (!nt || !n)
		return NULL;

	for (curr = n->rt_list_head, prev = NULL; curr; curr = curr->next) {
		if (curr == rt_id) {
			if (curr == n->rt_list_head)
				n->rt_list_head = curr->next;
			else
				prev->next = curr->next;
			if (curr == n->rt_list_tail)
				n->rt_list_tail = prev;
			break;
		}
		prev = curr;
	}
	return curr;
}

static bool __rt_delete(struct nfapi_fib_table_t *fib_table,
			struct nfapi_rt_id **nptr)
{
	struct nfapi_rt_id *n;

	if (!fib_table)
		return false;

	n = *nptr;
	if (n != NULL) {
		*nptr = n->rt_next;
		__neigh_rt_remove((n->neigh)->nt, n->neigh, n);
		nfapi_rt_free(n, (n->neigh)->nt);
		fib_table->entries--;
	}
	return (n != NULL);
}

bool __rt_add(struct nfapi_fib_table_t *fib_table,
	      struct nfapi_rt_id **cur_ptr,
	      struct nfapi_rt_id *new_rt_id,
	      bool replace)
{
	struct nfapi_rt_id *current;
	uint32_t count;

	if (!fib_table)
		return false;

	count = fib_table->entries + 1;
	current = *cur_ptr;
	if (current != NULL) {
		if (replace == true) {
			new_rt_id->rt_next = current->rt_next;
			if (false == __rt_delete(fib_table, cur_ptr))
				return false;
		} else {
			return false;
		}
	} else {
		/* If there is not an existing n, check if there is room */
		if (likely(count < RT_MAX_ENTRIES)) {
			(fib_table->entries)++;
			new_rt_id->rt_next = NULL;
		} else {
			return false;
		}
	}
	*cur_ptr = new_rt_id;
	return true;
}

struct nfapi_rt_id *nfapi_rt_create(struct nfapi_neigh_table_t *nt)
{
	struct nfapi_rt_id *rt_id;
	if (!nt)
		return NULL;

	rt_id = mem_cache_alloc(nt->rt_free_entries);
	return rt_id;
}

struct nfapi_rt_id *nfapi_rt_init(struct nfapi_neigh_table_t *nt,
				  struct nfapi_rt_id *rt_id)
{
	if (!nt)
		return NULL;
	memset(rt_id, 0, sizeof(struct nfapi_rt_id));
	rt_id->rt_id = DPA_OFFLD_INVALID_OBJECT_ID;
	rt_id->next = NULL;
	rt_id->rt_next = NULL;
	rt_id->neigh = NULL;
	return rt_id;
}

bool nfapi_rt_add(struct nfapi_neigh_table_t *nt,
				 struct nfapi_neigh_t *n,
				 struct nfapi_fib_table_t *fib_table,
				 struct nfapi_rt_id *new_rt_id)
{
	struct nfapi_route_bucket_t *bucket;
	struct nfapi_rt_id **cur_ptr;
	uint32_t key[9];
	int key_len;
	bool retval;

	/* add the route  in the neigh list*/
	if (!nt || !n || !fib_table)
		return false;
	if (!n->rt_list_head)
		n->rt_list_head = new_rt_id;
	if (n->rt_list_tail)
		n->rt_list_tail->next = new_rt_id;
	n->rt_list_tail = new_rt_id;
	new_rt_id->neigh = n;

	/* add the route in the corresponding fib table*/
	memset(key, 0, sizeof(key));
	key_len = sizeof(key);
	if (fib_table->family == AF_INET) {
		memcpy(&key[1],&new_rt_id->rt_entry.dst_addr,
			sizeof(struct in_addr));
		memcpy(&key[2],&new_rt_id->rt_entry.tos, sizeof(uint8_t));

	} else {
		memcpy(&key[4],&new_rt_id->rt_entry6.dst_addr.w_addr,
			sizeof(struct in6_addr));
		memcpy(&key[8],&new_rt_id->rt_entry6.tc, sizeof(uint8_t));
	}

	bucket = __rt_find_bucket(fib_table, key, key_len);

	if (unlikely(bucket == NULL))
		return false;

	cur_ptr = __rt_find(bucket, key, key_len, fib_table->family);
	if (unlikely(cur_ptr == NULL))
		return false;

	retval = __rt_add(fib_table, cur_ptr, new_rt_id, false);
	return retval;
}

bool nfapi_rt_remove(struct nfapi_fib_table_t *fib_table,
			uint32_t *key, uint32_t keylen)
{
	struct nfapi_route_bucket_t *bucket;
	struct nfapi_rt_id **cur_ptr;
	bool retval;

	if (!fib_table)
		return false;

	bucket = __rt_find_bucket(fib_table, key, keylen);
	if (unlikely(bucket == NULL))
		return false;

	cur_ptr = __rt_find(bucket, key, keylen, fib_table->family);
	if (unlikely(cur_ptr == NULL))
		return false;

	retval = __rt_delete(fib_table, cur_ptr);
	return retval;
}

struct nfapi_rt_id *nfapi_rt_lookup(struct nfapi_fib_table_t *fib_table,
				    uint32_t *key,
				    uint32_t keylen)
{
	struct nfapi_route_bucket_t *bucket;
	struct nfapi_rt_id **cur_ptr;

	if (!fib_table)
		return NULL;

	bucket = __rt_find_bucket(fib_table, key, keylen);
	if (unlikely(bucket == NULL))
		return NULL;

	cur_ptr = __rt_find(bucket, key, keylen, fib_table->family);
	if (unlikely(cur_ptr == NULL))
		return NULL;

	return *cur_ptr;
}

void nfapi_rt_free(struct nfapi_rt_id *rt_id, void *ctxt)
{
	struct nfapi_neigh_table_t *nt;

	nt = ctxt;
	mem_cache_free(nt->rt_free_entries, rt_id);
}
