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

#include "nfinfra_nfapi.h"
#include "rule_nfapi.h"

int nfapi_rule_table_init(struct nfapi_rule_table_t *table)
{

	struct nfapi_rule_bucket_t *bucket;
	uint32_t entries;
	int i;

	memset(table, 0, sizeof(struct nfapi_rule_table_t));
	table->free_entries =
		mem_cache_create(sizeof(struct nfapi_rule_t),
				 RULE_POOL_SIZE);

	if (unlikely(table->free_entries == NULL))
		return -ENOMEM;

	entries = mem_cache_refill(table->free_entries, RULE_POOL_SIZE);
	if (unlikely(entries != RULE_POOL_SIZE))
		return -ENOMEM;

	for (i = 0; i < RULE_TABLE_BUCKETS; i++) {
		bucket = table->buckets + i;
		bucket->head = NULL;
		bucket->id = i;
	}


	INIT_LIST_HEAD(&table->rule_list);

	return 0;
}

struct nfapi_rule_t *nfapi_rule_create(struct nfapi_rule_table_t *rt)
{
	struct nfapi_rule_t *rule;
	if (!rt)
		return NULL;

	rule = mem_cache_alloc(rt->free_entries);

	return rule;
}

struct nfapi_rule_t *nfapi_rule_init(struct nfapi_rule_table_t *rt,
				       struct nfapi_rule_t *rule,
				       uint32_t *key)
{
	if (!rt)
		return NULL;

	rule->prio = *key;
	rule->rt = rt;

	return rule;
}

void nfapi_rule_free(struct nfapi_rule_t *rule, struct nfapi_rule_table_t *rt)
{
	mem_cache_free(rt->free_entries, rule);
	return;
}

static inline uint32_t compute_rule_hash(const void *key, uint32_t key_len)
{
	uint64_t result;

	result = fman_crc64_init();
	result = fman_crc64_update(result, (void *)key, key_len);
	result = fman_crc64_finish(result);
	return ((uint32_t) result) & RULE_HASH_MASK;
}

static struct nfapi_rule_bucket_t
*__rule_find_bucket(struct nfapi_rule_table_t *rt,
		     const void *key, uint32_t keylen)
{
	uint32_t hash;
	if (!rt)
		return NULL;

	hash = compute_rule_hash(key, keylen);
	if (unlikely(hash >= RULE_TABLE_BUCKETS))
		return NULL;

	return &(rt->buckets[hash]);
}

static struct nfapi_rule_t **__rule_find(struct nfapi_rule_bucket_t *bucket,
				     const void *key, uint32_t keylen)
{
	struct nfapi_rule_t **nptr;
	struct nfapi_rule_t *rule;

	nptr = &(bucket->head);
	if (unlikely(nptr == NULL))
		return NULL;

	rule = *nptr;
	while (rule != NULL) {
		if (rule->prio == *(uint32_t*)key)
			break;
		else
			nptr = &(rule->next);
		rule = *nptr;
	}

	return nptr;
}

static bool __rule_delete(struct nfapi_rule_table_t *rt,
			   struct nfapi_rule_t **nptr)
{
	struct nfapi_rule_t *rule;

	if (!rt)
		return false;
	rule = *nptr;
	if (rule != NULL) {
		*nptr = rule->next;
		nfapi_rule_free(rule, rt);
		rt->entries--;
	}
	return (rule != NULL);
}

static bool __rule_add(struct nfapi_rule_table_t *rt,
			struct nfapi_rule_t **cur_ptr,
			struct nfapi_rule_t *new_rule, bool replace)
{
	struct nfapi_rule_t *current;
	uint32_t count;

	if (!rt)
		return false;

	count = rt->entries + 1;
	current = *cur_ptr;
	if (current != NULL) {
		if (replace == true) {
			new_rule->next = current->next;
			if (false == __rule_delete(rt, cur_ptr))
				return false;
		} else {
			return false;
		}
	} else {
		/* If there is not an existing n, check if there is room */
		if (likely(count < RULE_TABLE_MAX_ENTRIES)) {
			(rt->entries)++;
			new_rule->next = NULL;
		} else {
			return false;
		}
	}
	*cur_ptr = new_rule;
	return true;
}

static struct nfapi_rule_t *__rule_lookup(struct nfapi_rule_bucket_t *bucket,
				      const void *key, uint32_t keylen)
{
	struct nfapi_rule_t *rule;
	struct nfapi_rule_t **cur_ptr;

	cur_ptr = __rule_find(bucket, key, keylen);
	if (unlikely(cur_ptr == NULL))
		return NULL;

	rule = *cur_ptr;
	return rule;
}

bool nfapi_rule_add(struct nfapi_rule_table_t *rt,
		   struct nfapi_rule_t *new_rule)
{
	struct nfapi_rule_bucket_t *bucket;
	struct nfapi_rule_t **cur_ptr;
	bool retval;

	if (!rt)
		return false;

	bucket = __rule_find_bucket(rt, &new_rule->prio,
				   sizeof(new_rule->prio));

	if (unlikely(bucket == NULL))
		return false;

	cur_ptr = __rule_find(bucket, &new_rule->prio,
			      sizeof(new_rule->prio));
	if (unlikely(cur_ptr == NULL))
		return false;

	retval = __rule_add(rt, cur_ptr, new_rule, false);
	return retval;
}

bool nfapi_rule_remove(struct nfapi_rule_table_t *rt,
			uint32_t *key,
			uint32_t keylen)
{
	struct nfapi_rule_bucket_t *bucket;
	struct nfapi_rule_t **cur_ptr;
	bool retval;

	if (!rt)
		return false;

	bucket = __rule_find_bucket(rt, key, keylen);
	if (unlikely(bucket == NULL))
		return false;

	cur_ptr = __rule_find(bucket, key, keylen);
	if (unlikely(cur_ptr == NULL))
		return false;

	retval = __rule_delete(rt, cur_ptr);
	return retval;

}

struct nfapi_rule_t *nfapi_rule_lookup(struct nfapi_rule_table_t *rt,
					const void *key,
					uint32_t keylen)
{
	struct nfapi_rule_bucket_t *bucket;
	struct nfapi_rule_t *rule;

	if (!rt)
		return NULL;

	bucket = __rule_find_bucket(rt, key, keylen);
	if (unlikely(bucket == NULL))
		return NULL;

	rule = __rule_lookup(bucket, key, keylen);
	return rule;
}
