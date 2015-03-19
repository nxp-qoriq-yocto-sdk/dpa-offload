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

#ifndef __FIB_NFAPI
#define __FIB_NFAPI



#include <stdint.h>
#include <stdbool.h>
#include <net/ethernet.h>

#include <compat.h>
#include <fsl_fman.h>

#include "fsl_dpa_offload.h"

#include "nfinfra_nfapi.h"
#include "ip4_fwd_nfapi.h"
#include "ip6_fwd_nfapi.h"
#include "neigh_nfapi.h"

#define FIB_TABLE_POOL_SIZE_2EXP	(8)
#define HASH_TABLE_BUCKETS_2EXP		(8)
#define HASH_TABLE_MAX_ENTRIES_2EXP	(8)

/* Maximum number of fib tables in the fib hash table */
#define HASH_TABLE_MAX_ENTRIES	(1 << HASH_TABLE_MAX_ENTRIES_2EXP)
/* Maximum number of buckets in a fib hash table */
#define HASH_TABLE_BUCKETS	(1 << HASH_TABLE_BUCKETS_2EXP)
#define HASH_MASK		(HASH_TABLE_MAX_ENTRIES - 1)
/* Number of fib tables (routing tables) entries in the pool */
#define FIB_TABLE_POOL_SIZE	(1 << FIB_TABLE_POOL_SIZE_2EXP)

#define RT_BUCKETS_2EXP			(8)
#define RT_MAX_ENTRIES_2EXP		(8)
/*
 * Maximum number of routes in a fib table
 */
#define RT_MAX_ENTRIES		(1 << RT_MAX_ENTRIES_2EXP)
/* Maximum number of buckets in a fib table */
#define RT_BUCKETS		(1 << RT_BUCKETS_2EXP)
#define RT_MASK			(RT_MAX_ENTRIES - 1)

struct nfapi_rt_id;



struct nfapi_route_bucket_t {
	uint32_t id;
	struct nfapi_rt_id *head;
};

/* fib table (identifies a routing table) structure */
struct nfapi_fib_table_t {
	/* number of existing routes */
	uint32_t entries;
	/* route table family */
	int family;
	/* route table number */
	uint16_t rt_table_no;
	/* next fib table in a fib hash bucket */
	struct nfapi_fib_table_t *next;
	/* list head of the routes entries corresponding to the fib table */
	struct list_head route_list;
	struct nfapi_route_bucket_t buckets[RT_BUCKETS];
};

struct nfapi_hash_bucket_t {
	uint32_t id;
	struct nfapi_fib_table_t *head;
};

struct nfapi_fib_hash_table_t {
	uint32_t entries;
	struct mem_cache_t *free_entries;
	struct nfapi_hash_bucket_t buckets[HASH_TABLE_BUCKETS];
};

int nfapi_fib_hash_table_init(struct nfapi_fib_hash_table_t *table);

struct nfapi_rt_id *nfapi_rt_create(struct nfapi_neigh_table_t *nt);

struct nfapi_rt_id *nfapi_rt_init(struct nfapi_neigh_table_t *nt,
				     struct nfapi_rt_id *rt_id);

bool nfapi_rt_add(struct nfapi_neigh_table_t *nt,
		 struct nfapi_neigh_t *n,
		 struct nfapi_fib_table_t *fib_table,
		 struct nfapi_rt_id *new_rt_id);

bool nfapi_rt_remove(struct nfapi_fib_table_t *fib_table,
		     uint32_t *key,
		     uint32_t keylen);

struct nfapi_fib_table_t *nfapi_fib_table_lookup(
					struct nfapi_fib_hash_table_t *hash_tbl,
					const void *key,
					uint32_t keylen);

struct nfapi_fib_table_t *nfapi_fib_table_create(
				struct nfapi_fib_hash_table_t *hash_tbl);

struct nfapi_fib_table_t *nfapi_fib_table_init(
				    struct nfapi_fib_hash_table_t *hash_tbl,
				    struct nfapi_fib_table_t *fib_table,
				    const uint16_t *key, int family);

bool nfapi_fib_table_add(struct nfapi_fib_hash_table_t *hash_tbl,
		   struct nfapi_fib_table_t *new_fib_table);

void nfapi_fib_table_free(struct nfapi_fib_table_t *fib_table,
			  struct nfapi_fib_hash_table_t *hash_tbl);

struct nfapi_rt_id *nfapi_rt_lookup(struct nfapi_fib_table_t *fib_table,
				    uint32_t *key,
				    uint32_t keylen);

void nfapi_rt_free(struct nfapi_rt_id *rt_id, void *ctxt);

bool nfapi_fib_table_remove(struct nfapi_fib_hash_table_t *hash_tbl,
			   const void *key,
			   uint32_t keylen);

#endif
