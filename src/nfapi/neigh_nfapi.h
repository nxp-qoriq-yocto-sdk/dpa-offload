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

#ifndef __NEIGH_NFAPI
#define __NEIGH_NFAPI

#include <stdint.h>
#include <stdbool.h>
#include <net/ethernet.h>

#include <compat.h>
#include <fsl_fman.h>

#include "fsl_dpa_offload.h"

#include "nfinfra_nfapi.h"
#include "ip4_fwd_nfapi.h"
#include "ip6_fwd_nfapi.h"

#define NEIGH_TABLE_MAX_ENTRIES_2EXP	(10)
#define NEIGH_TABLE_BUCKETS_2EXP	(10)
#define NEIGH_POOL_SIZE_2EXP		(12)
#define RT_POOL_SIZE_2EXP		(10)

#define NEIGH_TABLE_MAX_ENTRIES		(1 << NEIGH_TABLE_MAX_ENTRIES_2EXP)
/**< Maximum Number of entries in Neighbour Table*/
#define NEIGH_TABLE_ENTRIES_MASK	(NEIGH_TABLE_MAX_ENTRIES - 1)
/**< Table Mask*/
#define NEIGH_TABLE_BUCKETS		(1 << NEIGH_TABLE_BUCKETS_2EXP)
/**< Maximum number of entries in a bucket of the Table*/
#define NEIGH_TABLE_BUCKETS_MASK	(NEIGH_TABLE_BUCKETS - 1)
/**< Buckt Mask*/
#define NEIGH_POOL_SIZE			(1 << NEIGH_POOL_SIZE_2EXP)
/**< Number of Entries in the Pool*/
#define RT_POOL_SIZE			(1 << RT_POOL_SIZE_2EXP)
/**< Number of route entries */

/* route structure */
struct nfapi_rt_id {
	/* next route entry in the list corresponding to a neighbor */
	struct nfapi_rt_id *next;
	/* next route entry in a fib table bucket */
	struct nfapi_rt_id *rt_next;
	/*
	 * route node in the route list corresponding to a fib table. The head
	 * of the list is defined in the fib table structure
	 */
	struct list_head route_node;
	/* neigh table for the route */
	struct nfapi_neigh_t *neigh;



	union {
		struct nf_ip4_fwd_route_entry rt_entry;
		struct nf_ip6_fwd_route_entry rt_entry6;
	};
	/*route classifier tables entry id */
	int rt_id;
};

/* neighbor structure */
struct nfapi_neigh_t {
	struct nfapi_neigh_t *next;
	struct nfapi_neigh_table_t *nt;
	/* Ip address ipv4/ipv6 */
	uint32_t ip_address[NF_IPV6_ADDRU32_LEN];
	uint32_t refcnt;
	/* neigh interface id */
	uint32_t ifid;
	/* header manip chain for this neighbor */
	int hmd[2];
	/* tx fqid to reach this neighbour */
	uint32_t tx_fqid;
	/* route cache */
	struct nfapi_rt_id *rt_list_head;
	struct nfapi_rt_id *rt_list_tail;
	/* neigh node corresponding to an eth interface list*/
	struct list_head neigh_node;
	/* neigh node corresponding to a neigh table list */
	struct list_head neigh_tbl_node;
	/* MAC address */
	struct ether_addr eth_addr;
	 /* Flags to indicate node's state */
	uint16_t	state;
};


struct nfapi_neigh_bucket_t {
	uint32_t id;
	struct nfapi_neigh_t *head;
};

/* neighbor table structure */
struct nfapi_neigh_table_t {
	uint32_t proto_len;
	void (*constructor) (struct nfapi_neigh_t *);
	struct mem_cache_t *free_entries;
	struct mem_cache_t *rt_free_entries;
	uint32_t entries;
	uint32_t rt_entries;
	struct nfapi_neigh_bucket_t buckets[NEIGH_TABLE_BUCKETS];
	/*
	 * list head of the neigh entries added to the corresponding neigh
	 * table
	 */
	struct list_head neigh_list;
};

/* contains the neighbor list with the same interface id */
struct nfapi_eth_ifs {
	bool init, init6;
	struct list_head if_list_head, if_list_head6;
};

static inline uint32_t compute_neigh_hash(const void *key, uint32_t key_len)
{
	uint64_t result;

	result = fman_crc64_init();
	result = fman_crc64_update(result, (void *)key, key_len);
	result = fman_crc64_finish(result);
	return ((uint32_t) result) & NEIGH_TABLE_BUCKETS_MASK;
}

int nfapi_neigh_table_init(struct nfapi_neigh_table_t *table);

struct nfapi_neigh_t *nfapi_neigh_create(struct nfapi_neigh_table_t *nt);

void neigh_free(struct nfapi_neigh_t *n, struct nfapi_neigh_table_t *nt);

struct nfapi_neigh_t *nfapi_neigh_init(struct nfapi_neigh_table_t *nt,
				       struct nfapi_neigh_t *n,
				       uint32_t *key);

bool nfapi_neigh_add(struct nfapi_neigh_table_t *nt,
		     struct nfapi_neigh_t *new_n);

bool nfapi_neigh_remove(struct nfapi_neigh_table_t *nt,
			uint32_t *key,
			uint32_t keylen);

struct nfapi_neigh_t *nfapi_neigh_lookup(struct nfapi_neigh_table_t *nt,
					 const uint32_t *key,
					 uint32_t keylen);

#endif
