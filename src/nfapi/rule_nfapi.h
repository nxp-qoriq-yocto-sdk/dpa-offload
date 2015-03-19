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

#ifndef __RULE_NFAPI
#define __RULE_NFAPI

#include <stdint.h>
#include <stdbool.h>
#include <net/ethernet.h>

#include <compat.h>
#include <fsl_fman.h>

#include "fsl_dpa_offload.h"

#include "ip4_fwd_nfapi.h"
#include "ip6_fwd_nfapi.h"

#define RULE_POOL_SIZE_2EXP		(10)
#define RULE_TABLE_BUCKETS_2EXP		(10)
#define RULE_TABLE_MAX_ENTRIES_2EXP	(10)

/* Maximum number of entries in the rule table */
#define RULE_TABLE_MAX_ENTRIES		(1 << RULE_TABLE_MAX_ENTRIES_2EXP)
/* Number of buckets in the rule table */
#define RULE_TABLE_BUCKETS		(1 << RULE_TABLE_BUCKETS_2EXP)
#define RULE_HASH_MASK			(RULE_TABLE_MAX_ENTRIES - 1)
/* Maximum number of rules defined in the memcache pool */
#define RULE_POOL_SIZE			(1 << RULE_POOL_SIZE_2EXP)



/* rule structure */
struct nfapi_rule_t {
	/* next rule in a rule table bucket */
	struct nfapi_rule_t *next;
	/*
	 * rule node in the rule list corresponding to the rule table. The head
	 * of the list is defined in the rule table structure
	 */
	struct list_head rule_node;
	uint32_t prio;
	struct nfapi_rule_table_t *rt;
	union {
		struct nf_ip4_fwd_pbr_rule rule_entry;
		struct nf_ip6_fwd_pbr_rule rule_entry6;
	};
};

struct nfapi_rule_bucket_t {
	uint32_t id;
	struct nfapi_rule_t *head;
};

/* rule table structure */
struct nfapi_rule_table_t {
	/* list head of the rules entries corresponding to the rule table */
	struct list_head rule_list;
	uint32_t entries;
	struct mem_cache_t *free_entries;
	struct nfapi_rule_bucket_t buckets[RULE_TABLE_BUCKETS];
};

int nfapi_rule_table_init(struct nfapi_rule_table_t *table);

struct nfapi_rule_t *nfapi_rule_create(struct nfapi_rule_table_t *rt);

struct nfapi_rule_t *nfapi_rule_init(struct nfapi_rule_table_t *rt,
				     struct nfapi_rule_t *rule,
				     uint32_t *key);

void nfapi_rule_free(struct nfapi_rule_t *rule, struct nfapi_rule_table_t *rt);

bool nfapi_rule_add(struct nfapi_rule_table_t *rt,
		    struct nfapi_rule_t *new_rule);

bool nfapi_rule_remove(struct nfapi_rule_table_t *rt,
		       uint32_t *key,
		       uint32_t keylen);

struct nfapi_rule_t *nfapi_rule_lookup(struct nfapi_rule_table_t *rt,
					const uint32_t *key,
					uint32_t keylen);


#endif
