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

#include <error.h>

#include "init_nfapi.h"
#include "ipsec.h"

/* Global nf_ipsec_data component */
static struct nf_ipsec_data __nf_ipsec_data;
struct nf_ipsec_data *gbl_nf_ipsec_data;

int init_nf_ipsec_global_data(void)
{
	int32_t entries;
	int i, ret = 0;

	/* Clear and initialize memory occupied by NF IPSec internal data */
	memset(&__nf_ipsec_data, 0, sizeof(__nf_ipsec_data));

	for (i = 0; i < NF_IPSEC_DIR_NUM; i++) {
		INIT_LIST_HEAD(&__nf_ipsec_data.sa_list[i]);
		INIT_LIST_HEAD(&__nf_ipsec_data.pol_list[i]);
	}
	memset(&__nf_ipsec_data.sa_mng, 0,
			NF_IPSEC_DIR_NUM * NF_IPSEC_MAX_SAS * sizeof(void *));
	memset(&__nf_ipsec_data.pol_state, POL_STATE_INVALID,
			NF_IPSEC_DIR_NUM * NF_IPSEC_MAX_POLS * sizeof(uint8_t));
	memset(&__nf_ipsec_data.pol_mng, 0,
			NF_IPSEC_DIR_NUM * NF_IPSEC_MAX_POLS * sizeof(void *));

	/* Reserve memory for NF IPSec internal structures */
	__nf_ipsec_data.sa_nodes = mem_cache_create(
			sizeof(struct nf_ipsec_sa_data), NF_IPSEC_MAX_SAS);
	if (unlikely(__nf_ipsec_data.sa_nodes == NULL))
		return -ENOMEM;

	__nf_ipsec_data.pol_nodes = mem_cache_create(
			sizeof(struct nf_ipsec_pol_data), NF_IPSEC_MAX_POLS);
	if (unlikely(__nf_ipsec_data.pol_nodes == NULL))
		return -ENOMEM;

	for (i = 0; i < NF_IPSEC_MAX_POOL_LINK_NODES; i++) {
		__nf_ipsec_data.link_nodes[i] =
			mem_cache_create(sizeof(struct nf_ipsec_sa_pol_link),
					NF_IPSEC_MAX_LINK_NODES);
		if (unlikely(__nf_ipsec_data.link_nodes[i] == NULL))
			return -ENOMEM;
	}

	entries = mem_cache_refill(__nf_ipsec_data.sa_nodes, NF_IPSEC_MAX_SAS);
	if (unlikely(entries != NF_IPSEC_MAX_SAS))
		return -ENOMEM;

	entries = mem_cache_refill(
			__nf_ipsec_data.pol_nodes, NF_IPSEC_MAX_POLS);
	if (unlikely(entries != NF_IPSEC_MAX_POLS))
		return -ENOMEM;

	for (i = 0; i < NF_IPSEC_MAX_POOL_LINK_NODES; i++) {
		entries = mem_cache_refill(__nf_ipsec_data.link_nodes[i],
				NF_IPSEC_MAX_LINK_NODES);
		if (unlikely(entries != NF_IPSEC_MAX_LINK_NODES))
			return -ENOMEM;
	}

	gbl_init->ipsec.dpa_ipsec_id = -1;

	/* Global nf_ipsec_data component */
	gbl_nf_ipsec_data = &__nf_ipsec_data;

	return ret;
}
