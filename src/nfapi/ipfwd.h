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

#ifndef _NFAPI_RESOURCES_H
#define _NFAPI_RESOURCES_H

#include <compat.h>
#include <fsl_qman.h>

#include "fsl_dpa_classifier.h"

#include "neigh_nfapi.h"
#include "fib_nfapi.h"
#include "ipmr_nfapi.h"
#include "neigh_nfapi.h"
#include "rule_nfapi.h"

#define PRIORITY_2TX	4

/* maximum number of interfaces - eth_if[MAX_IFS] */
#define MAX_IFS		256

enum nf_ipfwd_addr_family {
	IPv4 = 0,
	IPv6,
	MAX_ADDR
};

enum nf_ipfwd_table_type {
	NEIGH = 0,
	RULE,
	FIB,
	GROUP_IIF,
	MFC,
	MANIP,
	MAX_TABLE
};

struct nf_ipfwd_action {
	/* Fq associated with the route ccnode */
	struct qman_fq fq;

	/*
	 * Action type (enqueue to route ccnode or action next table)
	 * Next table action is set when the route ccnode is on the
	 * same port as rule ccnode
	 */
	enum dpa_cls_tbl_action_type	type;
	/*
	 * route ccnode id(mapped with a route table id). A rule entry
	 * will point to a goto table identified by this id.
	 * The  id links a rule table entry to a route ccnode. The enqueue
	 * action will be in the aforementioned fq
	 */
	int rt_table_no;
};

struct nf_ipfwd_cc {
	/* Classifier table descriptor */
	int td;
	/*
	 * Interface id which current ccnode belongs to
	 * (not used for route ccnode)
	 */
	int ifid;
	/* Action for a specific rule table.*/
	struct nf_ipfwd_action action;
};

/*
 * NFAPI IP4/IP6 unicast forwarding classifier resources
 */
struct nf_ipfwd_resources {
	/* TTL decrement header manip operation used only for mcast resources*/
	void *ttl_dec_hm;
	/* Number of classifier tables */
	int num_td;
	/* Key size, common for all tables */
	int keysize;
	/* Classifier resources array */
	struct nf_ipfwd_cc nf_cc[0];
};

struct nf_ipfwd_data {
	struct nfapi_eth_ifs eth_if[MAX_IFS];
	struct nfapi_neigh_table_t neigh_tbl[MAX_ADDR];
	struct nfapi_rule_table_t rule_tbl[MAX_ADDR];
	struct nfapi_fib_hash_table_t fib_htbl[MAX_ADDR];
	struct nfapi_grp_iif_table_t group_tbl[MAX_ADDR];
	struct nfapi_mr_table_t mr_tbl[MAX_ADDR];
	struct nfapi_fwd_manip_table_t manip_tbl[MAX_ADDR];
	/* IP forwarding unicast route classifier resources. */
	struct nf_ipfwd_resources *ip4fwd_route_nf_res,
				  *ip6fwd_route_nf_res;
	/* IP forwarding unicast rule classifier resources. */
	struct nf_ipfwd_resources *ip4fwd_rule_nf_res,
				  *ip6fwd_rule_nf_res;
	/* IP forwarding multicast interface table classifier resources. */
	struct nf_ipfwd_resources *ip4_mc_iif_grp_nf_res,
				  *ip6_mc_iif_grp_nf_res;
	/* IP forwarding multicast route table classifier resources. */
	struct nf_ipfwd_resources *ip4_mc_route_nf_res,
				  *ip6_mc_route_nf_res;
};

extern struct nf_ipfwd_data *gbl_nf_ipfwd_data;

#endif
