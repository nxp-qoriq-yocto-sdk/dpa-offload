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

#include "init_nfapi.h"
#include "ipfwd.h"

/* Global nf_ipfwd_data component */
static struct nf_ipfwd_data __nf_ipfwd_data;
struct nf_ipfwd_data *gbl_nf_ipfwd_data;

static int init_ipfwd_tables(uint32_t proto_len, int family)
{
	int ret = 0;

	ret = nfapi_neigh_table_init(&__nf_ipfwd_data.neigh_tbl[family]);
	if (ret < 0)
		return ret;
	__nf_ipfwd_data.neigh_tbl[family].proto_len = proto_len;

	ret = nfapi_rule_table_init(&__nf_ipfwd_data.rule_tbl[family]);
	if (ret < 0)
		return ret;

	ret = nfapi_fib_hash_table_init(&__nf_ipfwd_data.fib_htbl[family]);
	if (ret < 0)
		return ret;

	ret = nfapi_group_table_init(&__nf_ipfwd_data.group_tbl[family]);
	if (ret < 0)
		return ret;
	__nf_ipfwd_data.group_tbl[family].addr_len = proto_len;

	ret = nfapi_mrt_init(&__nf_ipfwd_data.mr_tbl[family]);
	if (ret < 0)
		return ret;
	__nf_ipfwd_data.mr_tbl[family].addr_len = proto_len;

	ret = nfapi_manip_init(&__nf_ipfwd_data.manip_tbl[family]);
	if (ret < 0)
		return ret;
	__nf_ipfwd_data.manip_tbl[family].addr_len = proto_len;

	return 0;
}

int init_nf_ipfwd_global_data(void)
{
	int ret = 0;

	if (gbl_init->ipfwd.user_data.init_ipv4) {
		ret = init_ipfwd_tables(sizeof(struct in_addr), IPv4);
		if (ret)
			return ret;
	}
	if (gbl_init->ipfwd.user_data.init_ipv6) {
		ret = init_ipfwd_tables(sizeof(struct in6_addr), IPv6);
		if (ret)
			return ret;
	}

	__nf_ipfwd_data.ip4_route_nf_res = gbl_init->ipfwd.ip4_route_nf_res;
	__nf_ipfwd_data.ip6_route_nf_res = gbl_init->ipfwd.ip6_route_nf_res;
	__nf_ipfwd_data.ip4_rule_nf_res = gbl_init->ipfwd.ip4_rule_nf_res;
	__nf_ipfwd_data.ip6_rule_nf_res = gbl_init->ipfwd.ip6_rule_nf_res;
	__nf_ipfwd_data.ip4_mc_iif_grp_nf_res =
					gbl_init->ipfwd.ip4_mc_iif_grp_nf_res;
	__nf_ipfwd_data.ip6_mc_iif_grp_nf_res =
					gbl_init->ipfwd.ip6_mc_iif_grp_nf_res;
	__nf_ipfwd_data.ip4_mc_route_nf_res =
					gbl_init->ipfwd.ip4_mc_route_nf_res;
	__nf_ipfwd_data.ip6_mc_route_nf_res =
					gbl_init->ipfwd.ip6_mc_route_nf_res;

	gbl_nf_ipfwd_data = &__nf_ipfwd_data;

	return 0;
}
