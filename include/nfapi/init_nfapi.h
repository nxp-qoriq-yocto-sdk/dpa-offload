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

#ifndef _INIT_NFAPI_H
#define _INIT_NFAPI_H

#include "ncsw_ext.h"

#include "fsl_dpa_ipsec.h"


/* Data received from the application */

struct nf_ipsec_user_data {
	int max_sa;
	uint8_t bpid;
	uint16_t bufsize;
	void **frag_nodes;
	uint16_t n_frag_nodes;
	bool ib_policy_verification;
};

struct nf_ipfwd_user_data {
	bool init_ipv4;
	bool init_ipv6;
};

/* Initialization data */

enum nf_ipsec_port_role {
	OB = 0,
	IB,
	IB_OH,
	OB_OH_PRE,
	OB_OH_POST,
	MAX_PORTS
};

struct net_if {
	struct list_head node;
	size_t size;
	unsigned int num_tx_fqs;
	struct qman_fq *tx_fqs;
	struct qman_fq rx_error;
	struct qman_fq tx_error;
	struct qman_fq tx_confirm;
	struct qman_fq *rx_default;
	struct list_head rx_list;
	const struct fm_eth_port_cfg *cfg;
};

struct nf_ipsec_init_data {

	/* user defined info */
	struct nf_ipsec_user_data user_data;

	/* info computed during init */
	uint32_t ipf_bpid;
	uint32_t bpid;
	uint32_t fqid;
	int dpa_ipsec_id;
	struct fman_if *ifs_by_role[MAX_PORTS];
	struct dpa_ipsec_params ipsec_params;
};

struct nf_ipfwd_init_data {
	/* user defined info */
	struct nf_ipfwd_user_data user_data;
	/* TODO: add necessary fields */
};

struct nf_init_data {

	t_Handle pcd_dev;
	struct usdpaa_netcfg_info *netcfg;
	struct list_head ifs;
	struct nf_ipsec_init_data ipsec;
	struct nf_ipfwd_init_data ipfwd;
};

extern struct nf_init_data *gbl_init;

#endif /* _INIT_NFAPI_H */
