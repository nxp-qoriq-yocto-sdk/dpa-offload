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

#ifndef _IPSEC_NFAPI_RESOURCES_H
#define _IPSEC_NFAPI_RESOURCES_H

#include <usdpaa/fsl_dpa_ipsec.h>

/*
 * NF API IPSec generic resource
 */
struct nf_ipsec_resources {
	struct dpa_ipsec_pre_sec_out_params pre_sec_out_params;
	uint8_t ipf_bpid; /* Scratch buffer pool for IP Fragmentation */
	void *pcd_dev;	/* PCD device handle */
	uint32_t fqid;  /* FQ ID for 'bypass' action for outbound direction */
	uint8_t bpid;	/* Buffer Pool ID to be used by SA */
	uint16_t bufsize; /* Buffer Pool buffer size */
	void **frag_nodes; /* Pointer to array of fragmentation nodes provided by application */
	uint16_t n_frag_nodes; /* Number of fragmentation nodes provided by application */
};

/* IPSec resources initialized by the application */
extern struct nf_ipsec_resources *nf_ipsec_resources;
#endif
