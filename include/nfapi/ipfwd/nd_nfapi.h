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

/*!
 * @file	nd_nfapi.h
 * @brief	This file contains the ND NF API prototypes and related
 *		macros and data structures
 * @addtogroup	ND
 * @{
 */

#ifndef __NF_ND_H
#define __NF_ND_H
#include "neigh_cmn_nfapi.h"
/*!Callback function for processing packet received from DP/AIOP*/

typedef int32_t (*nf_nd_rcvpkt_fromdp_cbk_fn)(struct nf_pkt_buf *pkt);

/*!	Nd application registered structure */
struct nf_nd_apln_register_cbkfns
{
	nf_nd_rcvpkt_fromdp_cbk_fn ndapln_pkt_recv_fn; /**< callback function*/
};

/*! Input parameters used to identify  a nd record */
struct nf_nd_entry_identifier{
	nf_if_id	ifid; /**< Interface Identifier */
	struct nf_ipv6_addr	ip_address;  /**< IP address */
};

/*! Input parameters used to configure nd record */
struct nf_nd_entry{
    struct nf_nd_entry_identifier nd_id;
	uint16_t	state; /**< Flags to indicate node's state */
	char	mac_addr[NF_ETHR_HWADDR_SIZE];	/**< MAC Address */
};


/*!   Output parameters used for add/delete  nd record */
struct nf_nd_outargs{
	int32_t result; /**< contains the result of the operation*/
};

/*! Input parameters used  to fetch stats information*/
struct nf_nd_stats_inargs{
	int32_t dummy; /**< Dummy input varaibl!< Dummy input varaiblee*/
};

/*! ND	stats structure */
struct nf_nd_stats
{
	uint64_t	nd_allocs; /**< nd records allocated */
	uint64_t	nd_lookups; /**< lookups done on nd table */
	uint64_t	nd_hits; /**< Successful nd lookups*/
	uint64_t	nd_resolution_failed; /**< nd resolution failures */
	uint64_t	nd_queue_discards; /**< Packet queue failures*/
	uint64_t	nd_destroys; /**< nd records freed */
};


/*!  Output parameters used for addition and deletion of  nd record*/
struct nf_nd_stats_outargs{
	int32_t result;  /**< contains the result of the operation*/
	struct nf_nd_stats stats; /**< structure containing the ND stats*/
};



/*! ND get operations */
enum nf_nd_cfg_get_op {
	NF_ND_GET_FIRST = 0, /**< Fetch first entry in the database */
	NF_ND_GET_NEXT, /**< Fetch next entry in the database */
	NF_ND_GET_EXACT  /**< Fetch exact entry for given nd details */
};

/*! Input parameters to  fetch ND entry information */
struct nf_nd_get_inargs{
        nf_if_id	ifid; /**< Interface Identifier */
        enum nf_nd_cfg_get_op	operation; /**< operation to be
                                            * done get first/next/exact*/
        struct nf_ipv6_addr   ip_address;  /**< IP address */
};


/*!  Output parameters used to fetch  nd record */
struct nf_nd_get_outargs{
	int32_t      result; /**< contains the result of the operation */
	struct nf_nd_entry nd_entry;
	/**< contains the nd entry details */
};

/*!
 * @brief	This API is used for adding ND entries.
 * @details	This function first validates the incoming parameters
 *		    and if all validations succeed, a new ND entry is added
 *		    to the database.
 *
 * @param[in]	nsid  Name space Identifier.
 * @param[in]	flags  API behavioral flags.
 * @param[in]	in  Pointer to input param structure
 *		which contains	ND record information.
 * @param[in]	resp  Response arguments for asynchronous call.
 * @param[out]	out  Pointer to output param structure
 *		that will be filled with output values of this API.
 * @returns	0 on Success or negative value on failure
 * @ingroup	ND
 */

int32_t nf_nd_entry_add(
			nf_ns_id nsid,
			const struct nf_nd_entry *in,
			nf_api_control_flags flags,
			struct nf_nd_outargs *out,
			struct nf_api_resp_args *resp);

/*!
 * @brief	This API is used for adding ND entries.
 * @details	This function first validates the incoming parameters
 *		and if all validations succeed, the ND entry is deleted from
 *		the database.
 *
 * @param[in]	nsid  Name space Identifier.
 * @param[in]	flags  API behavioral flags.
 * @param[in]	in  Pointer to input param structure
 *		which contains	ND record information.
 * @param[in]	resp  Response arguments for asynchronous call.
 * @param[out]	out  Pointer to output param structure
 *		that will be filled with output values of this API.
 * @returns	0 on Success or negative value on failure
 * @ingroup	ND
 */

int32_t nf_nd_entry_del(
			nf_ns_id nsid,
			const struct nf_nd_entry_identifier *in,
			nf_api_control_flags flags,
			struct nf_nd_outargs *out,
			struct nf_api_resp_args *resp);

/*!
 * @brief	This function flushes all the  dynamic
 *		ND entries of a given interface.
 *
 * @param[in]	nsid  Name space Identifier.
 * @param[in]	flags  Flags indicate API response (Sync/Async/etc..).
 * @param[in]	in  Input parameters to flush static nd entries.
 * @param[in]	resp  Response Information
 * @param[out]	out  Output Parameters
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup	ND
 *
 */

int32_t nf_nd_entry_flush( nf_ns_id nsid,
			     const struct nf_nd_entry *in,
			     nf_api_control_flags flags,
			     struct nf_nd_outargs *out,
			     struct nf_api_resp_args *resp);

/*!
 * @brief	This API is used to fetch information about the configured.
 * @details	This database is maintained per Name Space.
 *		This function first validates the incoming parameters
 *		and if all validations succeed, the following is performed
 *		depending on the type of operation:
 *		if operation is get_first, fetches first entry information from
 *		ND database.
 *		if operation is get_next, finds the entry in the ND database
 *		if operation is get_exact, finds the entry and returns it.
 *
 * @param[in]	nsid  Name space Identifier.
 * @param[in]	flags  API behavioral flags.
 * @param[in]	in  Pointer to input param structure
 *		which contains	ND entry information.
 * @param[in]	resp  Response arguments for asynchronous call.
 * @param[out]	out  Pointer to output param structure
 *		that will be filled with output values of this API.
 *
 * @returns	0 on Success or negative value on failure
 * @ingroup	ND
 */
int32_t nf_nd_entry_get(
			nf_ns_id    nsid,
			const struct nf_nd_get_inargs *in,
			nf_api_control_flags flags,
			struct nf_nd_get_outargs *out,
			struct nf_api_resp_args *resp);


/*!
 * @brief	DP/AIOP can send  packet to be given to local applications in
 *		the Control Plane/GPP.
 * @details	Application at CP/GPP will register a function to
 *		    receive such packets from DP/AIOP and further process the packet.
 *
 * @param[in]	  nd_appln_cbk_fns  pointer to the structure containing the
 *		  callback functions being registered by the ND Application.
 *
 * @returns	0 on Success or negative value on failure
 * @ingroup	ND
 */

uint32_t nf_nd_register_cbkfn(struct nf_nd_apln_register_cbkfns
				    *nd_appln_cbk_fns);



/*!
 * @brief	Fetches ND statistics.
 *
 * @param[in]	 nsid  Name Space ID for which the stats are to be retrieved.
 * @param[out]	 in  Structure where the statistics are filled.
 * @param[in]	 flags  API behavioral flags.
 * @param[in]	 respargs  Response arguments that will be passed
 *		 to the call back when the call is asynchronous.
 * @param[out]	 out  Structure that will be filled with output values of
 *		 this API.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup	ND
 */
int32_t nf_nd_stats_get ( nf_ns_id nsid,
			  nf_api_control_flags flags,
			  struct nf_nd_stats_outargs *out,
			  struct nf_api_resp_args  *respargs);

#endif /* ifndef __NF_ND_H */
/*! @} */
