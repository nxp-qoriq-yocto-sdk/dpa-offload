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
 * @file	arp_nfapi.h
 * @brief	This header file contains the ARP NF API prototypes,
 *		related macros and data structures
 * @addtogroup	ARP
 * @{
 */

#ifndef __NF_ARP_H
#define __NF_ARP_H
#include "nfinfra_nfapi.h"
#include "neigh_cmn_nfapi.h"

/*!
 *	Callback function for processing packet received from DP/AIOP
 */

typedef int32_t (*nf_arp_rcvpkt_fromdp_cbk_fn)(struct nf_pkt_buf *pkt);

/*!
 *	Callback function for sending unresolved IP packets from DP/AIOP to GPP
 */

typedef int32_t (*nf_arp_rcv_unresolved_ippkt_fromdp_cbkfn)
	(struct nf_pkt_buf *pkt,  nf_ipv4_addr gw_ipaddr);

/*!
 *	Application registeration structure
 */

struct nf_arp_apln_register_cbkfns
{
	nf_arp_rcvpkt_fromdp_cbk_fn	 app_pkt_recv_fn;
					/**<
					* Function to be invoked to send packet from AIOP
					* to interested applications at GPP.
					*/
  nf_arp_rcv_unresolved_ippkt_fromdp_cbkfn	app_unresolv_ip_pkt_rcv;
					/**<
					 * Function to be invoked when
					 * an IP address is unresolved at AIOP
					 */
};

/*!
 *	Parameters used to identify a arp record
 */
struct nf_arp_entry_identifier{
	nf_if_id	ifid; /**< Interface Identifier */
	nf_ipv4_addr	ip_address;  /**< IP address */
};

/*!
 *	Parameters used to configure a arp record
 */
struct nf_arp_entry{
        struct nf_arp_entry_identifier arp_id;
        uint16_t	state; /**< Flags to indicate node's state.
                 The node can be in any of the following states.
				 NF_NUD_STATE_INCOMPLETE The neighbour entry is incomplete
				 NF_NUD_STATE_REACHABLE The neighbour  is  reachable
				 NF_NUD_STATE_STALE The neighbour record information needs  to be re-validated
				 NF_NUD_STATE_DELAY Delay the revalidation of the  neighbour
				 NF_NUD_STATE_PROBE Revalidating the neighbour information  in the record
				 NF_NUD_STATE_FAILED The neighbour resolution has  failed
				 NF_NUD_STATE_PERMANENT It is a static neighbour entry and is reachable */

	char		mac_addr[NF_ETHR_HWADDR_SIZE];	/**< MAC Address */
};

/*!
 *	Output parameters used for addition and deletion of
 *	arp records
 */
struct nf_arp_outargs{
	int32_t result; /**< contains the result of the operation*/
};


/*!
 * Input parameters used for addition and deletion of  proxy arp records
 */
struct nf_proxy_arp_entry{
	nf_if_id		ifid; /**< Interface Identifier */
	nf_ipv4_addr	ip_address; /**< IP address */
};


/*!
 * ARP get operations macros
 */
enum nf_arp_cfg_get_op {
	NF_ARP_GET_FIRST = 0, /**< Fetch first entry in the database */
	NF_ARP_GET_NEXT , /**< Fetch next entry in the database */
	NF_ARP_GET_EXACT  /**< Fetch exact entry for given	details */
};


/*!
 * Input parameters to	fetch ARP entry information
 */

struct nf_arp_get_inargs{
	nf_if_id		ifid; /**< Interface Identifier */
	enum nf_arp_cfg_get_op	operation; /**< operation to be done get
										* first/next/exact */
	nf_ipv4_addr	ip_address;  /**< IP address */

};
/*!
 * Output parameters used to fetch	arp record
 */

struct nf_arp_get_outargs{
	int32_t		 result; /**< result of the operation*/
	struct nf_arp_entry arp_entry;
	/**< contains the arp entry details */
};


/*!
 * ARP	stats structure
 */
struct nf_arp_stats
{
	uint64_t	arp_allocs; /**< arp records allocated */
	uint64_t	arp_lookups; /**< lookups done on arp table */
	uint64_t	arp_hits; /**< Successful arp lookups*/
	uint64_t	arp_resolution_failed; /**< arp resolution failures */
	uint64_t	arp_queue_discards; /**< Packet queue failures*/
	uint64_t	arp_destroys; /**< arp records freed */

};

/*!
 * Input parameters used to fetch  arp statistics
 */
struct nf_arp_stats_inargs{
	int32_t		 dummy; /**< dummy input */
};

/*!
 * Output parameters used to fetch	arp  statistics
 */
struct nf_arp_stats_outargs{
	int32_t	 result;		/**< Result of the operation*/
	struct nf_arp_stats stats;	/**< structure containing the statistics
								* counter values*/
};

/*!
 * @brief	This API is used to add ARP entries.
 *
 * @details	This function first validates the incoming parameters
 *		and if all validations succeed, a new ARP entry is added to
 *		the database.
 *
 * @param[in]	nsid	Name space Identifier.
 * @param[in]	flags	PI behavioral flags.
 * @param[in]	in		Pointer to input param structure
 *						which contains	ARP record information.
 * @param[in]	resp	Response arguments for asynchronous call.
 *
 * @param[out]	out		Pointer to output param structure
 *						that will be filled with output
 *						values of this API.
 *
 * @returns	0 on Success or negative value on failure
 * @ingroup	ARP
 */
int32_t nf_arp_entry_add(
	nf_ns_id	nsid,
	const struct	nf_arp_entry *in,
	nf_api_control_flags	flags,
	struct nf_arp_outargs	*out,
	struct nf_api_resp_args *resp);


/*!
 * @brief	This API is used to delete ARP entries.
 *
 * @details	This function first validates the incoming parameters
 *		and if all validations succeed, it searches for the entry in
 *		the database and deletes it.
 *
 * @param[in]	nsid	Name space Identifier.
 * @param[in]	flags	API behavioral flags.
 * @param[in]	in		Pointer to input param structure
 *						which contains	ARP record information.
 * @param[in]	resp	Response arguments for asynchronous call.
 *
 * @param[out]	out		Pointer to output param structure
 *						that will be filled with output values
 *						of this API.
 *
 * @returns	0 on Success or negative value on failure
 * @ingroup	ARP
 */
int32_t nf_arp_entry_del(
	nf_ns_id	nsid,
	const struct	nf_arp_entry_identifier *in,
	nf_api_control_flags	flags,
	struct nf_arp_outargs	*out,
	struct nf_api_resp_args	*resp);


/*!
 * @brief	This function flushes all the  dynamic
 *		ARP entries add for a given interface.
 *
 * @param[in]	nsid	Name space Identifier.
 * @param[in]	flags	Flags indicate API response (Sync/Async/etc..).
 * @param[in]	in		Input parameters to flush	arp entries.
 * @param[in]	resp	Response Information
 * @param[out]	out		Output Parameters
 *
 * @returns	0 on Success or negative value on failure
 * @ingroup	ARP
 */
int32_t nf_arp_entry_flush(
			nf_ns_id	nsid,
			const struct	nf_arp_entry *in,
			nf_api_control_flags	flags,
			struct nf_arp_outargs	*out,
			struct nf_api_resp_args	*resp);

/*!
 * @brief	This function adds a proxy arp record for a given interface
 *
 * @param[in]	nsid	Name space Identifier.
 * @param[in]	flags	Flags indicate API response (Sync/Async/etc..).
 * @param[in]	in		Input Parameters.
 * @param[in]	resp	Response Information
 * @param[out]	out		Output Parameters
 * @returns	0 on Success or negative value on failure
 * @ingroup	ARP
 */

int32_t nf_proxy_arp_add_entry(
		nf_ns_id	nsid,
		const struct nf_proxy_arp_entry	*in,
		nf_api_control_flags	flags,
		struct nf_arp_outargs	*out,
		struct nf_api_resp_args	*resp);

/*!
 * @brief	This function deletes a proxy arp record for a given interface
 *
 * @param[in]	nsid	Name space Identifier.
 * @param[in]	flags	Flags indicate API response (Sync/Async/etc..).
 * @param[in]	in		Input Parameters.
 * @param[in]	resp	Response Information
 * @param[out]	out		Output Parameters
 * @returns	0 on Success or negative value on failure
 * @ingroup	ARP
 */

int32_t nf_proxy_arp_del_entry(
		nf_ns_id	nsid,
		const struct nf_proxy_arp_entry	*in,
		nf_api_control_flags	flags,
		struct nf_arp_outargs	*out,
		struct nf_api_resp_args	*resp);

/*!
 * @brief	This API is used to get the  ARP entries configured at AIOP.
 * @details	This API is used to fetch information about the configured
 *			records in the ARP database at AIOP.
 *			One database is maintained for a given virtual instance.
 *			This function first validates the incoming parameters
 *			and if all validations succeed, the following is performed
 *			depending on the type of operation:
 *			if operation is get_first, fetches first entry information from
 *			ARP database.
 *			if operation is get_next, finds the entry in the ARP database
 *			if operation is get_exact, finds the entry and returns it.
 *
 * @param[in]	flags	API behavioral flags.
 * @param[in]	in		Pointer to input param structure
 *						which contains	ARP entry information.
 * @param[in]	resp	Response arguments for asynchronous call.
 * @param[out]	out		Pointer to output param structure
 *						that will be filled with output values of this API.
 *
 * @returns	0 on Success or negative value on failure
 * @ingroup	ARP
 */

int32_t nf_arp_entry_get(
	nf_ns_id	 nsid,
	const struct nf_arp_get_inargs	*in,
	nf_api_control_flags	flags,
	struct nf_arp_get_outargs	*out,
	struct nf_api_resp_args	*resp);

/*!
 * @brief	This API is used by applications to receive packets from AIOP.
 * @details	DP/AIOP can send   a packet to be given to applications running
 *		in the Control Plane/GPP.
 *		Applications at CP/GPP	register a function to
 *		receive such packets from DP/AIOP and further process the packet.
 *
 * @param[in]	arp_appln_cbk_fns  pointer to the structure containing the
 *		callback functions being registered by the ARP Application.
 * @returns	0 on Success or negative value on failure
 * @ingroup	ARP
 */

uint32_t nf_arp_appln_register_cbkfn(
			struct nf_arp_apln_register_cbkfns	arp_appln_cbk_fns);



/*!
 * @brief	Fetches arp statistics.
 * @param[in]	nsid		Name Space ID for which the stats are to be
 *							retrieved.
 * @param[out]	out			Structure where the statistics are filled.
 * @param[in]	flags		API behavioral flags.
 * @param[in]	respargs	Response arguments that will be passed
 *							to the call back when the call is asynchronous.
 * @param[out]	out			Structure that will be filled with output values
 *							of this API.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup	ARP
 */

int32_t nf_arp_stats_get (nf_ns_id nsid,
			   nf_api_control_flags flags,
			   struct nf_arp_stats_outargs *out,
			   struct nf_api_resp_args	*respargs);

#endif /* ifndef __NF_ARP_H */
/*! @} */
