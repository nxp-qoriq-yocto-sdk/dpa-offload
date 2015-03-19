/*!
 * @file	nd_nfapi.h
 * @brief	This file contains the ND NF API prototypes and related
 *   		macros and data structures
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
  nf_nd_rcvpkt_fromdp_cbk_fn ndapln_pkt_recv_fn; /*!< callback function*/
};

/*! Input parameters used to configure nd record */
struct nf_nd_entry{
	nf_if_id	ifid; /*!< Interface Identifier */
	uint16_t	state; /*!< Flags to indicate node's state */
	struct nf_ipv6_addr	ip_address;  /*!< IP address */
	char	mac_addr[NF_ETHR_HWADDR_SIZE];  /*!< MAC Address */
};

/*! Input parameters used to delete nd record */
struct nf_nd_entry_del{
	nf_if_id	ifid; /*!< Interface Identifier */
	struct nf_ipv6_addr	ip_address;  /*!< IP address */
};

struct nf_nd_entry_mod{
	nf_if_id	ifid; /*!< Interface Identifier */
	uint16_t	state; /*!< Flags to indicate node's state */
	struct nf_ipv6_addr	ip_address;  /*!< IP address */
	char	mac_addr[NF_ETHR_HWADDR_SIZE];  /*!< MAC Address */
};


/*!   Output parameters used for add/delete  nd record */
struct nf_nd_outargs{
	int32_t result; /*!< contains the result of the operation*/
};

/*! Input parameters used  to fetch stats information*/
struct nf_nd_stats_inargs{
       int32_t dummy; /*!< Dummy input varaibl!< Dummy input varaiblee*/
};

/*! ND  stats structure */
struct nf_nd_stats
{
  uint64_t	nd_allocs; /*!< nd records allocated */
  uint64_t	nd_lookups; /*!< lookups done on nd table */
  uint64_t	nd_hits; /*!< Successful nd lookups*/
  uint64_t	nd_resolution_failed; /*!< nd resolution failures */
  uint64_t	nd_queue_discards; /*!< Packet queue failures*/
  uint64_t	nd_destroys; /*!< nd records freed */
};


/*!  Output parameters used for addition and deletion of  nd record*/
struct nf_nd_stats_outargs{
	int32_t result;  /*!< contains the result of the operation*/
    struct nf_nd_stats stats; /*!< structure containing the ND stats*/
};



/*! ND get operations */
enum nf_nd_cfg_get_op {
	ND_GET_FIRST_RECORD = 0, /*!< Fetch first entry in the database */
	ND_GET_FIRST_NEXT , /*!< Fetch next entry in the database */
	ND_GET_EXACT  /*!< Fetch exact entry for given nd details */
};

/*! Input parameters to  fetch ND entry information */
struct nf_nd_get_inargs{
	nf_if_id	ifid; /*!< Interface Identifier */
	enum nf_nd_cfg_get_op	operation; /*!< operation to be
                                        * done get first/next/exact*/
	struct nf_ipv6_addr   ip_address;  /*!< IP address */
};


/*!  Output parameters used to fetch  nd record */
struct nf_nd_get_outargs{
	int32_t      result; /*!< contains the result of the operation */
    struct nf_nd_entry nd_entry;
};

/*!
 * @brief	This API is used for adding ND entries.
 * @details	This function first validates the incoming parameters
 * 		    and if all validations succeed, a new ND entry is added
 * 		    to the database.
 *
 * @param[in]	nsid - Name space Identifier.
 * @param[in]	flags - API behavioral flags.
 * @param[in]	in - Pointer to input param structure
 * 		which contains  ND record information.
 * @param[in]	resp - Response arguments for asynchronous call.
 * @param[out]	out - Pointer to output param structure
 * 		that will be filled with output values of this API.
 * @returns SUCCESS on success; FAILURE otherwise.
 * @ingroup	ND
 */

int32_t nf_nd_add_entry(
	nf_ns_id nsid,
	const struct nf_nd_entry *in,
	nf_api_control_flags flags,
	struct nf_nd_outargs *out,
	struct nf_api_resp_args *resp);

/*!
 * @brief	This API is used for adding ND entries.
 * @details	This function first validates the incoming parameters
 * 		and if all validations succeed, the ND entry is deleted from
 * 		the database.
 *
 * @param[in]	nsid - Name space Identifier.
 * @param[in]	flags - API behavioral flags.
 * @param[in]	in - Pointer to input param structure
 * 		which contains  ND record information.
 * @param[in]	resp - Response arguments for asynchronous call.
 * @param[out]	out - Pointer to output param structure
 * 		that will be filled with output values of this API.
 * @returns SUCCESS on success; FAILURE otherwise.
 * @ingroup	ND
 */

int32_t nf_nd_del_entry(
	nf_ns_id nsid,
	const struct nf_nd_entry_del *in,
	nf_api_control_flags flags,
	struct nf_nd_outargs *out,
	struct nf_api_resp_args *resp);

/*!
 * @brief	This function flushes all the  dynamic
 * 		ND entries of a given interface.
 *
 * @param[in]	nsid - Name space Identifier.
 * @param[in]	flags - Flags indicate API response (Sync/Async/etc..).
 * @param[in]	in - Input parameters to flush static nd entries.
 * @param[in]	resp - Response Information
 * @param[out]	out - Output Parameters
 * @returns SUCCESS on success; FAILURE otherwise.
 *
 * @ingroup	ND
 *
 */

int32_t nf_nd_flush_entries( nf_ns_id nsid,
			  const struct nf_nd_entry *in,
		      nf_api_control_flags flags,
			  struct nf_nd_outargs *out,
			  struct nf_api_resp_args *resp);

int32_t nf_nd_modify_entry(
		nf_ns_id nsid,
		const struct nf_nd_entry_mod *in,
		nf_api_control_flags flags,
		struct nf_nd_outargs *out,
		struct nf_api_resp_args *resp);

/*!
 * @brief	This API is used to fetch information about the configured.
 * @details	This database is maintained per Name Space.
 * 		This function first validates the incoming parameters
 * 		and if all validations succeed, the following is performed
 * 		depending on the type of operation:
 * 		if operation is get_first, fetches first entry information from
 * 		ND database.
 * 		if operation is get_next, finds the entry in the ND database
 * 		if operation is get_exact, finds the entry and returns it.
 *
 * @param[in]	nsid - Name space Identifier.
 * @param[in]	flags - API behavioral flags.
 * @param[in]	in - Pointer to input param structure
 * 		which contains  ND entry information.
 * @param[in]	resp - Response arguments for asynchronous call.
 * @param[out]	out - Pointer to output param structure
 * 		that will be filled with output values of this API.
 *
 * @returns SUCCESS on success; FAILURE otherwise.
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
 *   		the Control Plane/GPP.
 * @details	Application at CP/GPP will register a function to
 * 		    receive such packets from DP/AIOP and further process the packet.
 *
 * @param[in]     nd_appln_cbk_fns - pointer to the structure containing the
 *                callback functions being registered by the ND Application.
 *
 * @returns SUCCESS on success; FAILURE otherwise.
 * @ingroup	ND
 */

uint32_t nf_nd_appln_register_cbkfn(struct nf_nd_apln_register_cbkfns
                                                         *nd_appln_cbk_fns);



/*!
 * @brief	Fetches ND statistics.
 *
 * @param[in]    nsid - Name Space ID for which the stats are to be retrieved.
 * @param[out]   in - Structure where the statistics are filled.
 * @param[in]    flags - API behavioral flags.
 * @param[in]    respargs - Response arguments that will be passed
 *               to the call back when the call is asynchronous.
 * @param[out]   out - Structure that will be filled with output values of
 *               this API.
 * @returns SUCCESS on success; FAILURE otherwise.
 *
 * @ingroup	ND
 */
int32_t nf_nd_stats_get ( nf_ns_id nsid,
                         const struct nf_nd_stats_inargs *in,
                         nf_api_control_flags flags,
                         struct nf_nd_stats_outargs *out,
                         struct nf_api_resp_args  *respargs);

#endif /* ifndef __NF_ND_H */
/*! @} */
