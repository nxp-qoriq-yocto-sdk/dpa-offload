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
 * 	Callback function for processing packet received from DP/AIOP
 */

typedef int32_t (*nf_arp_rcvpkt_fromdp_cbk_fn)(struct nf_pkt_buf *pkt);

/*!
 * 	Callback function for sending unresolved IP packets from DP/AIOP to GPP
 */

typedef int32_t (*nf_arp_rcv_unresolved_ippkt_fromdp_cbkfn)
    (struct nf_pkt_buf *pkt,  uint32_t gw_ipaddr);

/*!
 *  Application registeration structure
 */

struct nf_arp_apln_register_cbkfns
{
  nf_arp_rcvpkt_fromdp_cbk_fn	 app_pkt_recv_fn;
					/*!<
					* Function to be invoked to send packet from AIOP
					* to interested applications at GPP.
					*/
  nf_arp_rcv_unresolved_ippkt_fromdp_cbkfn	app_unresolv_ip_pkt_rcv;
					/*!<
					 * Function to be invoked when
					 * an IP address is unresolved at AIOP
					 */
};

/*!
 *  Parameters used to configure a arp record
 */
struct nf_arp_entry{
	nf_if_id	ifid; /*!< Interface Identifier */
	uint16_t	state; /*!< Flags to indicate node's state */
	uint32_t	ip_address;  /*!< IP address */
	char		mac_addr[NF_ETHR_HWADDR_SIZE];  /*!< MAC Address */
};

/*!
 *  Parameters used to delete a arp record
 */
struct nf_arp_entry_del{
	nf_if_id	ifid; /*!< Interface Identifier */
	uint32_t	ip_address;  /*!< IP address */
};

/*!
 *  Parameters used to configure a arp record
 */
struct nf_arp_entry_mod{
	nf_if_id	ifid; /*!< Interface Identifier */
	uint16_t	state; /*!< Flags to indicate node's state */
	uint32_t	ip_address;  /*!< IP address */
	char		mac_addr[NF_ETHR_HWADDR_SIZE];  /*!< MAC Address */
};

/*!
 * 	Output parameters used for addition and deletion of
 * 	arp records
 */
struct nf_arp_outargs{
	int32_t result; /*!< contains the result of the operation*/
};


/*!
 * Input parameters used for addition and deletion of  proxy arp records
 */
struct nf_proxy_arp_entry{
	nf_if_id		ifid; /*!< Interface Identifier */
	uint32_t	ip_address; /*!< IP address */
};


/*!
 * ARP get operations macros
 */
enum nf_arp_cfg_get_op {
	NF_ARP_GET_FIRST_RECORD = 0, /*!< Fetch first entry in the database */
	NF_ARP_GET_FIRST_NEXT , /*!< Fetch next entry in the database */
	NF_ARP_GET_EXACT  /*!< Fetch exact entry for given  details */
};


/*!
 * Input parameters to  fetch ARP entry information
 */

struct nf_arp_get_inargs{
	nf_if_id		ifid; /*!< Interface Identifier */
	enum nf_arp_cfg_get_op	operation; /*!< operation to be done get
                                        * first/next/exact */
	uint32_t	ip_address;  /*!< IP address */

};
/*!
 * Output parameters used to fetch  arp record
 */

struct nf_arp_get_outargs{
	int32_t      result; /*!< result of the operation*/
    struct nf_arp_entry arp_entry;
};


/*!
 * ARP  stats structure
 */
struct nf_arp_stats
{
  uint64_t	arp_allocs; /*!< arp records allocated */
  uint64_t	arp_lookups; /*!< lookups done on arp table */
  uint64_t	arp_hits; /*!< Successful arp lookups*/
  uint64_t	arp_resolution_failed; /*!< arp resolution failures */
  uint64_t	arp_queue_discards; /*!< Packet queue failures*/
  uint64_t	arp_destroys; /*!< arp records freed */

};

/*!
 * Input parameters used to fetch  arp statistics
 */
struct nf_arp_stats_inargs{
	int32_t      dummy; /*!< dummy input */
};

/*!
 * Output parameters used to fetch  arp  statistics
 */
struct nf_arp_stats_outargs{
	int32_t      result;  /*!< Result of the operation*/
     struct nf_arp_stats stats; /*!< structure containing the statistics
                                    * counter values*/
};

/*!
 * @brief	This API is used to add ARP entries.
 *
 * @details	This function first validates the incoming parameters
 *		and if all validations succeed, a new ARP entry is added to
 *		the database.
 *
 * @param[in]	nsid - Name space Identifier.
 * @param[in]	flags - API behavioral flags.
 * @param[in]	in - Pointer to input param structure
 *           		which contains  ARP record information.
 * @param[in]	resp - Response arguments for asynchronous call.
 *
 * @param[out]	out - Pointer to output param structure
 * 		that will be filled with output values of this API.
 *
 * @returns SUCCESS on success; FAILURE otherwise.
 * @ingroup	ARP
 */
int32_t nf_arp_add_entry(
	nf_ns_id      nsid,
	const struct nf_arp_entry *in,
	nf_api_control_flags flags,
	struct nf_arp_outargs *out,
	struct nf_api_resp_args *resp);


/*!
 * @brief	This API is used to delete ARP entries.
 *
 * @details	This function first validates the incoming parameters
 *		and if all validations succeed, it searches for the entry in
 *		the database and deletes it.
 *
 * @param[in]	nsid - Name space Identifier.
 * @param[in]	flags - API behavioral flags.
 * @param[in]	in - Pointer to input param structure
 * 		which contains  ARP record information.
 * @param[in]	resp - Response arguments for asynchronous call.
 *
 * @param[out]	out - Pointer to output param structure
 * 		that will be filled with output values of this API.
 *
 * @returns SUCCESS on success; FAILURE otherwise.
 * @ingroup	ARP
 */
int32_t nf_arp_del_entry(
	nf_ns_id      nsid,
	const struct nf_arp_entry_del *in,
	nf_api_control_flags flags,
	struct nf_arp_outargs *out,
	struct nf_api_resp_args *resp);


/*!
 * @brief	This function flushes all the  dynamic
 * 		ARP entries add for a given interface.
 *
 * @param[in]	nsid - Name space Identifier.
 * @param[in]	flags - Flags indicate API response (Sync/Async/etc..).
 * @param[in]	in - Input parameters to flush  arp entries.
 * @param[in]	resp - Response Information
 * @param[out]	out - Output Parameters
 *
 * @returns SUCCESS on success; FAILURE otherwise.
 * @ingroup	ARP
 */
int32_t nf_arp_flush_entries( nf_ns_id nsid,
			  const struct nf_arp_entry *in,
		      nf_api_control_flags flags,
			  struct nf_arp_outargs *out,
			  struct nf_api_resp_args *resp);

int32_t nf_arp_modify_entry(
		nf_ns_id      nsid,
		struct nf_arp_entry_mod *in,
		nf_api_control_flags flags,
		struct nf_arp_outargs *out,
		struct nf_api_resp_args *resp);

/*!
 * @brief	This function adds a proxy arp record for a given interface
 *
 * @param[in]	nsid - Name space Identifier.
 * @param[in]	flags - Flags indicate API response (Sync/Async/etc..).
 * @param[in]	in - Input Parameters.
 * @param[in]	resp - Response Information
 * @param[out]	out - Output Parameters
 * @returns SUCCESS on success; FAILURE otherwise.
 * @ingroup	ARP
 */

int32_t nf_proxy_arp_add_entry(nf_ns_id nsid,
		const struct nf_proxy_arp_entry *in,
		nf_api_control_flags flags,
		struct nf_arp_outargs *out,
		struct nf_api_resp_args *resp);

/*!
 * @brief	This function deletes a proxy arp record for a given interface
 *
 * @param[in]	nsid - Name space Identifier.
 * @param[in]	flags - Flags indicate API response (Sync/Async/etc..).
 * @param[in]	in - Input Parameters.
 * @param[in]	resp - Response Information
 * @param[out]	out - Output Parameters
 * @returns SUCCESS on success; FAILURE otherwise.
 * @ingroup	ARP
 */

int32_t nf_proxy_arp_del_entry(nf_ns_id nsid,
		const struct nf_proxy_arp_entry *in,
		nf_api_control_flags flags,
		struct nf_arp_outargs *out,
		struct nf_api_resp_args *resp);

/*!
 * @brief	This API is used to get the  ARP entries configured at AIOP.
 * @details	This API is used to fetch information about the configured
 *  		records in the ARP database at AIOP.
 * 	        One database is maintained for a given virtual instance.
 * 	        This function first validates the incoming parameters
 * 	        and if all validations succeed, the following is performed
 * 	        depending on the type of operation:
 * 	        if operation is get_first, fetches first entry information from
 * 	        ARP database.
 * 	        if operation is get_next, finds the entry in the ARP database
 * 	        if operation is get_exact, finds the entry and returns it.
 *
 * @param[in]	flags - API behavioral flags.
 * @param[in]	in - Pointer to input param structure
 * 		which contains  ARP entry information.
 *
 * @param[in]	resp - Response arguments for asynchronous call.
 * @param[out]	out - Pointer to output param structure
 * 		that will be filled with output values of this API.
 *
 * @returns SUCCESS on success; FAILURE otherwise.
 * @ingroup	ARP
 */

int32_t nf_arp_entry_get(
    nf_ns_id nsid,
	const struct nf_arp_get_inargs *in,
	nf_api_control_flags flags,
	struct nf_arp_get_outargs *out,
	struct nf_api_resp_args *resp);

/*!
 * @brief	This API is used by applications to receive packets from AIOP.
 * @details	DP/AIOP can send   a packet to be given to applications running
 * 		in the Control Plane/GPP.
 * 		Applications at CP/GPP  register a function to
 * 		receive such packets from DP/AIOP and further process the packet.
 *
 * @param[in]	arp_appln_cbk_fns - pointer to the structure containing the
 * 		callback functions being registered by the ARP Application.
 * @returns SUCCESS on success; FAILURE otherwise.
 * @ingroup	ARP
 */

uint32_t nf_arp_appln_register_cbkfn(struct nf_arp_apln_register_cbkfns
                                        arp_appln_cbk_fns);



/*!
 * @brief	Fetches arp statistics.
 * @param[in]	nsid - Name Space ID for which the stats are to be retrieved.
 * @param[in]	in - input structure.
 * @param[out]	out - Structure where the statistics are filled.
 * @param[in]	flags - API behavioral flags.
 * @param[in]	respargs - Response arguments that will be passed
 * 		to the call back when the call is asynchronous.
 * @param[out]	out - Structure that will be filled with output values of this API.
 * @returns SUCCESS on success; FAILURE otherwise.
 *
 * @ingroup	ARP
 */

int32_t nf_arp_stats_get (nf_ns_id nsid,
		       const struct nf_arp_stats_inargs *in,
               nf_api_control_flags flags,
		       struct nf_arp_stats_outargs *out,
		       struct nf_api_resp_args  *respargs);

#endif /* ifndef __NF_ARP_H */
/*! @} */
