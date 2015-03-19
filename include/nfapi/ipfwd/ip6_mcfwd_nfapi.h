
/*!
 * @file ip6_mcfwd_nfapi.h
 * @brief This file contains the IPv6 multicast forward NF API & related
 * macros, data structures
 *
 * @addtogroup IPv6_Multicast
 * @{
 */

#ifndef __IP6MCFWD_NFAPI_H
#define __IP6MCFWD_NFAPI_H
#include "nfinfra_nfapi.h"

/*!
 * Following macro defines max number of multicast interfaces
 * that can be supported in the system. It is a tunable parameter
 */

#define NF_IP6_MCFWD_MAX_VIFS    32

/*!
 *  Differt Interface types for multicast interface entries
 */
enum nf_ip6_mcfwd_vif_type {
	NF_IP6_MCFWD_VIF_TYPE_STATIC  = 0, /**< Static interface */
	NF_IP6_MCFWD_VIF_TYPE_REGISTER /**< PIM Register interface */
};

/*!
 *  Structure for configuring multicast forward group entries
 */
struct nf_ip6_mcfwd_group {
	struct nf_ipv6_addr group_addr;/**< Multicast group address */
	nf_if_id ifid;  /**< Interface id */
};

/*!
 * structure for configuring multicast interface entries
 */
struct nf_ip6_mcfwd_vif_entry {
	uint8_t  threshold; /**< TTL threshold */
	enum nf_ip6_mcfwd_vif_type  vif_type; /**< Interface type,
                            * ex NF_IP6_MCFWD_VIF_TYPE_STATIC for physical interface
                            */
	uint32_t vif_id; /**< Virtual Interface Id, index for the vif table */
	nf_if_id link_id; /**< Interface index */
};
/*!
 * structure for deleting multicast interface entries
 */
struct nf_ip6_mcfwd_vif_entry_del {
	uint32_t vif_id; /**< Virtual Interface Id, index for the vif table */
};

/*!
 *  structure for configuring multicast route entries
 */
struct nf_ip6_mcfwd_route {
	struct nf_ipv6_addr mcastgrp; /**< Multicast group address */
	struct nf_ipv6_addr src_ip; /**< Source address of the packet */
	uint32_t vif_id; /**< Index of the mulitcast interface in the vif
                          * table
                          */
	uint8_t ttls[NF_IP6_MCFWD_MAX_VIFS]; /**< Time to live is an array
                                               * with max vifs entries
                                               */
};

/*!
 *  structure for deleting multicast route entries
 */
struct nf_ip6_mcfwd_route_del {
	struct nf_ipv6_addr mcastgrp; /**< Multicast group address */
	struct nf_ipv6_addr src_ip; /**< Source address of the packet */
};

/*!
 *  IP Multicast Forward interface statistics structure
 */
struct nf_ip6_mcfwd_vif_stats {
	uint64_t in_pkts; /**< Number of received packets */
	uint64_t in_bytes; /**< Number of received bytes */
	uint64_t out_pkts; /**< Number of packets sent */
	uint64_t out_bytes; /**< Number of bytes sent */
};

/*!
 *  IP Multicast Forward flow statistics structure
 */
struct nf_ip6_mcfwd_route_stats {
	uint64_t pkts; /**< Number of packets processed */
	uint64_t bytes; /**< Number of bytes processed  */
};

/*!
 *  Different ipv6 multicast route get operations
 */
enum nf_ip6_mcfwd_get_op {
        NF_IP6_MCFWD_GET_FIRST = 0, /**< Get First Operation */
        NF_IP6_MCFWD_GET_NEXT,   /**<  Get  Next Operation */
        NF_IP6_MCFWD_GET_EXACT  /**<  Get  Exact Operation */
};

/*!
 * Multicast interface specific group output arguments
 */

struct nf_ip6_mcfwd_group_outargs {
	int32_t result;/**< Result for multicast group specific configuration */
};

/*!
 * Multicast vif output arguments
 */

struct nf_ip6_mcfwd_vif_outargs {
	int32_t result;  /**<Result for Multicast vif configuration */
};

/*!
 * Multicast route output arguments
 */

struct nf_ip6_mcfwd_route_outargs {
	int32_t result; /**< Output result for Multicast route configuration */
};

/*!
 * Input parameters for fetching interface specific multicast group
 */

struct  nf_ip6_mcfwd_group_get_inargs {
	enum nf_ip6_mcfwd_get_op operation;
	/**< Operation mentions get_first/get_next/get_exact */
	/*! Following two fields are not valid for get_first */
	struct nf_ipv6_addr group_addr;/**< Multicast group address */
	nf_if_id ifid;  /**< interface id */
};
/*!
 * Out parameters for fetch to fetching multicast interface
 */

struct  nf_ip6_mcfwd_group_get_outargs {

	struct nf_ip6_mcfwd_group ip6_mcfwd_entry; /**< Interface specific
                                                   * multicast group structure
						   * instance
                                                   */
	int32_t result; /**< result for the Interface specific multicast group
                         * get operations
                         */
};

/*!
 * Input parameters for fetching multicast interface
 */
struct  nf_ip6_mcfwd_vif_get_inargs {
	enum nf_ip6_mcfwd_get_op operation;
	/**< Operation mentions get_first/get_next/get_exact */
        uint32_t  vif_id; /**< vif_id, index for the vif table */
};

/*!
 * Out parameters for fetch to interface details
 */
struct  nf_ip6_mcfwd_vif_get_outargs {

	struct nf_ip6_mcfwd_vif_entry ip6_mcfwd_entry; /**< Instance for VIF */
	struct nf_ip6_mcfwd_vif_stats  stats;/**< Statistics structure */
	int32_t result; /**< Result for VIF Get API */
};


/*!
 * Input parameters for fetching multicast route details
 */
struct  nf_ip6_mcfwd_route_get_inargs {
	enum nf_ip6_mcfwd_get_op operation; /**< Operation mentions
                                             * get_first/get_next/get_exact
                                             */
	/*!
         * Instance for Multicast route
         */
	struct nf_ip6_mcfwd_route  ip6_mcfwd_entry;
};

/*!
 * Out parameters for fetch to fetching multicast route details
 */
struct  nf_ip6_mcfwd_route_get_outargs{
	/*!
         * Instance for Multicast route
         */
	struct nf_ip6_mcfwd_route ip6_mcfwd_entry;
	struct nf_ip6_mcfwd_route_stats stats;/**< Statistics structure */
	int32_t result;  /**< Result for Multicast route Get API */
};

/*!
 * @brief  Callback function for processing packet
 * received from DP
 *
 * @param[in] pkt Pointer to  nf_pkt_buf structure.
 *
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Multicast
 */

typedef int32_t (*nf_ip6mcfwdappl_rcvselfpkt_fromdp_fn)(
		struct nf_pkt_buf *pkt);

/*!
 * IPv6  multicast forward application register structure
 */
struct nf_ip6_mcfwd_appln_register_cbk_fns {
	/*!
         * callback for processing packets
         */
	nf_ip6mcfwdappl_rcvselfpkt_fromdp_fn ipmcfwdappln_selfpkt_recvfn;
};

/*!
 * IPv6 Multicast Forward statastics structure
 */
struct nf_ip6_mcfwd_stats{
	uint64_t in_pkts;/**< Packets received */
	uint64_t fwd_pkts;/**< Packets forwarded */
	uint64_t drop_pkts; /**< Packets Droped */
	uint64_t out_pkts; /**< Out packets */
};

/*!
 * Structure used for output arguments for
 * ip6 mcfwd stats related NF API
 */
struct nf_ip6_mcfwd_stats_outargs
{
      int32_t result; /**< stores result*/
      struct nf_ip6_mcfwd_stats ip6_mcfwd_stats; /**< ip forward stats*/
};
/*!
 * Structure used for output arguments for
 * ip6 mcfwd set status NF API
 */
struct nf_ip6_mcfwd_status_outargs
{
	int32_t result; /**< stores result*/
};


/*!
 * IPv6 multicast forward Namespace specific status enable/disable
 */

enum nf_ip6_mcfwd_status_flag {
                NF_IP6_MCFWD_STATUS_ENABLE = 0, /**< Status Enable */
                NF_IP6_MCFWD_STATUS_DISABLE     /**< Status Disable */
};


/*!
 * @brief This API is used to add interface specific multicast group address.
 * This database is maintained per Name Space instance.
 * This function first validates the incoming parameters and if all validations
 * succeed, adds the entry in the database.
 * @param[in]   nsid  Name Space instance ID.
 * @param[in]   ip6_mcfwd_grp  Pointer to the struct nf_ip6_mcfwd_group.
 *  Following fields have to be populated. group_addr- Interested multicast
 *  group address. ifid -  interface id.
 * @param[in]	flags  API behavioural flags.
 * @param[in]   ip6_mcfwd_respargs  Response arguments that will be passed to
 * the call back when the call is asynchronous.
 * Following fields are to be filled by the caller:
 * cbfn - Call back function pointer to be invoked
 * cbarg  - Call back function argument
 * cbarg_len - Call back function argument	length
 * @param[out] ip6_mcfwd_outargs - Structure that will be filled with
 * output values of this API.
 * This structure is filled when the call is synchronous or asynchronous.
 * If asynchronous, this will be the last argument to the call back function
 * ip6_mcfwd_respargs described above.
 * Following fields are filled in the structure:
 * result : Result of this API. Success or failure code in case of failure.
 * @returns	0 on Success or negative value on failure
 * @ingroup IPv6_Multicast
 */

int32_t nf_ip6_mcfwd_group_add(nf_ns_id nsid,
	const struct nf_ip6_mcfwd_group *ip6_mcfwd_grp,
	nf_api_control_flags flags,
	struct nf_ip6_mcfwd_group_outargs *ip6_mcfwd_outargs,
	struct nf_api_resp_args  *ip6_mcfwd_respargs);


/*!
 * @brief  This API is used  to delete multicast group address configuration.
 * This database is maintained per Name Space instance.
 * This function first validates the
 * incoming parameters and if all validations succeed,
 *  deletes the entry  from the  database.
 * @param[in] nsid  Name Space instance ID.
 * @param[in] ip6_mcfwd_grp  Pointer to the struct nf_ip6_mcfwd_group.
 * Following fields have to be populated.
 * group_addr- Interested multicast group address.
 * ifid -  interface id.
 * @param[in]	flags  API behavioural flags.
 * @param[in]   ip6_mcfwd_respargs  Response arguments that will be passed
 * to the call back when the call is asynchronous.
 * Following fields are to be filled by the caller:
 * cbfn - Call back function pointer to be invoked
 * cbarg  - Call back function argument
 * cbarg_len - Call back function argument	length
 * @param[out] ip6_mcfwd_outargs  Structure that will be filled with output
 * values of this API.
 * This structure is filled when the call is synchronous or asynchronous.
 * If asynchronous, this will  be the last argument to the call back function
 * ip6_mcfwd_respargs described above.
 * Following fields are filled in the structure:
 * result : Result of this API. Success or failure code in case of failure.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Multicast
 */

int32_t nf_ip6_mcfwd_group_delete(nf_ns_id nsid,
	const struct nf_ip6_mcfwd_group *ip6_mcfwd_grp,
	nf_api_control_flags flags,
	struct nf_ip6_mcfwd_group_outargs *ip6_mcfwd_outargs,
	struct nf_api_resp_args  *ip6_mcfwd_respargs);

/*!
 * @brief  This API is used to fetch  ipv6 interface specific multicast group
 * address information. This database
 * is maintained per Name Space.
 * This function first validates the incoming parameters
 * and if all validations succeed, the following is performed depending on
 * the type of operation:
 * if operation is get_first, fetches first entry information
 * from Multicast group database.
 * if operation is get_next, finds the entry in the  database
 * with given information and returns the next entry.
 * if operation is get_exact, finds the entry and returns it.
 *
 * @param[in]  nsid   network namespace id.
 * @param[in]  in  Pointer to input param structure. Which contains multicast
 * group address  information.
 * @param[in]  flags  API behavioural flags.
 * @param[in]	resp  Response arguments for asynchronous call.
 * @param[out]	out  Pointer to output param structure that will be filled
 * with output values of this API.
 * result : Result of this API. Success or failure code in case of failure.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Multicast
 */

int32_t nf_ip6_mcfwd_group_get(nf_ns_id nsid,
	const struct nf_ip6_mcfwd_group_get_inargs *in,
	nf_api_control_flags flags,
	struct nf_ip6_mcfwd_group_get_outargs *out,
	struct nf_api_resp_args *resp);


/*!
 * This API is used to add ipv6 multicast interface configuration.
 * This database is maintained per Name Space instance. This
 * function first validates the incoming parameters and if
 * all validations succeed, adds the vif entry  in the vif database.
 * @param[in]  nsid - Name Space instance ID.
 * @param[in]  ip6_mcfwd_vif - input arguments that will be passed to this api.
 * The following fields have to be populated
 * threshold -  ttl threshold value for packets that should be sent over this
 * network device. This value will be copied into  multicast route
 * entry ttls array.
 * vif_type - vif_type ex: whether the VIF represents a physical interface
 * or PIM register interface. 
 * if it is physical interface this flag should be set with
 * NF_IP6_MCFWD_VIF_TYPE_STATIC
 * vif_id - multicast interface id value, each interface
 * will be identified by unique interface id.
 * link_id - index of the network device, each multicast interface is
 * associated with a network device index, that will be used for
 * subsequent packet processing.
 * @param[in]	flags  API behavioural flags.
 * @param[in] ip6_mcfwd_respargs  Response arguments that will be passed
 * to the call back when the call is asynchronous.
 * Following fields are to be filled by the caller:
 * cbfn - Call back function pointer to be invoked
 * cbarg  - Call back function argument
 * cbarg_len - Call back function argument length
 * @param[out] ip6_mcfwd_outargs  Structure that will be filled with
 * output values of this API.
 * This structure is filled when the call is synchronous or asynchronous.
 * If asynchronous, this will
 * be the last argument to the call back function
 * ip6_mcfwd_respargs described above.
 * Following fields are filled in the structure:
 * result : Result of this API. Success or failure code in case of failure.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Multicast
*/

int32_t nf_ip6_mcfwd_vif_add(nf_ns_id nsid,
	const struct nf_ip6_mcfwd_vif_entry *ip6_mcfwd_vif,
	nf_api_control_flags flags,
	struct nf_ip6_mcfwd_vif_outargs *ip6_mcfwd_outargs,
	struct nf_api_resp_args  *ip6_mcfwd_respargs);


/*!
 * This API is used to delete ipv6 multicast interface configuration.
 * This database is maintained per Name Space instance. This
 * function first validates the incoming parameters and if
 * all validations succeed, deletes the vif entry in the vif database.
 * @param[in]	nsid  Name Space instance ID.
 * @param[in]   ip6_mcfwd_vif  input arguments that will be passed to this api.
 * The following fields have to be populated
 * vif_id - multicast interface id value, each multicast interface
 * will be identified by unique interface id.
 * @param[in]	flags  API behavioural flags.
 * @param[in] ip6_mcfwd_respargs  Response arguments that will be passed to
 * the call back when the call is asynchronous.
 * Following fields are to be filled by the caller:
 * cbfn - Call back function pointer to be invoked
 * cbarg  - Call back function argument
 * cbarg_len - Call back function argument length
 * @param[out] ip6_mcfwd_outargs  Structure that will be filled with
 * output values of this API.
 * This structure is filled when the call is synchronous or asynchronous.
 * If asynchronous, this will  be the last argument to the call back function
 * ip6_mcfwd_respargs described above.
 * Following fields are filled in the structure:
 * result : Result of this API. Success or failure code in case of failure.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Multicast
*/

int32_t nf_ip6_mcfwd_vif_delete(nf_ns_id nsid,
	const struct nf_ip6_mcfwd_vif_entry_del *ip6_mcfwd_vif,
	nf_api_control_flags flags,
	struct nf_ip6_mcfwd_vif_outargs *ip6_mcfwd_outargs,
	struct nf_api_resp_args  *ip6_mcfwd_respargs);
/*!
 * @brief This API is used to fetch ipv6 multicast interface
 * information. This database is maintained per Name Space.
 * This function first validates the incoming parameters
 * and if all validations succeed, the following is performed depending on
 * the type of operation:
 * if operation is get_first, fetches first entry information
 * from ipv6 address database.
 * if operation is get_next, finds the entry in the  database
 * with given information and returns the next entry.
 * if operation is get_exact, finds the entry and returns it.
 * @param[in]	nsid   network namespace id.
 * @param[in]	in  Pointer to input param structure.
 * which contains  ipv6 address  information.
 * @param[in]	flags  API behavioural flags.
 * @param[in]	resp  Response arguments for asynchronous call.
 * @param[out]	out  Pointer to output param structure
 * that will be filled with output values of this API.
 * result : Result of this API. Success or failure code in case of failure.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Multicast
 */
int32_t nf_ip6_mcfwd_vif_get(nf_ns_id nsid,
	const struct nf_ip6_mcfwd_vif_get_inargs *in,
	nf_api_control_flags flags,
	struct nf_ip6_mcfwd_vif_get_outargs *out,
	struct nf_api_resp_args *resp);

/*!
 * @brief This API is used to add/update ipv6 multicast route.
 * The multicast route database built in the form of a hash table. 
 * This database is maintained per Name Space instance. 
 * This function first validates
 * the incoming parameters  and if all validations succeed, adds the  entry
 * in the mf entry database.
 * @param[in] nsid  Name Space instance ID.
 * @param[in] ip6_mcfwd_entry  input argument that will be passed to this api.
 * The following fields have to be populated
 * mcastgrp-  Multicast group address.
 * src_ip-  Source address of the packet.  mcastgrp and src_ip
 * together form the key
 * vif_id - Index of the multicast interface id in the vif table
 * over which packets this MF entry should arrive
 * ttl - is an array with max vifs entries, where each entry
 * specifies whether a packet
 * should be forwarded over the multicast interface or not.
 * @param[in]	flags  API behavioural flags.
 * @param[in] ip6_mcfwd_respargs  Response arguments that will be passed to
 * the call back when the call is asynchronous.
 * Following fields are to be filled by the caller:
 * cbfn - Call back function pointer to be invoked
 * cbarg  - Call back function argument
 * cbarg_len - Call back function argument	length
 * @param[out] ip6_mcfwd_outargs - Structure that will be filled with
 * output values of this API.
 * This structure is filled when the call is synchronous or asynchronous.
 * If asynchronous, this will be the last argument to the call back function
 * ip6_mcfwd_respargs described above.
 * Following fields are filled in the structure:
 * result : Result of this API. Success or failure code in case of failure.
 * Refer Return values of this API.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Multicast
*/

int32_t nf_ip6_mcfwd_route_add(nf_ns_id nsid,
	const struct nf_ip6_mcfwd_route *ip6_mcfwd_entry,
	nf_api_control_flags flags,
	struct nf_ip6_mcfwd_route_outargs *ip6_mcfwd_outargs,
	struct nf_api_resp_args  *ip6_mcfwd_respargs);


/*!
 * @brief This API is used to deletes ipv6 multicast route.
 * The multicast route database built in the form of a hash table.
 * This database is maintained per  Name Space instance.
 * This function first validates
 * the incoming parameters  and if all validations succeed, deletes the entry
 * in the mf entry database.
 * @param[in] nsid  Name Space instance ID.
 * @param[in] ip6_mcfwd_entry  input argument that will be passed to this api.
 * The following fields have to be populated
 * mcastgrp-  Multicast group address.
 * src_ip-  Source address of the packet. mcastgrp and src_ip
 * together form the key.
 * @param[in]	flags  API behavioural flags.
 * @param[in] ip6_mcfwd_respargs  Response arguments that will be passed to
 * the call back when the call is asynchronous.
 * Following fields are to be filled by the caller:
 * cbfn - Call back function pointer to be invoked
 * cbarg  - Call back function argument
 * cbarg_len - Call back function argument	length
 * @param[out] ip6_mcfwd_outargs - Structure that will be filled with
 * output values of this API.
 * This structure is filled when the call is synchronous or asynchronous.
 * If asynchronous, this will be the last argument to the call back function
 * ip6_mcfwd_respargs described above.
 * Following fields are filled in the structure:
 * result : Result of this API. Success or failure code in case of failure.
 * Refer Return values of this API.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Multicast
*/

int32_t nf_ip6_mcfwd_route_delete(nf_ns_id nsid,
		const struct nf_ip6_mcfwd_route_del *ip6_mcfwd_entry,
		nf_api_control_flags flags,
		struct nf_ip6_mcfwd_route_outargs *ip6_mcfwd_outargs,
		struct nf_api_resp_args  *ip6_mcfwd_respargs);

/*!
 * @brief This API is used to fetch multicast route information
 * along with multicast route stats.
 * This database is maintained per Name Space.
 * This function first validates the incoming parameters
 * and if all validations succeed, the following is performed depending on
 * the type of operation:
 * if operation is get_first, fetches first entry information
 * from ipv6 address database.
 * if operation is get_next, finds the entry in the  database
 *  with given information and returns the next entry.
 * if operation is get_exact, finds the entry and returns it.
 * @param[in]	nsid   network namespace id.
 * @param[in]	in  Pointer to input param structure.
 * @param[in]	flags  API behavioural flags.
 * @param[in]	resp  Response arguments for asynchronous call.
 * @param[out]	out  Pointer to output param structure
 * result : Result of this API. Success or failure code in case of failure.
 * Refer Return values of this API.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Multicast
*/
int32_t  nf_ip6_mcfwd_route_get(nf_ns_id nsid,
	const struct nf_ip6_mcfwd_route_get_inargs *in,
	nf_api_control_flags flags,
	struct nf_ip6_mcfwd_route_get_outargs *out,
	struct nf_api_resp_args *resp);


/*!
 * @brief  DP can send self-destined packet to application for the
 * packet to be given to local applications in the Control Plane.
 * IP multicast Forward application at CP will register a function to
 * receive such packets from DP and further process the packet.
 *
 * @param[in] ip6_mcfwd_appln_cbkfn  pointer to the structure containing the
 * callback functions being registered by the Ip Forward Application.
 *
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Multicast
*/

int32_t nf_ip6_mcfwd_appln_register_cbkfn(
	struct nf_ip6_mcfwd_appln_register_cbk_fns *ip6_mcfwd_appln_cbkfn);

/*!
 * @brief  Send packet from CP to DP.
 * @param[in]  	nsid  Name Space ID.
 * @param[in] 	pkt  Packet to send out
 * @param[in] 	flags  API behavioural flags.
 * @param[in]	ip6_mcfwd_send_pkt_respargs -
 * Response arguments for asynchronous call.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Multicast
*/

int32_t nf_ip6_mcfwd_appln_send_pkt_to_dp(nf_ns_id nsid,
	void *pkt  /*Buffer from CP  - TBD */,
	nf_api_control_flags flags,
	struct nf_api_resp_args *ip6_mcfwd_send_pkt_respargs);

/*!
 * @brief  This API is used to set IP multicast forward
 * status as enable/disable for a given name space.
 * @param[in]        nsid  NamesSpace ID.
 * @param[in]        status  Status indicating enable/disable.
 * @param[in]        flags  API behavioural flags.
 * @param[in]        resp  Response arguments for asynchronous call.
 * result : Result of this API. Success or failure code in case of failure.
 * @returns	0 on Success or negative value on failure
 * @ingroup IPv6_Multicast
*/

int32_t nf_ip6_mcfwd_set_status(
	nf_ns_id nsid,
	enum nf_ip6_mcfwd_status_flag status,
	nf_api_control_flags flags,
	struct nf_ip6_mcfwd_status_outargs *out_args,
	struct nf_api_resp_args *resp);

/*!
 * @brief  This API is used to get IPv6 multicast forward
 * statastics for a given name space.
 * @param[in]  nsid  NamesSpace ID.
 * @param[in]  flags  API behavioural flags.
 * @param[out] ip6_out_args Pointer to
 *             struct nf_ip6_mcfwd_stats_outargs structure.
 * @param[in]  resp  Response arguments for asynchronous call.
 * result : Result of this API. Success or failure code in case of failure.
 * @returns	0 on Success or negative value on failure
 * @ingroup IPv6_Multicast
*/
int32_t nf_ip6_mcfwd_stats_get(nf_ns_id nsid,
      nf_api_control_flags flags,
      struct nf_ip6_mcfwd_stats_outargs *ip6_out_args,
      struct nf_api_resp_args  *ip6_fwd_stats_respargs);

#endif /* __IP6MCFWD_NFAPI_H */
/*! @} */
