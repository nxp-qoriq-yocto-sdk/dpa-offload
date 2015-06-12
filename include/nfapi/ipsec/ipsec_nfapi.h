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
 * @file ipsec_nfapi.h
 *
 * @brief This file contains the IPSec NF APIs, related macros and data
 * structures.
 *
 * @addtogroup	IPSEC
 * @{
 */

#ifndef __IPSEC_API_H
#define __IPSEC_API_H



/*!
 * SPD Policy/SA direction information
 */
enum nf_ipsec_direction {
	NF_IPSEC_INBOUND =1, 	/**< Inbound Direction */
	NF_IPSEC_OUTBOUND 	/**< Outbound Direction */
};


/*!
 * SPD Policy Action information
 */
enum nf_ipsec_policy_rule_action {
	NF_IPSEC_POLICY_ACTION_IPSEC = 1, 	/**< Apply IPSec processing on Packet*/
	NF_IPSEC_POLICY_ACTION_DISCARD, 	/**< Discard or Drop the packet */
	NF_IPSEC_POLICY_ACTION_BYPASS 	/**< Bypass/Allow to pass the packet */
};

/*!
 * SPD Policy Position information
 */
enum nf_ipsec_policy_rule_position{
	NF_IPSEC_POLICY_POSITION_BEGIN = 1,/**< Add at the beginning of the list */
	NF_IPSEC_POLICY_POSITION_BEFORE, 	/**< Add before the mentioned Policy */
	NF_IPSEC_POLICY_POSITION_AFTER, 	/**< Add after the mentioned Policy */
	NF_IPSEC_POLICY_POSITION_END 	/**< Add at the end of the list */
};


/*!
 * DSCP Range information
 */
struct nf_ipsec_policy_rule_dscprange {
	uint8_t start; 	/**< Start value in Range */
	uint8_t end; 	/**< End value  in Range */
};

/*!
 * Fragmentation Options information
 */
enum nf_ipsec_policy_handle_fragments_opts {
	NF_IPSEC_POLICY_FRAGOPTS_REASSEMBLE_BEFORE_IPSEC=1,
	/**< IPSec Policy for Frag Option to Reassemble
	 * before IPsec.
	 */

	NF_IPSEC_POLICY_FRAGOPTS_SAMESA_FOR_NONINITIAL_FRAG,
	/**< IPSec Policy for Frag option for same SA for
	 * non-initial fragments.
	 */

	NF_IPSEC_POLICY_FRAGOPTS_STATEFUL_FRAG_CHECK,
	/**< IPSec Policy for Frag option stateful
	 * fragmentation check.
	 */

	NF_IPSEC_POLICY_FRAGOPTS_SEPARATESA_FOR_NONINITIAL_FRAG
	/**< IPSec Policy for Frag option for separate
	 * SA for non-initial fragments.
	 */
};

/*!
 * Fragmentation Before Encapsulation (Redside Fragmentation)
 */
enum nf_ipsec_policy_redside_fragmentation {
	NF_IPSEC_POLICY_REDSIDE_FRAGMENTATION_DISABLE = 0,
			/**< Diasable Redside fragmentation in IPSec Policy */
	NF_IPSEC_POLICY_REDSIDE_FRAGMENTATION_ENABLE
			/**< Enable Redside fragmentation in IPSec Policy */
};


#define NF_IPSEC_SEL_PROTOCOL_ANY 0
		/**< Protocol as ANY */

/*!
 * IPSec Selector  information
 */

struct nf_ipsec_selector {
	enum nf_ip_version version;	/*!< IP Version */
	uint8_t protocol;	/*!< IP Transport Protocol or ANY */
	struct nf_l4_port src_port;
		/*!< IP Source Port or ICMP Type(If protocol is ICMP) */
	struct nf_l4_port dest_port;
		/*!< IP Destination Port or ICMP code(If protocol is ICMP) */
/*! Union details
*/
	union {
		struct nf_ipv4_addr_info src_ip4;
			/*!< Source IPv4 address */
		struct nf_ipv6_addr_info src_ip6;
			/*!< Source IPv6 address */
	};

/*! Union details
*/
	union {
		struct nf_ipv4_addr_info dest_ip4;
			/*!< Destination IPv4 address */
		struct nf_ipv6_addr_info dest_ip6;
			/*!< Destination IPv6 address */
	};
};


/*!
 * SPD Policy Policy Status information
 */
enum nf_ipsec_policy_rule_status{
	NF_IPSEC_POLICY_STATUS_ENABLE = 0,	/**< Enable IPSec Policy */
	NF_IPSEC_POLICY_STATUS_DISABLE 	/**< Disable IPSec Policy */
};

/*!
 * SPD Policy Parameters information
 */
struct nf_ipsec_policy {
	uint32_t policy_id;
	/**< Policy ID that uniquely identifies the
	 * policy within a given Name Space and Tunnel instance.
	 */

	enum nf_ipsec_policy_rule_action action; 	/**< SPD Policy Action */
	enum nf_ipsec_policy_rule_status status; 	/**< SPD Policy Status */
	enum nf_ipsec_policy_rule_position position;
						/**< Policy Position */
	uint32_t relative_policy_id; /**< Relative Policy ID */
	uint8_t n_dscp_ranges; 			/**< Number of DSCP Ranges */
	struct nf_ipsec_policy_rule_dscprange *dscp_ranges;
						/**< Array of DSCP Ranges */
	enum nf_ipsec_policy_redside_fragmentation redside;
	/**< Fragmentation before Encapsulation option: TRUE/FALSE */
	enum nf_ipsec_policy_handle_fragments_opts fragments_opts;
	/**< Fragment handling options */
	uint32_t n_selectors; 			/**< Number of selectors */
	struct nf_ipsec_selector *selectors; 	/**< Array of Selectors */
};

/*!
 * Input parameters to SPD Policy addition
 */
struct nf_ipsec_spd_add_inargs{
	uint32_t tunnel_id;  		/**< Tunnel ID */
	enum nf_ipsec_direction dir; 	/**< Direction: Inbound or Outbound */
	struct nf_ipsec_policy spd_params;
	/**< Policy details.   */
};

/*!
 * Output parameters to SPD Policy addition
 */
struct nf_ipsec_spd_add_outargs{
	int32_t result;
	/**< 0:Success; Non Zero value: Error code indicating failure */
};

/*!
 * @brief This API is used to add Inbound/Outbound SPD policy to SPD policy
 * database.  This database is maintained per Name Space and Tunnel instance.
 * This function first validates the incoming parameters
 * and if all validations succeed, new SPD policy is added to the database.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] in  Pointer to input param structure
 * which contains  spd policy information.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @param[out] out  Pointer to output param structure
 * that will be filled with output values of this API.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD)
 * @endinternal
 *
 * @ingroup IPSEC
 */
int32_t nf_ipsec_spd_add(
	nf_ns_id nsid,
	const struct nf_ipsec_spd_add_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_spd_add_outargs *out,
	struct nf_api_resp_args *resp);

/*!
 * Input parameters to SPD Policy deletion
 */

struct nf_ipsec_spd_del_inargs {
	uint32_t tunnel_id;  		/**< Tunnel ID */
	enum nf_ipsec_direction dir; 	/**< Direction: Inbound or Outbound */
	uint32_t policy_id;
	/**< Policy ID that uniquely identifies
	 * the policy within a given Name Space and Tunnel instance. */
};

/*!
 * Output parameters to SPD Policy deletion
 */
struct nf_ipsec_spd_del_outargs{
	int32_t result;
		/**< 0:Success; Non Zero value: Error code indicating failure */
};

/*!
 * @brief This API is used to delete Inbound/Outbound SPD policy from SPD policy
 * database.  This database is maintained per Name Space and Tunnel instance.
 * This function first validates the incoming parameters
 * and if all validations succeed, finds the entry in the database
 * with given information and deletes it.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] in  Pointer to input param structure
 * which contains  spd policy information.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @param[out] out  Pointer to output param structure
 * that will be filled with output values of this API.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD)
 * @endinternal
 *
 * @ingroup IPSEC
 */
int32_t nf_ipsec_spd_del(
	nf_ns_id nsid,
	const struct nf_ipsec_spd_del_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_spd_del_outargs *out,
	struct nf_api_resp_args *resp);

/*!
 * Input parameters to SPD Policy modification
 */
struct nf_ipsec_spd_mod_inargs{
	uint32_t tunnel_id;  		/**< Tunnel ID */
	enum nf_ipsec_direction dir; 	/**< Direction: Inbound or Outbound */
	struct nf_ipsec_policy spd_params;
	/**< Policy details.   */
};

/*!
 * Output parameters to SPD Policy modification
 */
struct nf_ipsec_spd_mod_outargs{
	int32_t result;
	/**< 0:Success; Non Zero value: Error code indicating failure */
};

/*!
 * @brief This API is used to modify Inbound/Outbound SPD policy.
 * SPD Policy database is maintained per Name Space and Tunnel instance.
 * This function first validates the incoming parameters
 * and if all validations succeed,finds the entry in the database
 * with given information and modifies it.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] in  Pointer to input param structure
 * which contains  spd policy information.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @param[out] out  Pointer to output param structure
 * that will be filled with output values of this API.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD)
 * @endinternal
 *
 * @ingroup IPSEC
 */
int32_t nf_ipsec_spd_mod(
	nf_ns_id nsid,
	const struct nf_ipsec_spd_mod_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_spd_mod_outargs *out,
	struct nf_api_resp_args *resp);

/*!
 * SPD Policy Statistics information structure
 */
struct nf_ipsec_spd_stats {
	uint64_t received_pkts;
		/**< Received Outbound/Inbound packets */
	uint64_t processed_pkts;
		/**< Processed Outbound/Inbound packets */
	uint64_t pkts_to_apply_sec;
		/**< Received Outbound/Inbound packets to apply security */
	uint64_t sec_applied_pkts;
		/**< Outbound/Inbound packets applied security */
	uint64_t processed_bytes;
		/**< Number of bytes processed on Inbound/Outbound policy */
	struct {
		uint32_t crypto_op_failed;
			/**< Crypto operations failed */
	}protocol_violation_errors;
	struct {
		uint32_t no_matching_dscp_range;
		/**< Matching dscp range not found in the SPD policy */

		uint32_t submit_to_sec_failed;
			/**< Submission to SEC failed for crypto operations */
		uint32_t icmp_sent_for_pmtu;
			/**< ICMP error message sent for PMTU */
		uint32_t sa_hard_life_time_expired;
			/**< SA hard life time expired */
		uint32_t no_outb_sa;
			/**< Outbound SA not found */
		uint32_t frag_failed;
			/**< Fragmentation failed */
	}local_errors;

	/*!
	 * @internal
	 * @todo TBD
	 * @endinternal
	 */

};

/*!
 * SPD fetch operations
 */
enum nf_ipsec_spd_get_op {
	NF_IPSEC_SPD_GET_FIRST = 0,/**< Fetch first entry in the database */
	NF_IPSEC_SPD_GET_NEXT, 	/**< Fetch next entry for given SPD policy */
	NF_IPSEC_SPD_GET_EXACT	/**< Fetch entry for given SPD policy*/
};

/*!
 * Use for nf_ipsec_spd_get_inargs.flags
 */

#define NF_IPSEC_SPD_GET_STATS    0x1 /**<  Fetch SPD statistics */
#define NF_IPSEC_SPD_GET_PARAMS 0x2 /**< Fetch SPD parameters */

/*!
 * Input parameters to fetch SPD Policy information
 */
struct nf_ipsec_spd_get_inargs{
	uint32_t tunnel_id;  		/**< Tunnel ID */
	enum nf_ipsec_direction dir; 	/**< Direction: Inbound or Outbound */
	enum nf_ipsec_spd_get_op operation;
		/**< Operation mentions get_first/get_next/get_exact */
	uint32_t flags;
		/**< Flags indicate to get complete SPD information
	 	 * or only statistics or only policy details
	 	 */
	uint32_t policy_id;
	/**< Policy ID that uniquely identifies
	 * the policy within a given Name Space and Tunnel instance.
	 * Not valid/filled for get_first
	 */
	uint32_t max_n_selectors;
		/**< Memory available to hold this number of
		 * selectors for in the outargs(spd_params.selectors)
		 */
	uint32_t max_n_dscp_ranges;
		/**< Memory available to hold this number of
		 * dscp ranges for in the outargs(spd_params.dscp_ranges)
		 */

};

/*!
 * Output parameters to fetch SPD Policy information
 */
struct nf_ipsec_spd_get_outargs{
	int32_t result;
	/**< 0:Success; Non Zero value: Error code indicating failure */
	struct nf_ipsec_policy spd_params;/**< Policy details */
	struct nf_ipsec_spd_stats stats; 	/**< SPD policy related stats */
};

/*!
 * @brief This API is used to fetch Inbound/Outbound SPD information.
 * This database is maintained per Name Space and Tunnel instance.
 * This function first validates the incoming parameters
 * and if all validations succeed, the following is performed
 * depending on the type of operation:
 * if operation is get_first, fetches first entry information
 * from SPD database.
 * if operation is get_next, finds the entry in the SPD database
 * with given information and returns the next entry.
 * if operation is get_exact, finds the entry and returns it.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] in  Pointer to input param structure
 * which contains  spd policy information.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @param[out] out  Pointer to output param structure
 * that will be filled with output values of this API.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD)
 * @endinternal
 *
 * @ingroup IPSEC
 */

int32_t nf_ipsec_spd_get(
	nf_ns_id nsid,
	const struct nf_ipsec_spd_get_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_spd_get_outargs *out,
	struct nf_api_resp_args *resp);


/*!
 * @brief This API is used to flush/delete all Inbound and Outbound SPD
 * policies in a given name space.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD)
 * @endinternal
 *
 * @ingroup IPSEC
 */
int32_t nf_ipsec_spd_flush(
	nf_ns_id nsid,
	nf_api_control_flags flags,
	struct nf_api_resp_args *resp);


/*!
 * Input parameters to  ICMP Error Message Type and Code Policy
 * addition
 */
struct nf_ipsec_icmp_err_msg_typecode_add_inargs{
	uint8_t entry_id;
		/**< ID is used to identify the policy uniquely
 		 * in the database
		 */
	enum nf_ip_version version; /**< IP Version */
	uint8_t type; 		/**< ICMP Type */
	uint8_t start_code; 	/**< ICMP start code */
	uint8_t end_code; 	/**< ICMP end code */
};

/*!
 * Output parameters to ICMP Error Message Type and Code Policy
 * addition
 */
struct nf_ipsec_icmp_err_msg_typecode_add_outargs {
	int32_t result;
		/**< 0:Success; Non Zero value: Error code indicating failure */
};

/*!
 * @brief This API is used to add ICMP Error Message Type and Code configuration
 * to ICMP database. This database is maintained per Name Space instance.
 * This function first validates the incoming parameters
 * and if all validations succeed, new ICMP policy is added to the database.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] in  Pointer to input param structure
 * which contains  ICMP error message type and code information.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @param[out] out  Pointer to output param structure
 * that will be filled with output values of this API.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD)
 * @endinternal
 *
 * @ingroup IPSEC
 */
int32_t nf_ipsec_icmp_err_msg_typecode_add(
	nf_ns_id nsid,
	const struct nf_ipsec_icmp_err_msg_typecode_add_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_icmp_err_msg_typecode_add_outargs *out,
	struct nf_api_resp_args *resp);

/*!
 * Input parameters to  ICMP Error Message Type and Code Policy
 * deletion
 */
struct nf_ipsec_icmp_err_msg_typecode_del_inargs{
	uint8_t entry_id;
		/**< ID is used to identify the policy uniquely
 		 * in the database
		 */
};

/*!
 * Output parameters to ICMP Error Message Type and Code Policy
 * deletion
 */
struct nf_ipsec_icmp_err_msg_typecode_del_outargs {
	int32_t result;
		/**< 0:Success; Non Zero value: Error code indicating failure */
};

/*!
 * @brief This API is used to delete ICMP Error Message Type and Code policy from ICMP
 * database.  This database is maintained per Name Space instance.
 * This function first validates the incoming parameters
 * and if all validations succeed, finds the entry in the database
 * with given information and deletes it.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] in  Pointer to input param structure
 * which contains  ICMP error message type and code information.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @param[out] out  Pointer to output param structure
 * that will be filled with output values of this API.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD)
 * @endinternal
 *
 * @ingroup IPSEC
 */
int32_t nf_ipsec_icmp_err_msg_typecode_del(
	nf_ns_id nsid,
	const struct nf_ipsec_icmp_err_msg_typecode_del_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_icmp_err_msg_typecode_del_outargs *out,
	struct nf_api_resp_args *resp);

/*!
 * Input parameters to  ICMP Error Message Type and Code Policy
 * modification
 */
struct nf_ipsec_icmp_err_msg_typecode_mod_inargs{
	uint8_t entry_id;
		/**< ID is used to identify the policy uniquely
 		 * in the database
		 */
	enum nf_ip_version version; /**< IP Version */
	uint8_t type; 		/**< ICMP Type */
	uint8_t start_code; 	/**< ICMP start code */
	uint8_t end_code; 	/**< ICMP end code */
};

/*!
 * Output parameters to ICMP Error Message Type and Code Policy
 * modification
 */
struct nf_ipsec_icmp_err_msg_typecode_mod_outargs {
	int32_t result;
		/**< 0:Success; Non Zero value: Error code indicating failure */
};

/*!
 * @brief This API is used to modify ICMP Error Message Type and Code policy.
 * ICMP policy database is maintained per Name Space instance.
 * This function first validates the incoming parameters
 * and if all validations succeed,finds the entry in the database
 * with given information and modifies it.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] in  Pointer to input param structure
 * which contains  ICMP message type and code information.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @param[out] out  Pointer to output param structure
 * that will be filled with output values of this API.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD)
 * @endinternal
 *
 * @ingroup IPSEC
 */
int32_t nf_ipsec_icmp_err_msg_typecode_mod(
	nf_ns_id nsid,
	const struct nf_ipsec_icmp_err_msg_typecode_mod_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_icmp_err_msg_typecode_mod_outargs *out,
	struct nf_api_resp_args *resp);

/*!
 * ICMP fetch operations
 */
enum nf_ipsec_icmp_get_op {
	NF_IPSEC_ICMP_GET_FIRST = 0,
		/**< Fetch first entry in the database */
	NF_IPSEC_ICMP_GET_NEXT,
		/**< Fetch next entry for given ICMP Type & Code policy */
	NF_IPSEC_ICMP_GET_EXACT
		/**< Fetch entry for given ICMP Type & Code policy */
};

/*!
 * Input parameters to fetch
 * ICMP Error Message Type and Code Policy Configuration
 */
struct nf_ipsec_icmp_err_msg_typecode_get_inargs{
	enum nf_ipsec_icmp_get_op operation;
	/**< Operation mentions get_first/get_next/get_exact */
	uint8_t entry_id;
	/**< ID is used to identify the policy uniquely in the
 	 * database. Not valid for get_first operation
	 */
};

/*!
 * Output parameters to fetch
 * ICMP Error Message Type and Code Policy Configuration
 */
struct nf_ipsec_icmp_err_msg_typecode_get_outargs {
	int32_t result;
	/**< 0:Success; Non Zero value: Error code indicating failure */
	enum nf_ip_version version; /**< IP Version */
	uint8_t type; 		/**< ICMP Type */
	uint8_t start_code; 	/**< ICMP start code */
	uint8_t end_code; 	/**< ICMP start code */
};

/*!
 * @brief This API is used to fetch ICMP Message Type and Code
 * information.
 * This database is maintained per Name Space.
 * This function first validates the incoming parameters
 * and if all validations succeed, the following is performed
 * depending on the type of operation:
 * if operation is get_first, fetches first entry information
 * from ICMP database.
 * if operation is get_next, finds the entry in the ICMP database
 * with given information and returns the next entry.
 * if operation is get_exact, finds the entry and returns it.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] in  Pointer to input param structure
 * which contains  ICMP record information.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @param[out] out  Pointer to output param structure
 * that will be filled with output values of this API.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD)
 * @endinternal
 *
 * @ingroup IPSEC
 */
int32_t nf_ipsec_icmp_err_msg_typecode_get(
	nf_ns_id nsid,
	const struct nf_ipsec_icmp_err_msg_typecode_get_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_icmp_err_msg_typecode_get_outargs *out,
	struct nf_api_resp_args *resp);


/*!
 * SA Selector information
 */
struct nf_ipsec_sa_selector {
	uint32_t policy_id;   /**<  Corresponding SPD Policy ID */
	struct nf_ipsec_selector  selector;
	/**< Selector information for which SA processing is required */
};

/*!
 * NAT Port information
 */
struct nf_ipsec_nat_info{
	uint16_t dest_port; 		/**< Destination Port */
	uint16_t src_port; 		/**< Source Port */
	struct nf_ip_addr nat_oa_peer_addr;
	/**< Original Peer address, valid if encapsulation mode is Transport */
};


/*!
 * Tunnel end points information
 */
struct nf_ipsec_tunnel_end_addr{
	struct nf_ip_addr src_ip; 	/**< Tunnel Source IP Address */
	struct nf_ip_addr dest_ip; /**< Tunnel Destination IP Address */
};

/*!
 * @internal
 * IPSec Security Protocol Macros
 * @endinternal
 */
#define NF_IPSEC_PROTOCOL_ESP 50 /**< IPSec Protocol is ESP */
#define NF_IPSEC_PROTOCOL_AH  51 /**< IPSec Protocol is AH */

/*!
 * IPSec SA DF bit handle values
 */
enum nf_ipsec_df_bit_handle {
	NF_IPSEC_DF_COPY = 1,
		/**< Handle DF bit.  Copy DF bit from inner to outer header */
	NF_IPSEC_DF_CLEAR,
		/**< Handle DF bit.  Clear DF bit in outer header */
	NF_IPSEC_DF_SET
		/**< Handle DF bit.  Set DF bit in outer header */
};

/*!
 * IPSec SA DSCP handle values
 */
enum nf_ipsec_dscp_handle {
	NF_IPSEC_DSCP_COPY = 1,
		/**< Copy DSCP value from inner to outer header */
	NF_IPSEC_DSCP_CLEAR,
		/**< Clear(no) DSCP value in outer header */
	NF_IPSEC_DSCP_SET
		/**< Set with mentioned DSCP value in outer header */
};

/*!
 * Inbound SA flags information
 */
enum nf_ipsec_inb_sa_flags {

	NF_IPSEC_INB_SA_VERIFY_PKTSEL_WITH_SA_SEL = BIT(1),
	/**< When enabled, the decrypted packet's selectors will
	 * be checked against the SA's selectors, to ensure packet arrival on
	 * the right SA.
	 */
	NF_IPSEC_INB_SA_DO_PEERGW_CHANGE_ADAPTATION = BIT(2),
	/**< When this flag is enabled and IPSEC-DP detects changes in the peer
  	 * gateway as part of inbound processing, the changes will be
  	  * applied for outbound SA so that traffic through the tunnel will
  	  * not be disrupted.
  	  */

	NF_IPSEC_INB_SA_VERIFY_INBOUND_SPD_POLICY = BIT(3),
	/**< When enabled, inbound policy is searched for the decrypted packet
	 * and it is compared against the policy stored in the SA selector,
	 * to ensure packet arrival on right SA and SPD policy.
	 */

	NF_IPSEC_INB_SA_PROPOGATE_ECN = BIT(4),
	/**< When enabled,  ECN value from the outer tunnel packet
	 * will get populated to the decrypted packet's IP header, for those
	 * processed off this SA.
	 */
};

/*!
 * Outbound SA flags information
 */
enum nf_ipsec_outb_sa_flags {
	NF_IPSEC_OUTB_SA_REDSIDE_FRAGMENTATION = BIT(1),
	/**< When enabled, packets processed against this SA should undergo
	 * Red-side fragmentation(Fragmentation before encapsulation).
	 * Red-side fragmentation is done on the packets for the which
	 * the post-encryption packet size exceeds the Path MTU.
	 */
};

/*!
 * Common SA flags information for Inbound and Outbound SA
 */
enum nf_ipsec_sa_flags {
	NF_IPSEC_SA_DO_UDP_ENCAP_FOR_NAT_TRAVERSAL = BIT(1),
	/**< When enabled, this indicates that IPSEC-DP has to do
	 * UDP encapsulation/decapsulation for IPSEC packet so that they
	 * can traverse through NAT boxes. UDP encapsulation/decapsulation
	 * is to be applied for packets that get processed off this SA.
	 */

	NF_IPSEC_SA_USE_ESN = BIT(2),
	/**< While encrypting and decrypting packets, extended
	 * sequence number will be used for anti-replay window check.
	 */

	NF_IPSEC_SA_LIFETIME_IN_SEC = BIT(3),
	/**< This indicates that the SA life time is in seconds */

	NF_IPSEC_SA_LIFETIME_IN_KB = BIT(4),
	/**< This indicates that the SA life time is in kilo bytes */

	NF_IPSEC_SA_LIFETIME_IN_PKT_CNT = BIT(5),
	/**< This indicates that the SA life time is in packet count */

	NF_IPSEC_SA_DO_ANTI_REPLAY_CHECK = BIT(6),
	/**< When enabled, it indicates that packets need to be encrypted
	 * and sent out with valid sequence numbers such that it passes
	 * anti-replay window check at the peer gateway. similarly on the
	 * inbound side, sequence number in the packet will undergo anti-replay
	 * checks.
	 */

	NF_IPSEC_SA_ENCAP_TRANSPORT_MODE = BIT(7)
	/**< This indicates that the encapsulation mode
	 * used on the SA is transport.
	 */

};
/*!
 * Authentication Algorithms information
 */
enum nf_ipsec_auth_alg {
	NF_IPSEC_AUTH_ALG_NONE=1, 	/**< No Authentication */
	NF_IPSEC_AUTH_ALG_MD5HMAC, /**< MD5 HMAC Authentication Algorithm */
	NF_IPSEC_AUTH_ALG_SHA1HMAC,/**< SHA1 HMAC Authentication Algorithm */
	NF_IPSEC_AUTH_ALG_AESXCBC, /**< AES-XCBC Authentication Algorithm */
	NF_IPSEC_AUTH_ALG_SHA2_256_HMAC,
	/**< SHA2 HMAC Authentication Algorithm with Key length 256 bits*/
	NF_IPSEC_AUTH_ALG_SHA2_384_HMAC,
	/**< SHA2 HMAC Authentication Algorithm with Key length 384 bits*/
	NF_IPSEC_AUTH_ALG_SHA2_512_HMAC,
	/**< SHA2 HMAC Authentication Algorithm with Key length 512 bits*/
};

/*!
 * Encryption Algorithms information
 */
enum nf_ipsec_cipher_alg{
	NF_IPSEC_ENC_ALG_NULL=1, 	/**< NULL Encryption Algorithm */
	NF_IPSEC_ENC_ALG_DES_CBC, 	/**< DES-CBC Encryption Algorithm */
	NF_IPSEC_ENC_ALG_3DES_CBC, /**< 3DES-CBC Encryption Algorithm */
	NF_IPSEC_ENC_ALG_AES_CBC, 	/**< AES-CBC Encryption Algorithm */
	NF_IPSEC_ENC_ALG_AES_CTR 	/**< AES-CTR Encryption Algorithm */
};

/*!
 * Combined mode Algorithms information
 */
enum nf_ipsec_comb_alg{
	NF_IPSEC_COMB_AES_CCM=1,	/**< AES-CCM Combined mode Algorithm */
	NF_IPSEC_COMB_AES_GCM, 	/**< AES-GCM Combined mode Algorithm */
	NF_IPSEC_COMB_AES_GMAC 	/**< AES-GMAC Combined mode Algorithm */
};

/*!
* IP Compression Algorithms information
*/
enum nf_ipsec_ipcomp_alg{
        NF_IPSEC_IPCOMP_DEFLATE=1,      /**< Deflate IP Compression Algorithm */
        NF_IPSEC_IPCOMP_LZS,    /**< LZS IP Compression  Algorithm */
};

/*!
* IP Compression protocol information
*/
struct nf_ipsec_ipcomp_info {
	enum nf_ipsec_ipcomp_alg algo;	/**< IP Compression algorithm */
	uint32_t cpi;	/**< Compression parameter index */
};

/*!
 * SA crypto suite information
 */
struct nf_ipsec_sa_crypto_params {
	enum nf_ipsec_auth_alg auth_algo;
		/**< Authentication algorithm */
	uint8_t *auth_key;
		/**< Authentication key */
	uint32_t auth_key_len_bits;
		/**< Authentication key length in bits */
	enum nf_ipsec_cipher_alg cipher_algo;
		/**< Encryption algorithm */
	uint8_t *cipher_key;
		/**< Encryption/decryption Key */
	uint32_t cipher_key_len_bits;
		/**< Encryption/decryption Key Length in bits.
	 	* It holds the nonce length (32 bits) followed by
	 	* the key, if encryption algorithm is AES-CTR.
	 	*/
	enum nf_ipsec_comb_alg comb_algo;
		/**< Combined mode/aead algorithm.*/
	uint8_t *comb_key;
		/**< Combined mode key.  */
	uint32_t comb_key_len_bits;
		/**< Combined mode key length in bits.
		 * It holds the salt length followed by the key.
		 */

	uint8_t icv_len_bits;
		/**< ICV-Integrity Checksum Value size in bits */
};

/*!
 * IPSec SA inbound/outbound information
 */
struct nf_ipsec_sa{
	uint32_t spi;
		/**< Security Parameter Index of the SA */
	uint8_t protocol;
		/**< Security Protocol ESP/AH */
	enum nf_ipsec_sa_flags cmn_flags;
			/**< Flags indicate SA related information */
	union {
		struct {
			enum nf_ipsec_outb_sa_flags flags;
			/**< Flags indicate SA related information, specific to outbound */

			uint8_t dscp;
			/**< DSCP value, valid when DSCP handle is SET */
			uint32_t mtu;
			/**< Maximum transmission unit.  */
			uint16_t dscp_start;
			/**< DSCP start value.  Valid for only when
			 * SA per DSCP option is enabled in the SPD Policy
			 */
			uint16_t dscp_end;
			/**< DSCP end value.  Valid for only when
			 * SA per DSCP option is enabled in the SPD Policy
			 */

			enum nf_ipsec_df_bit_handle df_bit_handle;
				/**< DF bit options */
			enum nf_ipsec_dscp_handle dscp_handle;
				/**< DSCP options */
			uint8_t *iv;
				/**< Initialization Vector */
			uint8_t iv_len_bits;
				/**< IV	length in bits */
		}outb;
		struct {
			enum nf_ipsec_inb_sa_flags flags;
			/**< Flags indicate SA related information, specific to inbound */
			uint8_t anti_replay_window_size;
			/**< Anti-Replay window size in bytes */
			uint32_t outb_spi;
			/**< Outbound SA SPI value. */
		}inb;
	};
	struct nf_ipsec_sa_crypto_params crypto_params;
		/**< SA crypto suite information. */
	struct nf_ipsec_ipcomp_info *ipcomp_info;
		/**< IP compression protocol information.
		* This information is filled when IP Compression is required for SA processing.
		*/
	uint16_t periodic_time_interval;
		/**< Periodic update interval value in seconds. */
	uint32_t soft_kilobytes_limit;
		/**< Soft Kilobytes expire. */
	uint32_t hard_kilobytes_limit;
		/**< Hard Kilobytes expire. */
	uint64_t soft_pkt_limit;
		/**< Soft Packet count expire. */
	uint64_t hard_pkt_limit;
		/**< Hard Packet count expire. */
	uint32_t soft_seconds_limit;
		/**< Soft Seconds expire. */
	uint32_t hard_seconds_limit;
		/**< Hard Second expire. */
	uint32_t n_selectors;
		/**< Number of selectors. */
	struct nf_ipsec_sa_selector *selectors;
		/**< Array of selectors. */
	struct nf_ipsec_nat_info nat_info;
		/**< NAT port information. */
	struct nf_ipsec_tunnel_end_addr te_addr;
		/**< Tunnel end points address. */
};


/*!
 * Input parameters for SA addition
 */
struct nf_ipsec_sa_add_inargs{
	enum nf_ipsec_direction dir;	/**< Direction: Inbound or Outbound */
	uint32_t tunnel_id; /**< Tunnel ID */
	uint8_t n_sas;
	     /**< Number of SAs in SA bundle.  This value will be 2 for ESP+AH combinations */
	struct nf_ipsec_sa  *sa_params;
                                /**< SA bundle, array of SA Parameters. */
};

/*!
 * Output parameters for SA addition
 */

struct nf_ipsec_sa_add_outargs{
	int32_t result;
		/**< 0:Success; Non Zero value: Error code indicating failure */
};

/*!
 * @brief This API is used to add Inbound/Outbound SA to SA
 * database.  This database is maintained per Name Space instance.
 * This function first validates the incoming parameters
 * and if all validations succeed, new SA is added to the database.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] in  Pointer to input param structure
 * which contains  SA information.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @param[out] out  Pointer to output param structure
 * that will be filled with output values of this API.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD)
 * @endinternal
 *
 * @ingroup 	IPSEC
 */
int32_t nf_ipsec_sa_add(
	nf_ns_id nsid,
	const struct nf_ipsec_sa_add_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_sa_add_outargs *out,
	struct nf_api_resp_args *resp);

/*!
 * Parameters to identify SA uniquely.
 */

struct nf_ipsec_sa_identifier {
	 uint32_t spi;   /**< SPI Value */
	 struct nf_ip_addr dest_ip; /**< Destination Gateway Address */
	 uint8_t protocol;  /**< Security Protocol (ESP/AH) */
};

/*!
 * Input parameters for SA deletion
 */
 struct nf_ipsec_sa_del_inargs {
	enum nf_ipsec_direction dir;  /**< Direction: Inbound or Outbound */
	struct nf_ipsec_sa_identifier	 sa_id;
		/**< SA identifier information */
};

/*!
 * Output parameters for SA deletion
 */
struct nf_ipsec_sa_del_outargs{
	int32_t result;
		/**< 0:Success; Non Zero value: Error code indicating failure */
};

/*!
 * @brief This API is used to delete Inbound/Outbound SA from SA
 * database.  This database is maintained per Name Space.
 * This function first validates the incoming parameters
 * and if all validations succeed, finds the entry in the database
 * with given information and deletes it.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] in  Pointer to input param structure
 * which contains  SA information.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @param[out] out  Pointer to output param structure
 * that will be filled with output values of this API.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD)
 * @endinternal
 *
 * @ingroup 	IPSEC
 */
int32_t nf_ipsec_sa_del(
	nf_ns_id nsid,
	const struct nf_ipsec_sa_del_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_sa_del_outargs *out,
	struct nf_api_resp_args *resp);

/*!
 * IPSec SA modify flags information
 */
enum nf_ipsec_sa_modify_flags {
	NF_IPSEC_SA_MODIFY_LOCAL_GW_INFO = 1,
	/**< By setting this flag, local gateway information will
	 * be modified in the given SA.
	 */
	NF_IPSEC_SA_MODIFY_PEER_GW_INFO,
	/**< By setting this flag, Peer gateway information will
	 * be modified in the given SA.
	 */
	NF_IPSEC_SA_MODIFY_MTU ,
	/**< By setting this flag, MTU will be modified in the given SA.
	 * Valid for Outbound direction SA.
	 */
	NF_IPSEC_SA_ADD_SEL,
	/**< By setting this flag, Selector will be added
	 * to the given SA.
	 */
	NF_IPSEC_SA_DEL_SEL,
	/**< By setting this flag, Selector will be deleted
	 * from the given SA.
	 */
	NF_IPSEC_SA_MODIFY_REPLAY_INFO
	/**< By setting this flag, SA will be updated with Sequence number
	 * window bit map, etc */
};

/*!
 * IPSec SA anti-replay modify flags information
 */
enum nf_ipsec_sa_modify_replay_info_flags {
	NF_SA_MODIFY_SEQ_NUM = BIT (1),
		/**< By setting this flag, SA will be updated with given Sequence number */
	NF_SA_MODIFY_ANTI_REPLAY_WINDOW = BIT (2)
		/**< By setting this flag, SA will be updated with given window bit map array */
};
/*!
 * Input parameters for SA modification
 */
struct nf_ipsec_sa_mod_inargs{
	enum nf_ipsec_direction dir;	/**< Direction: Inbound or Outbound */
	uint32_t tunnel_id; /**< Tunnel ID */
	struct nf_ipsec_sa_identifier	 sa_id;
		/**< SA identifier information */
	enum nf_ipsec_sa_modify_flags flags;
		/**< flags indicating modify type */
	union {
		struct {
			uint16_t port;
				/**< New port */
			struct nf_ip_addr addr;
				/**< New IP Address */
		}addr_info;
			 /**< Valid if SA modify type is
			  * NF_IPSEC_SA_MODIFY_LOCAL_GW_INFO or
 			  * NF_IPSEC_SA_MODIFY_PEER_GW_INFO.
       			  */
		uint32_t mtu;
			/**< New MTU value.
			 * Valid if SA modify type is NF_IPSEC_SA_MODIFY_MTU.
         			 */
		struct nf_ipsec_sa_selector selector;
			/**< SA selector Information.
			 * Valid if SA modify type is NF_IPSEC_SA_ADD_SEL or
			 * NF_IPSEC_SA_DEL_SEL.
         			 */
		struct {
			enum nf_ipsec_sa_modify_replay_info_flags flags;
				/**< flags indicating modify type */
			uint8_t anti_replay_window_size;
				/**< Anti-Replay window size in bytes. */
			uint32_t *anti_replay_window_bit_map;
				/**< Anti-Replay window bit map array */
			uint32_t seq_num;
				/**< Sequence number */
			uint32_t hi_seq_num;
				/**< Higher order Sequence number */
		}replay_info;
			 /**< Valid if SA modify type is
 			  * NF_IPSEC_SA_MODIFY_REPLAY_INFO.
 			  */
	};
};

/*!
 * Output parameters for SA modification
 */

struct nf_ipsec_sa_mod_outargs{
	int32_t result;
		/**< 0:Success; Non Zero value: Error code indicating failure */
};

/*!
 * @brief This API is used to modify Inbound/Outbound SA.
 * SA database is maintained per Name Space instance.
 * This function first validates the incoming parameters
 * and if all validations succeed,finds the entry in the database
 * with given information and modifies it.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] in  Pointer to input param structure
 * which contains  SA information.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @param[out] out  Pointer to output param structure
 * that will be filled with output values of this API.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD)
 * @endinternal
 *
 * @ingroup 	IPSEC
 */
int32_t nf_ipsec_sa_mod(
	nf_ns_id nsid,
	const struct nf_ipsec_sa_mod_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_sa_mod_outargs *out,
	struct nf_api_resp_args *resp);

/*!
 * Use for nf_ipsec_sa_get_inargs.flags
 */

#define NF_IPSEC_SA_GET_STATS    0x1 /**<  Fetch SA statistics */
#define NF_IPSEC_SA_GET_PARAMS 0x2 /**< Fetch SA parameters */

/*!
 * SA fetch operations
 */
enum nf_ipsec_sa_get_op {
	NF_IPSEC_SA_GET_FIRST = 0,	/**< Fetch first entry in the database */
	NF_IPSEC_SA_GET_NEXT, 	/**< Fetch next entry for given SA */
	NF_IPSEC_SA_GET_EXACT 	/**< Fetch entry for given SA */
};

/*!
 * SA Statistics information structure
 */
struct nf_ipsec_sa_stats {
	uint64_t received_pkts;
		/**< Number of packets went inside for SA processing */
	uint64_t processed_pkts;
		/**< Number of packets processed by SA */
	uint64_t processed_bytes;
		/**< Number of bytes processed by SA */
	struct {
		uint32_t invalid_ipsec_pkt;
			/**< Invalid IPSec (ESP/AH) packet */
		uint32_t inner_no_ipv4_ipv6_pkt;
			/**< Decrypted packet is not IPv4 or IPv6 packet */
		uint32_t invalid_pad_length;
			/**< Invalid pad length */
		uint32_t invalid_seq_number;
			/**< Invalid Sequence number received */
		uint32_t anti_replay_late_pkt;
			/**< Anti Replay Check: Late packet */
		uint32_t anti_replay_replay_pkt;
			/**< Anti Replay Check: Replay packet */
		uint32_t invalid_icv;
			/**< ICV comparison failed */
		uint32_t seq_num_over_flow;
			/**< Sequence number over flow */
		uint32_t sa_sel_verify_failed;
			/**< SA selector verification failed */
		uint32_t crypto_op_failed;
			/**< Crypto operations failed */
		uint32_t icmp_sent_for_pmtu;
			/**< ICMP error message sent for PMTU */

	}protocol_violation_errors;
	struct {
		uint32_t no_tail_room;
			/**< Buffer has no tail room */
		uint32_t submit_to_sec_failed;
			/**< Submission to SEC failed for crypto operations */
	}local_errors;
	/*!
	 * @internal
	 * @todo TBD
	 * @endinternal
	 */

};

/*!
 * Input parameters to fetch SA  information
 */
struct nf_ipsec_sa_get_inargs{
	enum nf_ipsec_direction dir; 	/**< Direction: Inbound or Outbound */
	/*!
	 * @internal
	 *  Following  field is not valid/filled for get_first
	 * @endinternal
	 */

	struct nf_ipsec_sa_identifier	 sa_id;
		/**< SA identifier information */
	enum nf_ipsec_sa_get_op operation; /**< Operation mentions
					 * get_first/get_next/get_exact
					 */
 	uint32_t flags;
		/**< Flags indicate to get complete SA information
	 	 * or only statistics or only SA details
	 	 */

	uint32_t max_n_selectors;
		/**< Memory available to hold this number of
		 * selectors for in the outargs(sa_params.selectors)
		 */

};

/*!
 * Output parameters to fetch SA information
 */
struct nf_ipsec_sa_get_outargs{
	int32_t result;
		/**< 0:Success; Non Zero value: Error code indicating failure */
	struct nf_ipsec_sa sa_params;
		/**< SA details */
	struct nf_ipsec_sa_stats stats; 	/**< SA related stats */
};

/*!
 * @brief This API is used to fetch Inbound/Outbound SA information.
 * This database is maintained per Name Space.
 * This function first validates the incoming parameters
 * and if all validations succeed, the following is performed
 * depending on the type of operation: if operation is get_first,
 *  fetches first entry information from SA database.
 * if operation is get_next, finds the entry in the SA database
 * with given information and returns the next entry.
 * if operation is get_exact, finds the entry and returns it.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] in  Pointer to input param structure
 * which contains  SA information.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @param[out] out  Pointer to output param structure
 * that will be filled with output values of this API.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD)
 * @endinternal
 *
 * @ingroup 	IPSEC
 */
int32_t nf_ipsec_sa_get(
	nf_ns_id nsid,
	const struct nf_ipsec_sa_get_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_sa_get_outargs *out,
	struct nf_api_resp_args *resp);

/*!
 * @brief This API is used to flush/delete all Inbound and Outbound SAs
 * in a given name space.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD)
 * @endinternal
 *
 * @ingroup IPSEC
 */
int32_t nf_ipsec_sa_flush(
	nf_ns_id nsid,
	nf_api_control_flags flags,
	struct nf_api_resp_args *resp);

/*!
 * IPSec Global statistics information structure
 */
struct nf_ipsec_global_stats {
	uint64_t outb_received_pkts;
		/**< Received Outbound packets */
	uint64_t outb_processed_pkts;
		/**< Processed Outbound packets */
	uint64_t outb_pkts_to_apply_sec;
		/**< Received Outbound packets to apply security */
	uint64_t outb_sec_applied_pkts;
		/**< Outbound packets applied security */
	uint64_t outb_processed_bytes;
		/**< Number of bytes processed in the outbound processing */
	uint64_t outb_sec_applied_bytes;
		/**< Number of bytes applies security in the outbound processing */
	uint64_t inb_received_pkts;
		/**< Received Inbound packets */
	uint64_t inb_processed_pkts;
		/**< Processed Inbound packets */
	uint64_t inb_pkts_to_apply_sec;
		/**< Received Inbound packets to apply security */
	uint64_t inb_sec_applied_pkts;
		/**< Inbound packets applied security */
	uint64_t inb_processed_bytes;
		/**< Number of bytes processed in the inbound processing */
	uint64_t inb_sec_applied_bytes;
		/**< Number of bytes applies security in the inbound processing */
	struct {
		uint32_t invalid_ipsec_pkt;
			/**< Invalid IPSec (ESP/AH) packet */
		uint32_t inner_no_ipv4_ipv6_pkt;
			/**< Decrypted packet is not IPv4 or IPv6 packet */
		uint32_t invalid_pad_length;
			/**< Invalid pad length */
		uint32_t invalid_seq_number;
			/**< Invalid Sequence number received */
		uint32_t anti_replay_late_pkt;
			/**< Anti Replay Check: Late packet */
		uint32_t anti_replay_replay_pkt;
			/**< Anti Replay Check: Replay packet */
		uint32_t invalid_icv;
			/**< ICV comparison failed */
		uint32_t crypto_op_failed;
			/**< Crypto operations failed */
		uint32_t seq_num_over_flow;
			/**< Sequence number over flow */
		uint32_t sa_sel_verify_failed;
			/**< SA selector verification failed */
		uint32_t icmp_sent_for_pmtu;
			/**< ICMP error message sent for PMTU */
		uint32_t sa_hard_life_time_expired;
			/**< SA hard life time expired */
	}protocol_violation_errors;
	struct {
		uint32_t no_tail_room;
			/**< Buffer has no tail room */
		uint32_t submit_to_sec_failed;
			/**< Submission to SEC failed for crypto operations */
		uint32_t no_outb_sa;
			/**< Outbound SA not found */
		uint32_t no_inb_sa;
			/**< Inbound bound SA not found */
		uint32_t frag_failed;
			/**< Fragmentation failed */
		uint32_t mem_alloc_failed;
			/**< Memory allocation failed for SA/SPD/Shared descriptor etc.*/
	}local_errors;
/*!
 * @internal
 * @todo TBD
 * @endinternal
 */
};


/*!
 * Input parameters to fetch Global Statistics
 */
struct nf_ipsec_global_stats_get_inargs {
	/*!
	 * @internal
	 * At present this structure is not containing any fields
	 * @endinternal
	 */
};


/*!
 * Output parameters to fetch Global Statistics
 */
struct nf_ipsec_global_stats_get_outargs {
	int32_t result;
		/**< 0:Success; Non Zero value: Error code indicating failure */
	struct nf_ipsec_global_stats stats;

/*!
 * @internal
 * @todo TBD
 * @endinternal
 */
};

/*!
 * @brief This API fetches global statistics for given Name Space.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] in  Pointer to input param structure.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @param[out] out  Pointer to output param structure that will be filled
 * with output values of this API.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD).
 * @endinternal
 *
 * @ingroup	IPSEC
 */
int32_t nf_ipsec_global_stats_get(
	nf_ns_id nsid,
	const struct nf_ipsec_global_stats_get_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_global_stats_get_outargs *out,
	struct nf_api_resp_args *resp);
/*!
 * Encryption inject flags information
 */
enum nf_ipsec_encrypt_inject_flags {
        NF_IPSEC_INJECT_POLICY_INFO = BIT (1),
		/**< This indicates Policy ID information is supplied */
        NF_IPSEC_INJECT_SA_IDENTIFIER_INFO = BIT (2),
		/**< This indicates SA identifier information is supplied */
};
/*!
 * Input parameters to inject packet for IPSec encryption
 */
struct nf_ipsec_encrypt_inject {
	enum nf_ipsec_encrypt_inject_flags flags;
		/**< Based on the flags set,
 		 * appropriate fields in the structure will be used.
 		 */
	uint32_t tunnel_id;	/**< Tunnel ID */
	uint32_t policy_id; 	/**< SPD Policy ID */
	struct nf_ipsec_sa_identifier	 sa_id;
		/**< SA identifier information */
	void    *pkt; /**< Packet */
	struct nfinfra_pkt_meta *meta;
		/**< Packet meta information*/
	/*!
	 * @internal
	 * @todo TODO : Packet details
	 * @endinternal
	 */
};

/*!
 * @brief Control plane application uses this function to request
 * IPSec-DP to encrypt and send the packet out.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] in  Pointer to input param structure which contains packet
 * details and matching SPD and SA details
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD).
 * @endinternal
 *
 * @ingroup	IPSEC
 */
int32_t nf_ipsec_encrypt_and_send(nf_ns_id nsid,
				const struct nf_ipsec_encrypt_inject *in);

/*!
 * Input parameters to inject packet for IPSec decryption
 */
struct nf_ipsec_decrypt_inject {
	void    *pkt; /**< Packet */
	struct nfinfra_pkt_meta *meta;
		/**< Packet meta information*/
	/*!
	 * @internal
	 * @todo TODO : Packet details
	 * @endinternal
	 */

};

/*!
 * @brief Control plane application uses this function to request
 * IPSec-DP to decrypt and send the packet out.
 * @internal
 * @todo details TBD
 * @endinternal
 *
 * @param[in] in  Pointer to input param structure which contains
 * packet details.
 *
 * @returns 0 on Success or negative value on failure.
 *
 * @internal
 * @todo (more errors TBD).
 * @endinternal
 *
 * @ingroup	IPSEC
 */
int32_t nf_ipsec_decrypt_and_send(const struct nf_ipsec_decrypt_inject *in);

/*!
 * IPSec Module Authentication Algorithm Capabilities
 */
struct nf_ipsec_auth_algo_cap {
	uint32_t  md5:1, /**< HMAC-MD5 */
	sha1:1,  /**< HMAC-SHA1 */
	sha2:1,  /**< HMAC-SHA2 */
	aes_xcbc:1,  /**< AES-XCBC */
	none:1; /**< No Authentication */

};

/*!
 * IPSec Module Encryption Algorithm Capabilities
 */
struct nf_ipsec_cipher_algo_cap {
	uint32_t des:1, /**< DES-CBC */
	des_3:1, /**< 3DES-CBC */
	aes:1, /**< AES-CBC */
	aes_ctr:1, /**< AES-CTR */
	null:1; /**< NULL Encryption */
};

/*!
 * IPSec Module Combined mode Algorithm Capabilities
 */
struct nf_ipsec_comb_algo_cap {
	uint32_t aes_ccm:1,  /**< AES-CCM */
	aes_gcm:1, /**< AES-GCM */
	aes_gmac:1; /**< AES-GMAC */
};


/*!
 * IPSec Module Capabilities
 */
struct nf_ipsec_capabilities {
	/*! This parameter indicates if IPSec-DP is capable of doing SPD
	 * rule search for incoming or outgoing datagrams
	 */

	uint32_t
	sel_store_in_spd : 1,

	/*! Authentication Header processing */
	ah_protocol:1,

	/*! ESP Header processing */
	esp_protocol:1,

	/*! IPComp related processing */
	ipcomp_protocol:1,

	/*! IPSec Tunnel Mode processing */
	tunnel_mode:1,

	/*! IPSec Tunnel Mode processing */
	transport_mode:1,

	/*! This indicates if IPSec-DP has capability to generate
	 * (for Outbound) and verify (for Inbound) extended sequence numbers.
	 */
	esn:1,

	/*! This option indicates if IPSec-DP has capability to do ESP
	 * and AH processing together on a same packet for a given SA.
	 */
	multi_sec_protocol:1,

	/*! This option indicates if IPSec-DP can handle
	 * packets that need to be processed on SAs for which life
	 * time in seconds option has been selected.
	 */
	lifetime_in_sec:1,

	/*! This option indicates if IPSec-DP can handle
	 * packets that need to be processed on SAs for which
	 * life time in KB option has been selected.
	 */
	lifetime_in_kbytes:1,

	/*! This option indicates if IPSec-DP can handle
	 * packets that need to be processed on SAs for which
	 * life time in number of packets option has been selected.
	 */
	lifetime_in_packet_cnt:1,

	/*! This option indicates whether IPSec-DP can
 	 * handle the necessary UDP Encapsulation required at
	 * IPSec level for traversing NAT boxes.
	 */
	udp_encap:1,

	/*! This option indicates whether IPSec-DP can fragment packets
	 * before IPSec encryption, so that the resulting IPSec encrypted
	 * fragments do not exceed MTU
	 */
	redside_frag:1,

	/*! Due to intermediate NAT boxes,
	 * destination gateway tunnel endpoint address may change.
	 * Based on SPI value, an IPSec implementation	can typically
	 * find out if there has been a change in the destination
	 * tunnel endpoint address. Once a change is detected, the IPSec
	 * implementation has to update the destination gateway address
	 * for the Outbound SA of the tunnel so that outbound traffic
	 * will continue. This option indicates if IPSec_DP is capable of
	 * detecting changes in destination gateway address and adapting
	 * to the same.
	 */
	peer_gw_adaptation:1,

	/*! This option indicates if IPSec-DP is capable of
	 * detecting changes to the local gateway endpoint address
	 * and updates its tunnel data	structures.
	 */
	local_gw_adaptation:1,

	/*! This option indicates whether IPSec-DP is capable of providing
	 * limited Traffic Flow confidentiality
	 */
	tfc:1,

	/*! This option indicates whether IPSec_DP is capable of handling
	 * fragments (Separate SA for non initial, Stateful fragmentation)
	 */
	/*!
	 * @internal
	 * No comments added here
	 * @endinternal
	 */
	frag_options:1,

	/*! This option indicates whether IPSec-DP is capable of
	 * accepting or rejecting the ICMP error messages, by searching the
	 * ICMP record using type and code
	 */
	icmp_error_msg_process:1,

	/*! This option indicates whether IPSec-DP is capable of
	 * supporting network objects in the selectors configuration
	 */
	network_objects:1;

	/*! Authentication Algorithms such as MD5,
	 * SHA1, AES-XCBC, etc are supported
	 */
	struct nf_ipsec_auth_algo_cap    auth_algo_cap;

	/*! Encryption Algorithms such as DES,
	 * 3DES, AES-CBC,AES-CTR, etc are supported \n
	 * These algorithms have to be considered with capabilities
	 * such as esp_protocol and ah_protocol to understand
	 * the SA based functionality supported by IPSec-DP
	 */
	struct nf_ipsec_cipher_algo_cap    cipher_algo_cap;

	/*! Combined mode Algorithms supported such as aes-ccm,
	 * aes-gcm, etc
	 */
	struct nf_ipsec_comb_algo_cap    comb_algo_cap;

	/*! Maximum number of Name Spaces supported by IPSec-DP.*/
	uint32_t	     max_name_spaces;

	/*! Maximum number of Tunnel interfaces supported
	 * in each name space.
	 */
	uint32_t	     max_tunnels;

	/*! Indicates the maximum number of IN and OUT
	 * SPD Containers for each name space. For example if the supplied
	 * value is 64, it indicates IPSec-DP supports 64 IN SPD policies
	 * and 64 OUT SPD policies.
	 */
	uint32_t	     max_spd_policies;

	/*! Indicates the maximum number of IN and OUT
	 * IPSec SAs in each name space.  For example if the supplied
	 * value is 1k, it indicates IPSec-DP supports 1k IN IPSEC SAS
	 * and 1k OUT IPSec SAs in each name space.
	 */
	uint32_t	     max_sas;

	/*! Maximum number of ICMP policies supported by IPSec-DP.*/
	uint32_t	     max_icmp_policies;

};


/*!
 * Output parameters to fetch IPSec module capabilities
 */
struct nf_ipsec_cap_get_outargs {
	struct nf_ipsec_capabilities cap; /**< Module Capabilities */
};


/*!
 * @brief This API fetches IPSec module Capabilities
 *
 * @param[in] flags - API behavioral flags.
 * @param[out] out - Pointer to output param structure.
 * Capabilities of underlying IPSec module which offers to
 * control plane application.
 * @param[in] resp - Response arguments for asynchronous call.
 *
 * @returns SUCCESS on success; FAILURE otherwise
 *
 * @internal
 * @todo (more errors TBD).
 * @endinternal
 *
 * @ingroup IPSEC
 */
int32_t nf_ipsec_capabilities_get(
	nf_api_control_flags flags,
	struct nf_ipsec_cap_get_outargs *out,
	struct nf_api_resp_args *resp);

/*!
 * @brief This API fetches IPSec module API version
 *
 * @param[in]
 *
 * @param[out] version  API Version
 *
 * @returns	0 on Success or negative value on failure
 *
 * @internal
 * @todo (more errors TBD).
 * @endinternal
 *
 * @ingroup	IPSEC
 */
int32_t nf_ipsec_api_version_get(char *version);


/*!
 * IPSec DP status flag information
 */
enum nf_ipsec_status_flag {
	NF_IPSEC_STATUS_ENABLE = 0, 	/**< Set  IPSec-DP status as enable */
	NF_IPSEC_STATUS_DISABLE		/**< Set  IPSec-DP status as disable */
};


/*!
 * @brief This API is used to set IPSec-DP
 * status as enable/disable for given name space.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] status  Status indicating enable/disable.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @returns	0 on Success or negative value on failure
 *
 * @internal
 * @todo (more errors TBD).
 * @endinternal
 *
 * @ingroup IPSEC
 */
int32_t nf_ipsec_dp_set_status(
	nf_ns_id nsid,
	enum nf_ipsec_status_flag status,
	nf_api_control_flags flags,
	struct nf_api_resp_args *resp);


/*!
 * @brief This API is used to inform IPSec-DP to revalidate its Policies
 * or SAs or any runtime information in a given name space.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @returns	0 on Success or negative value on failure
 *
 * @internal
 * @todo (more errors TBD).
 * @endinternal
 *
 * @ingroup	IPSEC
 */
int32_t nf_ipsec_dp_revalidate(
	nf_ns_id nsid,
	nf_api_control_flags flags,
	struct nf_api_resp_args *resp);

/*!
 * ICMP error message processing status flag information
 */
enum nf_ipsec_icmp_err_msg_process_status_flag {
	NF_IPSEC_ICMP_ERR_MSG_PROCESS_STATUS_ENABLE = 0,
		/**< Enable  ICMP error message processing. */
	NF_IPSEC_ICMP_ERR_MSG_PROCESS_STATUS_DISABLE = 0,
		/**< Disable  ICMP error message processing. */
};


/*!
 * @brief This API is used to enable/disable ICMP error message
 * processing for given name space.
 *
 * @param[in] nsid  NamesSpace ID.
 * @param[in] status  Status indicating enable/disable.
 * @param[in] flags  API behavioral flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @returns	0 on Success or negative value on failure
 *
 * @internal
 * @todo (more errors TBD).
 * @endinternal
 *
 * @ingroup IPSEC
 */
int32_t nf_ipsec_set_icmp_err_msg_process_status(
	nf_ns_id nsid,
	enum nf_ipsec_icmp_err_msg_process_status_flag status,
	nf_api_control_flags flags,
	struct nf_api_resp_args *resp);


/*!
 * No Outbound SA notification information structure.
 */
struct nf_no_outb_sa_notification {
	uint32_t tunnel_id;  	/**< Tunnel ID */
	uint32_t policy_id;   	/**< Outbound SPD Policy ID */
	void      *pkt;	/**< Packet */
	struct nfinfra_pkt_meta *meta;
		/**< Packet meta information*/
	/*!
	 * @internal
	 * @todo  TODO packet details
	 * @endinternal
	 */
};

/*!
 * No Inbound SA notification information structure.
 */
struct nf_no_inb_sa_notification {
	void      *pkt; /**< Packet */
	struct nfinfra_pkt_meta *meta;
		/**< Packet meta information*/
	/*!
	 * @internal
	 * @todo  TODO packet details
	 * @endinternal
	 */

};

/*!
 * SA expire notification types
 */
enum nf_ipsec_sa_expire_notification_type{
	NF_IPSEC_SA_SOFT_LIFETIME_OUT_BY_SEC = 1,
		/**< Indication for Soft Life time out in Seconds */
	NF_IPSEC_SA_HARD_LIFETIME_OUT_BY_SEC,
		/**< Indication for Hard Life time out in Seconds */
	NF_IPSEC_SA_SOFT_LIFETIME_OUT_BY_BYTES,
		/**< Indication for Soft Life time out in Bytes */
	NF_IPSEC_SA_HARD_LIFETIME_OUT_BY_BYTES,
		/**< Indication for Hard Life time out in Bytes */
	NF_IPSEC_SA_SOFT_LIFETIME_OUT_BY_PKTS,
		/**< Indication for Soft Life time out in packets */
	NF_IPSEC_SA_HARD_LIFETIME_OUT_BY_PKTS
		/**< Indication for Hard Life time out in packets */
};

/*!
 * SA expire notification information structure.
 */
struct nf_sa_expire_notification {
	enum nf_ipsec_direction dir;
		/**< Direction: Inbound or Outbound */
	enum nf_ipsec_sa_expire_notification_type expire_type;
		/**< SA Expirty notification type */
	struct nf_ipsec_sa_identifier	 sa_id;
		/**< SA identifier information */
};

/*!
 * Peer Gateway change adapt notification information structure.
 */
struct nf_peer_gw_change_adapt_notification {
	uint32_t spi; 			/**< SPI Value */
	uint8_t protocol; 		/**< Security Protocol (ESP/AH) */
	struct nf_ip_addr new_dst_adr; 	/**< New Destination Gateway Address */
	struct nf_ip_addr old_dst_adr; 	/**< Old Destination Gateway Address */
	uint16_t new_port; 		/**< New Port */
	uint16_t old_port; 		/**< old Port */
};

/*!
 * Sequence Number Overflow notification information structure.
 */
struct nf_seq_num_overflow_notification {
	struct nf_ipsec_sa_identifier	 sa_id;
		/**< SA identifier information */
};

/*!
 * SA Periodic update notification information structure.
 */
struct nf_sa_periodic_update_notification {
	enum nf_ipsec_direction dir;	/**< Direction: Inbound or Outbound */
	struct nf_ipsec_sa_identifier	 sa_id;
		/**< SA identifier information */

	uint32_t seq_num; 		/**< SA sequence number */
	uint32_t hi_seq_num; 		/**< SA Higher order sequence number.
	 				 * Valid when ESN is enabled on SA
					 */
	uint32_t elapsed_time_sec;	/**< Elapsed Seconds of SA life time */
	uint64_t processed_pkts;      /**< Number of Packets processed by SA */
	uint64_t processed_bytes; 	/**< Number of bytes processed by SA */

	/*!
	 * @internal
	 * @todo TBD
	 * @endinternal
	 */
};

/*!
 * Self decrypted packet notification information structure.
 */
struct nf_ipsec_self_decrypted_pkt_notification {
	void      *pkt;
	struct nfinfra_pkt_meta *meta;
		/**< Packet meta information*/
	struct nf_ipsec_sa_identifier	 sa_id;
		/**< SA identifier information */
};

/*!
 * IPSec Log message IDs
 */
enum nf_ipsec_log_msg_id {
	NF_IPSEC_LOG_MSG_ID1 = 1
	/**< IPSec-DP uses this ID when it receives invalid length
	 * ESP packet
	 */

	/*!
	 * @internal
	 * @todo TBD
	 * @endinternal
	 */


};

#define NF_IPSEC_LOG_MSG_LEN	200 /**< Log message length */
/*!
 * IPSec log notification information structure.
 */
struct nf_ipsec_log_notification {
	enum nf_ipsec_direction dir;	/**< Direction: Inbound or Outbound */
	enum nf_ipsec_log_msg_id msg_id; 	/**< Log message ID */
	uint8_t msg[NF_IPSEC_LOG_MSG_LEN]; 		/**< Message to be logged */

	uint32_t tunnel_id;  		/**< Tunnel ID */
	uint32_t policy_id;   		/**< Outbound SPD Policy ID */

	struct nf_ipsec_sa_identifier	 sa_id;
		/**< SA identifier information */

	/*!
	 * @internal
	 * @todo TBD
	 * @endinternal
	 */


};


/*! This callback function is invoked when outbound SA is
 *  not found in IPSec-DP
 */
typedef void (*nf_ipsec_cbk_no_outb_sa_fn)(
	nf_ns_id nsid,
	struct nf_no_outb_sa_notification *in);
/*! This callback function is invoked when
 * inbound SA is not found in IPSec-DP
 */
typedef void (*nf_ipsec_cbk_no_inb_sa_fn)(
	nf_ns_id nsid,
	struct nf_no_inb_sa_notification *in);
/*! This callback function is invoked when the
 * IPSec-DP detects  SA expire.
 */
typedef void (*nf_ipsec_cbk_sa_expire_fn)(
	nf_ns_id nsid,
	struct nf_sa_expire_notification *in);
/*! This callback function is invoked when the IPSec-DP
 * identifies Peer gateway change
 */
typedef void (*nf_ipsec_cbk_peer_gw_change_adapt_fn)(
	nf_ns_id nsid,
	struct nf_peer_gw_change_adapt_notification *in);
/*! This callback function is invoked when the IPSec-DP
 * encounters sequence number overflow
 */
typedef void (*nf_ipsec_cbk_seq_num_overflow_fn)(
	nf_ns_id nsid,
	struct nf_seq_num_overflow_notification *in);

/*! This callback function is invoked for periodic
 * updates for SA
 */
typedef void (*nf_ipsec_cbk_sa_periodic_update_fn)(
	nf_ns_id nsid,
	struct nf_sa_periodic_update_notification *in);

/*! This callback function is invoked when IPSec-DP
 * sends a log message
 */
typedef void (*nf_ipsec_cbk_log_notification_fn)(
	nf_ns_id nsid,
	struct nf_ipsec_log_notification *in);

/*! This callback function is invoked if decrypted packet is self packet */
typedef void (*nf_ipsec_cbk_self_decrypted_pkt_notification_f)(
	nf_ns_id nsid,
	struct nf_ipsec_self_decrypted_pkt_notification *in);

/*!
 * IPSec notification hooks structure.
 * This structure contains hooks for receiving
 * unsolicited notifications.
 */
struct nf_ipsec_notification_hooks {
	nf_ipsec_cbk_no_outb_sa_fn no_outb_sa_fn;
		/**< This callback function is invoked when outbound SA is
		 *  not found in IPSec-DP
		 */

	nf_ipsec_cbk_no_inb_sa_fn no_inb_sa_fn;
		/**< This callback function is invoked when
		 * inbound SA is not found in IPSec-DP
		 */

	nf_ipsec_cbk_sa_expire_fn sa_expire_fn;
		/**< This callback function is invoked when the
		 * IPSec-DP detects  SA expire.
		 */

	nf_ipsec_cbk_peer_gw_change_adapt_fn peer_gw_change_adapt_fn;
		/**< This callback function is invoked when the IPSec-DP
		 * identifies Peer gateway change
		 */

	nf_ipsec_cbk_seq_num_overflow_fn seq_num_overflow_fn;
		/**< This callback function is invoked when the IPSec-DP
		 * encounters sequence number overflow
		 */

	nf_ipsec_cbk_sa_periodic_update_fn sa_periodic_update_fn;
		/**< This callback function is invoked for periodic
		 * updates for SA
		 */

	nf_ipsec_cbk_log_notification_fn log_notification_fn;
		/**< This callback function is invoked when IPSec-DP
		 * sends a log message
		 */
	nf_ipsec_cbk_self_decrypted_pkt_notification_f
		self_decrypted_notification_fn;
		/**< This callback function is invoked
		 * if decrypted packet is self packet
		 */
};

/*!
 * @brief This API registers callback hooks for receiving notifications
 * sent by IPSec NF-DP
 *
 * @param[in] hooks - Pointer to ipsec_notification_hooks structure
 * containing callback function pointers.
 *
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPSEC
 */
int32_t nf_ipsec_notification_hooks_register(
		const struct nf_ipsec_notification_hooks *hooks);

/*!
 * @brief This API deregisters IPSec NF-DP notification callback hooks.
 *
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPSEC
 */
int32_t nf_ipsec_notification_hooks_deregister(void);


#endif /* __IPSEC_API_H */
/*! @} */
