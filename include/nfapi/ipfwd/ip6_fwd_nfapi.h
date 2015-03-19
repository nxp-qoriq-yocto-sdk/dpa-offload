/*!
 * @file ip6_fwd_nfapi.h
 * @brief This file contains the IPv6 unicast forward NF API, related
 * 	  macros and data structures
 *
 * @internal
 * NOTE: For LS AIOP only hash based algorithm is valid
 * @endinternal
 *
 * @addtogroup IPv6_Unicast
 * @{
 */

#ifndef __IP6FWD_NFAPI_H
#define __IP6FWD_NFAPI_H
#include "common_nfapi.h"



/*!
 * Flags for PBR rule
 */

enum nf_ip6_fwd_pbr_rule_flags {
	NF_IP6_PBR_IN_IFACE_VALID = BIT(0), /*!  In iface is valid. */
	NF_IP6_PBR_OUT_IFACE_VALID = BIT(1), /*! Out iface is valid. */
	NF_IP6_PBR_PERMANENT_RULE = BIT(2) /*!  Permanent rule.  */
};


/*!
 * Actions for a PBR rule
 */
enum nf_ip6_fwd_pbr_rule_action {
	NF_IP6_PBR_ACT_GOTO_TABLE, /**< Go to a table */
	NF_IP6_PBR_ACT_GOTO_RULE, /**< Go to another rule */
	NF_IP6_PBR_ACT_NO_OPERATION, /**< Skip the rule */
	NF_IP6_PBR_ACT_BLACKHOLE, /**< Black hole, silent drop */
	NF_IP6_PBR_ACT_UNREACHABLE, /**<Drop,send ICMP net unreachable err msg*/
	NF_IP6_PBR_ACT_PROHIBIT /**< Drop, send ICMP Pkt filtered err msg */
};

/*!
 * Structue for configuring PBR Rule
 */
struct nf_ip6_fwd_pbr_rule {
	uint16_t priority; /**< Priority of the rule */
	struct nf_ipv6_addr src_addr; /**< Source IP */
	uint8_t srcip_prefix; /**< Source IP mask value */
	struct nf_ipv6_addr dst_addr; /**< Destination IP */
	uint8_t dstip_prefix; /**< Destination IP prefix len */
	nf_if_id  in_ifid; /**< Source interface id */
	nf_if_id  out_ifid; /**< Destination interface id */
	uint16_t flags; /**<PBR rule flags. Refer #nf_ip6_fwd_pbr_rule_flags */
	uint8_t tc; /**< Traffic class (tos) */
	uint8_t action;
	/**< PBR rule actions actions. Refer #nf_ip6_fwd_pbr_rule_action */
	uint32_t opaque; /**< Opaque value */
	uint32_t opaque_mask; /**< Opaque mask */
	uint32_t target_policy_id; /**< Target policy ID, if action is goto rule*/
	uint16_t rt_table_no; /**< Route table number, if action is goto table */
};

/*!
 * Structue for deleting PBR Rule
 */
struct nf_ip6_fwd_pbr_rule_del {
	uint16_t priority; /**< Priority of the rule */
	struct nf_ipv6_addr src_addr; /**< Source IP */
	uint8_t srcip_prefix; /**< Source IP mask value */
	struct nf_ipv6_addr dst_addr; /**< Destination IP */
	uint8_t dstip_prefix; /**< Destination IP prefix len */
	nf_if_id  in_ifid; /**< Source interface id */
	nf_if_id  out_ifid; /**< Destination interface id */
	uint16_t flags; /**< PBR rule flags. Refer #nf_ip6_fwd_pbr_rule_flags */
	uint8_t tc; /**< Traffic class (tos) */
	uint8_t action;
	/**< PBR rule actions actions. Refer #nf_ip6_fwd_pbr_rule_action */
	uint32_t opaque; /**< Opaque value */
	uint32_t opaque_mask; /**< Opaque mask */
	uint32_t target_policy_id; /**< Target policy ID, if action is goto rule*/
	uint16_t rt_table_no; /**< Route table number, if action is goto table */
};

/*!
 * Scope of the route, covers from universe to site to link to host
 * and to nowhere
 */
enum nf_ip6_fwd_route_scope {
	NF_IP6_RT_SCOPE_UNIVERSE=0, /**< Global/Universal scope */
	/*!
	 * @internal
	 * User defined values go here
	 * @endinternal
	 */
	NF_IP6_RT_SCOPE_SITE=200, /**< Site scope */
	NF_IP6_RT_SCOPE_LINK=253, /**< Link level scope*/
	NF_IP6_RT_SCOPE_HOST=254, /**< Scope is host*/
	NF_IP6_RT_SCOPE_NOWHERE=255 /**< Scope no where. Drop packet*/
};

/*!
 * Different route types that can be configured for a route
 */
enum nf_ip6_fwd_route_type {
	NF_IP6_RT_TYPE_UNICAST = 1, /**<Unicast*/
	NF_IP6_RT_TYPE_LOCAL, /**< Local */
	NF_IP6_RT_TYPE_UNREACHABLE, /**< Drop, send ICMP net unreachable err msg */
	NF_IP6_RT_TYPE_BLACKHOLE, /**< Black hole, silent drop */
	NF_IP6_RT_TYPE_PROHIBIT, /**< Drop, send ICMP Pkt filtered err msg */
	NF_IP6_RT_TYPE_BROADCAST, /**< Broadcast */
	NF_IP6_RT_TYPE_THROW, /**< A special route used in conjunction with PBR.
			      *   If this route matches, lookup in this table is
			      *   terminated pretending that no route was found.
			      *   The packets are dropped and the ICMP message net
			      *   unreachable is generated.
			      *   Without PBR it is equivalent to the absence of the
			      *   route in the routing table. */
	NF_IP6_RT_TYPE_ANYCAST /**< Anycast */
};


/*!
 *IPv6 route's next hop flags
 */
enum nf_ip6_fwd_nh_flags {
	NF_IP6_RT_NH_DEAD = BIT(1)
	/**< Specifies inactive next hop.  */
};

/*!
 * Next hop structure
 */
struct nf_ip6_fwd_nh {
	uint8_t flags;  /**< Next hop flags. Refer #nf_ip6_fwd_nh_flags */
	uint8_t scope; /**< Scope of the gateway. Refer #nf_ip6_fwd_route_scope */
	nf_if_id  out_ifid; /**< Out interface Id*/
	struct nf_ipv6_addr gw_ipaddr; /**< Gateway IP address*/
	int32_t weight; /**< weight  - for ECMP */
	int32_t power;/**< Power - for ECMP */
	uint32_t traffic_classid;/**<traffic class ID- For QoS */
};

/*! Maximum multiple gateways that can be configured for a single route */
#define NF_IP6_FWD_MAX_ECMP_GWS 8

/*!
 * ip6 ECMP algorithm types
 */
enum nf_ip6_ecmp_algo {
	NF_IP6_ECMP_ALGO_HASH_BASED=1, /**< ECMP Hash based algo*/
	NF_IP6_ECMP_ALGO_ROUND_ROBIN, /**< ECMP Round Robin algo*/
	NF_IP6_ECMP_ALGO_WEIGHTED_RANDOM /**< ECMP Weighted Random algo*/
};

/*!
 * @internal
 * Metrics for a route
 * Do we need to support all? TBD
 * @endinternal
 */
enum nf_ip6_fwd_route_metrics {
	/*!
	 * @internal
	 * NF_IP6_RT_METRIC_UNSPEC=0,
	 * NF_IP6_RT_METRIC_LOCK=1,
	 * @endinternal
	 */
	NF_IP6_RT_METRIC_MTU=2, /**< Path MTU */
	NF_IP6_RT_METRIC_WINDOW, /**< Maximum advertised window */
	NF_IP6_RT_METRIC_RTT, /**< Round trip time*/
	NF_IP6_RT_METRIC_RTTVAR, /**< RTT variance */
	NF_IP6_RT_METRIC_SSTHRESH, /**< Slow start threshold */
	NF_IP6_RT_METRIC_CWND, /**< Congestion window */
	NF_IP6_RT_METRIC_ADVMSS, /**< Maximum Segment Size */
	NF_IP6_RT_METRIC_REORDERING, /**< Maximum Reordering */
	NF_IP6_RT_METRIC_HOPLIMIT, /**< Default Time To Live */
	NF_IP6_RT_METRIC_INITCWND, /**< Initial Congestion window */
	NF_IP6_RT_METRIC_FEATURES, /**< Not a metric */
	NF_IP6_RT_METRIC_RTO_MIN, /**< Min retransmission timeout val */
	NF_IP6_RT_METRIC_INITRWND, /**< Initial receive window size*/
	NF_IP6_RT_METRICS_MAX /**< Max Metrics */
};



enum nf_ip6_fwd_route_metrics_flags {
/*!
 * @internal
 * Macros that define which metric is set
 * Macro to set UNSPEC Bit
 * NF_IP6_RT_METRIC_UNSPEC_SET = BIT(0)
 * Macro to set LOCK Bit
 * NF_IP6_RT_METRIC_LOCK_SET = BIT(1)
 * @endinternal
 */
	NF_IP6_RT_METRIC_MTU_SET = BIT(2),
	/**< Macro to set Path MTU Bit */
	NF_IP6_RT_METRIC_WINDOW_SET = BIT(3),
	/**< Macro to set  maximum advertised window bit*/
	NF_IP6_RT_METRIC_RTT_SET = BIT(4),
	/**< Macro to set RTT Bit  */
	NF_IP6_RT_METRIC_RTTVAR_SET = BIT(5),
	/**< Macro to set RTT Variance Bit */
	NF_IP6_RT_METRIC_SSTHRESH_SET = BIT(6),
	/**< Macro to set SSTHRESH Bit */
	NF_IP6_RT_METRIC_CWND_SET = BIT(7),
	/**< Macro to set CWND Bit */
	NF_IP6_RT_METRIC_ADVMSS_SET = BIT(8),
	/**< Macro to set ADVMSS Bit */
	NF_IP6_RT_METRIC_REORDERING_SET = BIT(9),
	/**< Macro to set Reordering Bit */
	NF_IP6_RT_METRIC_HOPLIMIT_SET = BIT(10),
	/**< Macro to set Hop Limit Bit */
	NF_IP6_RT_METRIC_INITCWND_SET = BIT(11),
	/**< Macro to set Init CWND Bit */
/*!
 * @internal
 * Macro to set features bit
 * NF_IP6_RT_METRIC_FEATURES_SET = BIT(12),
 * @endinternal
 */
	NF_IP6_RT_METRIC_RTO_MIN_SET = BIT(13),
	/**< Macro to set RTO MIN Bit */
	NF_IP6_RT_METRIC_INITRWND_SET = BIT(14)
	/**< Macro to set Init RWND Bit */
};


/*!
 * Structure to add a route entry
 */
struct nf_ip6_fwd_route_entry {
	struct nf_ipv6_addr dst_addr;
	/**< Destination IP */
	uint8_t prefix_len;
	/**< Destination IP prefix len */
	uint16_t rt_table_id;
	/**< Route table ID, to which this route is to be added */
	uint32_t priority;
	/**< Priority/Metric of the route. Smaller the value, higher
	 * the priority/metric.*/
	uint8_t tc;
	/**< Traffic class (tos) */
	uint8_t type;
	/**< Route type*/
	uint8_t num_gw;
	/**< Number of gateways present in this route */
	uint8_t protocol;
	/**< Specifies how this route is installed. Could be through
	 * ICMP redirect message/native OS/ During boot/by admin/by a
	 * routing protocol */
	struct nf_ipv6_addr prefsrc;
	/**< Preferred source for the route */
	uint16_t path_mtu;
	/**< MTU defined for the path */
	struct nf_ip6_fwd_nh gw_info[NF_IP6_FWD_MAX_ECMP_GWS];
	/**< Single/Multiple gateway(s). */
	uint32_t route_metrics[NF_IP6_RT_METRICS_MAX];
	/**< Metrics for the routei: TCP window size, RTT, advmss, etc */
	uint16_t route_metrics_flags;
	/**< Route metrics flag. Refer #nf_ip6_fwd_route_metrics_flags*/
#define NF_IP6_FWD_ROUTE_ACCESSED BIT(1)
	/*! Macro to set IP FWD Route Accessed Bit */
	uint8_t state;
	/**< State of route accessibility. If this flag is set,
	 *   this it is assumed that internal implementation has
	 *   to invalidate the cache (if implemented).*/
};

/*!
 * Structure to modify a route entry
 */
struct nf_ip6_fwd_route_entry_mod {
	struct nf_ipv6_addr dst_addr;
		/**< Destination IP */
	uint8_t prefix_len;
		/**< Destination IP prefix len */
	uint16_t rt_table_id;
	/**< Route table ID, to which this route is to be added */
	uint32_t priority;
	/**< Priority/Metric of the route. Smaller the value, higher
	 * the priority/metric.*/
	uint8_t tc; /**< Traffic class (tos) */
	uint8_t type; /**< Route type*/
	uint8_t num_gw;
	/**< Number of gateways present in this route */
	uint8_t protocol;
	/**< Specifies how this route is installed. Could be through
	 * ICMP redirect message/native OS/ During boot/by admin/by a
	 * routing protocol */
	struct nf_ipv6_addr prefsrc; /**< Preferred source for the route */
	uint16_t path_mtu; /**< MTU defined for the path */
	struct nf_ip6_fwd_nh gw_info[NF_IP6_FWD_MAX_ECMP_GWS];
	/**< Single/Multiple gateway(s). */
	uint32_t route_metrics[NF_IP6_RT_METRICS_MAX];
	/**< Metrics for the routei: TCP window size, RTT, advmss, etc */
	uint16_t route_metrics_flags;
	/**< Route metrics flag. Refer #nf_ip6_fwd_route_metrics_flags*/
#define NF_IP6_FWD_ROUTE_ACCESSED BIT(1)
	/*! Macro to set IP FWD Route Accessed Bit */
	uint8_t state;
	/**< State of route accessibility. If this flag is set,
	 *   this it is assumed that internal implementation has
	 *   to invalidate the cache (if implemented).*/
};

/*!
 * Structure to delete a route entry
 */
struct nf_ip6_fwd_route_entry_del {
	struct nf_ipv6_addr dst_addr; /**< Destination IP */
	uint8_t prefix_len; /**< Destination IP prefix len */
	uint16_t rt_table_id;
	/**< Route table ID, to which this route is to be added */
	uint32_t priority;
	/**< Priority/Metric of the route. Smaller the value, higher
	 * the priority/metric.*/
	uint8_t tc; /**< Traffic class (tos) */
};

/*!
 * IPv6 unicast forward statistics structure
 */
struct nf_ip6_fwd_stats {
      uint64_t ip6_in_pkts; /**< In rcvd pkts */
      uint64_t ip6_in_bytes; /**< In rcvd bytes*/
      uint64_t ip6_in_hdr_errs; /**< In pkt hdr err */
      uint64_t ip6_in_no_route; /**< In no route */
      uint64_t ip6_in_local_pkts; /**< In local deliver */
      uint64_t ip6_in_fwd_pkts; /**< Forwarded pkts */
      uint64_t ip6_out_pkts; /**< Out rcvd pkts */
      uint64_t ip6_out_bytes; /**< Out rcvd bytes*/
      uint64_t ip6_out_hdr_errs; /**< Out pkt hdr err */
      uint64_t ip6_out_no_route; /**< Out no route */
      uint64_t ip6_spoof_pkt; /**< Out no route */
};


/*!
 * Structure used for output arguments for
 * PBR rules related NF API
 */
struct nf_ip6_fwd_pbr_rule_outargs {
      int32_t result; /**< stores result*/
};

/*!
 * Structure used for output arguments
 * for ipv6 Spoof attack check status related NF API
 */
struct nf_ip6_fwd_spoof_atk_chk_outargs {
	int32_t result; /**< stores result*/
};
/*!
 * @internal
 * ipr status outargs
 * @endinternal
 */
/*!
 * Structure used for output arguments
 * for ipv6 IPR status related NF API
 */
struct nf_ip6_fwd_ipr_outargs {
	int32_t result; /**< stores result*/
};

/*!
 * Structure used for output arguments for
 * route related NF API
 */
struct nf_ip6_fwd_route_outargs {
      int32_t result; /**< stores result*/
};

/*!
 * Structure used for output arguments for
 * ip6 fwd stats related NF API
 */
struct nf_ip6_fwd_stats_outargs {
      int32_t result; /**< stores result*/
      struct nf_ip6_fwd_stats ip6_fwd_stats; /**< ipv6 forward stats*/
};


/*!
 * Input parameters to  PBR configuration
 */
struct nf_ip6_fwd_pbr_rule_cfg_inargs {
	uint16_t pbr_rule_priority_id;   /**< PBR rule priority */
	struct nf_ip6_fwd_pbr_rule pbr_rule_params; /**< PBR rule parameters */
};

/*!
 * Output parameters to  PBR rule configuration
 */
struct nf_ip6_fwd_pbr_rule_cfg_outargs {
      int32_t result; /**< 0:Success;
        	       *   Non Zero value: Error code indicating failure */
};

/*!
 * PBR get operations
 */
enum nf_ip6_fwd_pbr_rule_get_op {
      NF_IP6_FWD_PBR_GET_FIRST = 0, /**< Fetch first entry in the database */
      NF_IP6_FWD_PBR_GET_NEXT =1, /**< Fetch next entry for given PBR rule */
      NF_IP6_FWD_PBR_GET_EXACT = 2 /**< Fetch eact PBR entry for given priority*/
};

/*!
 * Input parameters for get operations of PBR rules
 */
struct nf_ip6_fwd_pbr_rule_get_inargs {
      uint8_t operation;
      /**< Get operation type. Refer #nf_ip6_fwd_pbr_get_op */
      struct nf_ip6_fwd_pbr_rule pbr_rule_params; /**< PBR rule details */
};

/*!
 * Output parameters for get operations of PBR rules
 */
struct nf_ip6_fwd_pbr_rule_get_outargs {
      int32_t result; /**< 0:Success;
		       *   Non Zero value: Error code indicating failure */
      struct nf_ip6_fwd_pbr_rule pbr_rule_params; /**< PBR rule details */
/*!
 * @internal
 * TBD - Stats?
 * @endinternal
 */
};

/*!
 * Input parameters to route configuration
 */
struct nf_ip6_fwd_route_cfg_inargs {
      struct nf_ip6_fwd_route_entry route_params; /**< Route parameters */
};

/*!
 * Output parameters to route configuration
 */
struct nf_ip6_fwd_route_cfg_outargs {
      int32_t result; /**< 0:Success;
			 * Non Zero value: Error code indicating failure */
};

/*!
 * Route get operations
 */
enum nf_ip6_fwd_route_get_op {
      NF_IP6_FWD_ROUTE_GET_FIRST = 0, /**< Fetch first entry in the database */
      NF_IP6_FWD_ROUTE_GET_NEXT =1, /**< Fetch next entry for given route */
      NF_IP6_FWD_ROUTE_GET_EXACT = 2 /**< Fetch eact route entry */
};

/*!
 * Input parameters for get operations of routes
 */
struct nf_ip6_fwd_route_get_inargs {
      uint8_t operation;
      /**< Get operation type. Refer #nf_ip6_fwd_route_get_op */
      uint32_t route_table_id; /**< Route table ID*/
      struct nf_ip6_fwd_route_entry route_in_params; /**< Route parameters */
};

/*!
 * Input parameters for get operations of routes
 */
struct nf_ip6_fwd_route_get_outargs {
      int32_t result;
      /**< 0:Success; Non Zero value: Error code indicating failure */
      struct nf_ip6_fwd_route_entry route_out_params;
      /**< Route parameters */
/*!
 * @internal
 * TBD - Stats?
 * @endinternal
 */
};


/*!
 * @brief  Callback function for processing packet
 *	   received from DP
 *
 * @param[in] pkt  pointer to nf_pkt_buf structure
 *
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Unicast
 */
typedef int32_t (*nf_ip6fwdappl_rcvselfpkt_fromdp_cbk_fn)(
		struct nf_pkt_buf *pkt, struct nfinfra_pkt_meta *meta);

/*!
 * Ip fwd application registered structure
 */
struct nf_ip6_fwd_apln_register_cbk_fn {
      nf_ip6fwdappl_rcvselfpkt_fromdp_cbk_fn ip6fwdappln_selfpkt_recv_fn;
				       /**< self pkt recv function. Refer #nf_ip6fwdappl_rcvselfpkt_fromdp_cbk_fn
					*/
};


/*!
 * IPv6 forward Namespace specific PBR status enable/disable
 */
enum nf_ip6_fwd_pbr_status {
      NF_IP6_FWD_PBR_STATUS_ENABLE = 0,
      /**< to enable ipv6 PBR status*/
      NF_IP6_FWD_PBR_STATUS_DISABLE
      /**< to disable ipv6 PBR status*/
};

/*!
 * IPv6 forward Namespace specific Spood attack check status enable/disable
 */
enum nf_ip6_fwd_spoof_atk_chk_status {
	NF_IP6_FWD_SPOOF_ATK_CHK_STATUS_ENABLE = 0,
	/**< to enable ipv6 spoof attck check status*/
	NF_IP6_FWD_SPOOF_ATK_CHK_STATUS_DISBLE
		/**< to disable ipv6 spoof attck check status*/
};

/*!
 * IPv6 forward Namespace specific forwarding status enable/disable
 */
enum nf_ip6_fwd_status {
	NF_IP6_FWD_STATUS_ENABLE = 0,
	/**< to enable ipv6 forwarding status*/
	NF_IP6_FWD_STATUS_DISBLE
		/**< to disable ipv6 forwarding status*/
};
/*
 * @internal
 * IPv6 DP status
 * @endinternal
 */
/*!
 * IPv6 forward DP status enable/disable
 */
enum nf_ip6_fwd_dp_status {
	NF_IP6_FWD_DP_STATUS_ENABLE = 0,
	/**< to enable ipv6 forwarding DP status*/
	NF_IP6_FWD_DP_STATUS_DISBLE
		/**< to disable ipv6 forwarding DP status*/
};
/*
 * @internal
 * IPv6 IPR status
 * @endinternal
 */
/*!
 * IPv6 forward IPR status enable/disable
 */
enum nf_ip6_fwd_ipr_status_flag {
	NF_IP6_FWD_IPR_STATUS_ENABLE = 0,
	/**< To enable ipv6 forwarding IPR status*/
	NF_IP6_FWD_IPR_STATUS_DISBLE
		/**< To disable ipv6 forwarding IPR status*/
};

/*
@internal
 * nfapi defines for ip features
@endinternal
*/
/*!
 * Macro specifying spoof attack feature is enabled
 */
#define NFAPI_IP6_FWD_SPOOF_ENABLED 0x01
/*!
 * Macro specifying PBR feature is enabled
 */
#define NFAPI_IP6_FWD_PBR_ENABLED 0x02
/*!
 * Macro specifying packet forwarding feature is enabled
 */
#define NFAPI_IP6_FORWARDING_ENABLED 0x04
/*!
 * Macro specifying DP is enabled
 */
#define NFAPI_IP6_FWD_DP_ENABLED 0x08
/*!
 * Macro specifying IP reassembly feature is enabled
 */
#define NFAPI_IP6_FWD_IPR_ENABLED 0x10


/*
@internal
 * Structure used for output arguments for
 * status related NF API
@endinternal
*/
struct nf_ip6_fwd_status_outargs {
	uint32_t result; /* Result */
	uint8_t status; /*Stores enabled feature info*/
};


/*!
 * @brief  	This API adds a rule to the Policy Based Routing
 * rule database. This database is maintained per
 * Name Space instance. This function first validates
 * the incoming parameters and if all validations succeed,
 * adds the rule in the PBR rule database.
 *
 * @param[in] ns_id  NamesSpace ID
 * @param[in] new_pbr_rule  pointer to nf_ip6_fwd_pbr_rule structure
 * @param[in] flags  Control Flags for the NF API.
 * @param[in] ip6_fwd_pbr_respargs  Response arguments that will be passed to
 * the call back when the call is asynchronous.
 * Following fields are to be filled by the caller:
 * cbfn - Call back function pointer to be invoked
 * cbarg  - Call back function argument
 * cbarg_len - Call back function argument length
 *
 * @param[out] ip6_out_args  Structure that will be filled with output
 * values of this API. This structure is filled when the
 * call is synchronous or asynchronous. If asynchronous,
 * this will be the last argument to the call back function
 * ip4_fwd_pbr_respargs described above.
 * Following fields are filled in the structure:
 * result : Result of this API. Success or failure code in
 * case of failure. Refer Return values of this API.
 * @returns	0 on Success or negative value on failure
 * @internal
 * Success if a rule is added successfully else
 * one of the following error code is returned
 * - Invalid parameter value (ip, action)
 * - Memory allocation failure to create a rule
 * - more values are TBD
 * @endinternal
 *
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_pbr_rule_add(nf_ns_id ns_id,
		const struct nf_ip6_fwd_pbr_rule *new_pbr_rule,
		nf_api_control_flags flags,
		struct nf_ip6_fwd_pbr_rule_outargs *ip6_out_args,
		struct nf_api_resp_args  *ip6_fwd_pbr_respargs);


/*!
 * @brief  	This API deletes a rule to the Policy Based Routing
 *	rule database. If the rule to be deleted is a
 *	permanent rule, an error will be thrown.
 *	Any non-zero value for the in parameters is
 *	considered as a valid field value. The order of validating
 *	fields will be in the following order
 *
 * @param[in] ns_id  NamesSpace ID
 * @param[in] pbr_rule  pointer to nf_ip6_fwd_pbr_rule_del structure
 * @param[in] flags  Control  Flags for the NF API.
 * @param[in] ip6_fwd_pbr_respargs - Response arguments that will be
 * passed to the call back when the call is asynchronous.
 * Following fields are to be filled by the caller:
 * cbfn - Call back function pointer to be invoked
 * cbarg  - Call back function argument
 * cbarg_len - Call back function argument length
 *
 * @param[out] ip6_out_args  Structure that will be filled with output
 * values of this API.
 * This structure is filled when the call is synchronous or
 * asynchronous. If asynchronous, this will
 * be the last argument to the call back function
 * ip6_fwd_pbr_respargs described above.
 * Following fields are filled in the structure:
 * result : Result of this API. Success or failure code
 * in case of failure. Refer Return values of this API.
 *
 * @returns	0 on Success or negative value on failure
 * @internal
 * Success if a rule is deleted successfully else
 * one of the following error code is returned
 * 	- Invalid parameter value (ip, action)
 *	- Memory allocation failure to delete a rule
 *	- more values are TBD
 * @endinternal
 *
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_pbr_rule_delete(nf_ns_id ns_id,
		const struct nf_ip6_fwd_pbr_rule_del *pbr_rule,
		nf_api_control_flags flags,
		struct nf_ip6_fwd_pbr_rule_outargs *ip6_out_args,
		struct nf_api_resp_args  *ip6_fwd_pbr_respargs);

/*!
 * @brief       This API is used to get PBR rule. This database
 *	is maintained per Name Space.
 *	This function first validates the incoming parameters
 *	and if all validations succeed, the following is
 *	performed depending on the type of operation:
 *	if operation is get_first, fetches first PBR rule
 *	from the database.
 *	if operation is get_next, finds the entry in the
 *	rule database with given information and
 *	returns the next entry.
 *	if operation is get_exact, finds the entry and returns it.
 *
 * @param[in] nsid  NamesSpace ID
 * @param[in] in  Pointer to input param structure
 *		  which contains  PBR rule information.
 * @param[in] flags  API Control  flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @param[out] out  Pointer to output param structure
 *		     that will be filled with output values of this API.
 *
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_pbr_rule_get(nf_ns_id nsid,
      const struct nf_ip6_fwd_pbr_rule_get_inargs *in,
      nf_api_control_flags flags,
      struct nf_ip6_fwd_pbr_rule_get_outargs *out,
      struct nf_api_resp_args *resp);


/*!
 * @brief       This API adds a route to routing database.
 *	This database is maintained per Name Space.
 *	This function first validates the incoming parameters
 *	and if all validations succeed, then new route is added
 *	to the database.
 *
 * @param[in] ns_id  NamesSpace ID
 * @param[in] new_rt_entry_data  pointer to nf_ip6_fwd_route_entry
 * @param[in] flags  Control Flags for the NF API.
 * @param[in] ip6_fwd_route_respargs  Response arguments that will be passed
 * to the call back when the call is asynchronous.
 * Following fields are to be filled by the caller:
 * cbfn - Call back function pointer to be invoked
 * cbarg  - Call back function argument
 * cbarg_len - Call back function argument length
 *
 * @param[out] ip6_out_args  Structure that will be filled with output
 * values of this API.
 *	This structure is filled when the call is synchronous
 *	or asynchronous. If asynchronous, this will
 *	be the last argument to the call back function
 *	ip6_fwd_pbr_respargs described above.
 *	Following fields are filled in the structure:
 *	result : Result of this API. Success or failure code
 *	in case of failure. Refer Return values of this API.
 *
 * @returns	0 on Success or negative value on failure
 * @internal
 * Success if a route is added successfully else
 * one of the following error code is returned
 * - Invalid parameter value (ip, action)
 * - Memory allocation failure to create a rule
 * - more values are TBD
 * @endinternal
 *
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_route_add(nf_ns_id ns_id,
		const struct nf_ip6_fwd_route_entry *new_rt_entry_data,
		nf_api_control_flags flags,
		struct nf_ip6_fwd_route_outargs *ip6_out_args,
		struct nf_api_resp_args  *ip6_fwd_route_respargs);

/*!
 * @brief       This API modifies a route in the routing database.
 *	This database is maintained per Name Space.
 *	This function first validates the incoming parameters
 *	and if all validations succeed, then updates the given route
 *	record in the database.
 *
 * @param[in] ns_id  NamesSpace ID
 * @param[in] rt_entry_data  pointer to nf_ip6_fwd_route_entry_mod
 * @param[in] flags  Control Flags for the NF API.
 * @param[in] ip6_fwd_route_respargs  Response arguments that will be passed
 * to the call back when the call is asynchronous.
 * Following fields are to be filled by the caller:
 * cbfn - Call back function pointer to be invoked
 * cbarg  - Call back function argument
 * cbarg_len - Call back function argument length
 *
 * @param[out] ip6_out_args  Structure that will be filled with
 * output values of this API.
 * This structure is filled when the call is synchronous
 * or asynchronous. If asynchronous, this will
 * be the last argument to the call back function
 * ip6_fwd_pbr_respargs described above.
 * Following fields are filled in the structure:
 * result : Result of this API. Success or failure code
 * in case of failure. Refer Return values of this API.
 *
 * @returns	0 on Success or negative value on failure
 * @internal
 * Success if a rule is updated successfully else
 * one of the following error code is returned
 * - Invalid parameter value (ip, action)
 * - Memory allocation failure to update a rule
 * - more values are TBD
 * @endinternal
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_route_modify(nf_ns_id ns_id,
		const struct nf_ip6_fwd_route_entry_mod *rt_entry_data,
		nf_api_control_flags flags,
		struct nf_ip6_fwd_route_outargs *ip6_out_args,
		struct nf_api_resp_args  *ip6_fwd_route_respargs);

/*!
 * @brief       This API deletes a route from the routing database.
 *	This database is maintained per Name Space.
 *	This function first validates the incoming parameters
 *	and if all validations succeed, then deletes th given route
 *	record from the database.
 *
 * @param[in] ns_id  NamesSpace ID
 * @param[in] rt_entry_data  pointer to nf_ip6_fwd_route_entry_del
 * @param[in] flags - Control Flags for the NF API.
 * @param[in] ip6_fwd_route_respargs  Response arguments that will be passed
 * to the call back when the call is asynchronous.
 * Following fields are to be filled by the caller:
 * cbfn - Call back function pointer to be invoked
 * cbarg  - Call back function argument
 * cbarg_len - Call back function argument length
 *
 * @param[out] ip6_out_args  Structure that will be filled
 * with output values of this API.
 * This structure is filled when the call is synchronous
 * or asynchronous. If asynchronous, this will
 * be the last argument to the call back function
 * ip6_fwd_pbr_respargs described above.
 * Following fields are filled in the structure:
 * result : Result of this API. Success or failure code
 * in case of failure. Refer Return values of this API.
 *
 * @returns	0 on Success or negative value on failure
 * @internal
 * Success if a rule is deleted successfully else
 * one of the following error code is returned
 * - Invalid parameter value (ip, action)
 * - Memory allocation failure to delete a rule
 * - more values are TBD
 * @endinternal
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_route_delete(nf_ns_id ns_id,
		const struct nf_ip6_fwd_route_entry_del *rt_entry_data,
		nf_api_control_flags flags,
		struct nf_ip6_fwd_route_outargs *ip6_out_args,
		struct nf_api_resp_args  *ip6_fwd_route_respargs);

/*!
 * @brief       This API is used to get a route. This database
 *	is maintained per Name Space.
 *	This function first validates the incoming parameters
 *	and if all validations succeed, the following is
 *	performed depending on the type of operation:
 *	if operation is get_first, fetches first
 *	route from the database.
 *	if operation is get_next, finds the entry in the route database
 *	with given information and returns the next entry.
 *	if operation is get_exact, finds the entry and returns it.
 *
 * @param[in] nsid  Name Space ID for which the stats are to be retrieved.
 *	This field which is part of nf_ip6_fwd_stats argument,
 *	has to be filled by the caller.
 * @param[in] in  Pointer to input param structure
 * which contains  PBR rule information.
 * @param[in] flags  API Control flags.
 * @param[out] out  Pointer to output param structure
 * that will be filled with output values of this API.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @returns	0 on Success or negative value on failure
 *
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_route_get(nf_ns_id nsid,
      const struct nf_ip6_fwd_route_get_inargs *in,
      nf_api_control_flags flags,
      struct nf_ip6_fwd_route_get_outargs *out,
      struct nf_api_resp_args *resp);

/*!
 * @brief       Fetches ip6 forward module statistics.
 *
 * @param[in] nsid  Name Space ID for which the stats are to be retrieved.
 * This field which is part of nf_ip6_fwd_stats argument,
 * has to be filled by the caller.
 * @param[in] flags  API Control flags.
 * @param[in] ip6_fwd_stats_respargs  Response arguments that
 * will be passed to the call back when the
 *	call is asynchronous.
 * @param[out] ip6_out_args  Structure that will be filled
 * with output values of this API.
 * This structure is filled when the call is synchronous
 * or asynchronous. If asynchronous, this will
 * be the last argument to the call back function
 * ip6_fwd_route_respargs described above.
 * Following fields are filled in the structure:
 * result : Result of this API.
 * Success or failure code in case of failure.
 * @returns	0 on Success or negative value on failure
 *
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_stats_get(nf_ns_id nsid,
      nf_api_control_flags flags,
      struct nf_ip6_fwd_stats_outargs *ip6_out_args,
      struct nf_api_resp_args  *ip6_fwd_stats_respargs);

/*!
 * @brief   DP can send self-destined packet to application for the
 * packet to be given to local applications in the Control Plane.
 * IP Forward application at CP will register a function to
 * receive such packets from DP and further process the packet.
 *
 * @param[in] ip6_fwd_appln_cbk_fn  pointer to the structure containing the
 * callback function being registered by the
 * Ip Forward Application.
 * @returns	0 on Success or negative value on failure
 * @internal
 * Success if the callback function is registerd successfully
 * else failure is returned.
 * @endinternal
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_appln_register_cbk_fn(
		struct nf_ip6_fwd_apln_register_cbk_fn *ip6_fwd_appln_cbk_fn);


/*!
 * @brief   Send packet from CP to DP.
 *
 * @param[in] nsid  Namespace ID for which the stats are to be retrieved.
 *	This field which is part of nf_ip6_fwd_stats argument,
 *	has to be filled by the caller.
 * @param[in] pkt  Packet to send out
 * @param[in] meta  NF Infra packet metadata
 *
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_appln_send_pkt_to_dp(
      void *pkt,
      struct nfinfra_pkt_meta  *meta);
/*!
 * @internal
 * Buffer from CP  - TBD
 * @endinternal
 */

/*!
 * @brief   This API is used to set IP forward PBR status as
 * enable/disable for a given name space.
 *
 * @param[in] nsid  Namespace ID
 * @param[in] status  Status indicating enable/disable.
 * @param[in] flags  API Control flags.
 * @param[in] resp  Response arguments for asynchronous call.
 * @param[out] ip6_out_args  Structure that will be filled
 * with output values of this API.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_pbr_set_status(
	nf_ns_id nsid,
	enum nf_ip6_fwd_pbr_status status,
	nf_api_control_flags flags,
	struct nf_ip6_fwd_pbr_rule_outargs *ip6_out_args,
	struct nf_api_resp_args *resp);

/*!
 * @brief   This API is used to set IPv6 Spoof attack check status as
 * enable/disable for a given name space.
 *
 * @param[in] nsid  Namespace ID
 * @param[in] status  Status indicating enable/disable.
 * @param[in] flags  API Control  flags.
 * @param[in] resp  Response arguments for asynchronous call.
 * @param[out] ip6_out_args  Structure that will be filled
 * with output values of this API.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_spoof_atk_chk_set_status(
                nf_ns_id nsid,
                enum nf_ip6_fwd_spoof_atk_chk_status status,
                nf_api_control_flags flags,
            	struct nf_ip6_fwd_spoof_atk_chk_outargs *ip6_out_args,
                struct nf_api_resp_args *resp);

/*
@internal
 * IPR status enable/disable
@endinternal
*/
/*!
 * @brief   This API is used to set IPv6 IPR status as
 * enable/disable for a given name space.
 *
 * @param[in] nsid  Namespace ID
 * @param[in] status  Status indicating enable/disable.
 * @param[in] flags  API Control  flags.
 * @param[in] ip6_out_args  IPR output args
 * @param[in] resp  Response arguments for asynchronous call.
 * @param[out] ip6_out_args  Structure that will be filled
 * with output values of this API.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_ipr_set_status(nf_ns_id nsid,
			enum nf_ip6_fwd_ipr_status_flag status,
			nf_api_control_flags flags,
			struct nf_ip6_fwd_ipr_outargs *ip6_out_args,
			struct nf_api_resp_args *resp);
/*!
 * @brief   This API is used to set IPv6 unicast forwarding status as
 * enable/disable for a given name space.
 *
 * @param[in] nsid  Namespace ID
 * @param[in] status  Status indicating enable/disable.
 * @param[in] flags  API Control  flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_set_status(
                nf_ns_id nsid,
                uint8_t status,
                nf_api_control_flags flags,
                struct nf_api_resp_args *resp);
/*
@internal
 * IPR status enable/disable
@endinternal
*/
/*!
 * @brief   This API is used to set IPv6 unicast forward DP status as
 * enable/disable for a given name space.
 *
 * @param[in] nsid  Namespace ID
 * @param[in] status  Status indicating enable/disable.
 * @param[in] flags  API Control  flags.
 * @param[in] resp  Response arguments for asynchronous call.
 *
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_dp_set_status(
                nf_ns_id nsid,
                uint8_t status,
                nf_api_control_flags flags,
                struct nf_api_resp_args *resp);

/*
@internal
 * IPR status enable/disable
@endinternal
*/
/*!
 * @brief   This API is used to get IPv6 forward features status.
 *
 * @param[in] nsid  Namespace ID
 * @param[in] status  Status indicating enable/disable.
 * @param[in] flags  API Control flags.
 * @param[in] resp  Response arguments for asynchronous call.
 * @param[out] ip6_out_args  Structure that will be filled
 * with output values of this API.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup IPv6_Unicast
 */
int32_t nf_ip6_fwd_get_status(
			nf_ns_id nsid,
			nf_api_control_flags flags,
			struct nf_ip6_fwd_status_outargs *ip6_out_args,
			struct nf_api_resp_args *resp);

#endif /* __IP6FWD_NFAPI_H */
/*! @} */
