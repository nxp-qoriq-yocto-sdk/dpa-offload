/*!
 * @file  common_nfapi.h
 *
 * @brief  This file contains common declarations for all Network Function API.
 *
 * @addtogroup NF_BDT
 * @{
*/
#ifndef __COMMON_NFAPI_H
#define __COMMON_NFAPI_H

#ifndef BIT
#define BIT(x)  (1<<((x)))
#endif

/*! Name space ID. */
typedef uint16_t nf_ns_id;

/*! Interface ID */
typedef uint32_t nf_if_id;

/*! Network Interface ID */
typedef uint32_t nf_ni_id;

/*! API behavioural flags. */
enum nf_api_control_flags {
	NF_API_CTRL_FLAG_ASYNC = BIT(0), /**< If set, API call should be
			asynchronous. Otherwise API call will be synchronous.*/
	NF_API_CTRL_FLAG_NO_RESP_EXPECTED = BIT(1), /**< If set, no response is
			expected for this API call */
};
/*! API behavioural flags. */
typedef uint32_t nf_api_control_flags;

/*! IPv4 address */
typedef uint32_t nf_ipv4_addr;


/*!
 * IPv6 address
 */
struct nf_ipv6_addr{
	/*!  U8 Addr Len. */
#define NF_IPV6_ADDRU8_LEN 16
	/*!  U16 Addr len */
#define NF_IPV6_ADDRU16_LEN 8
	/*!  U32 Addr len */
#define NF_IPV6_ADDRU32_LEN 4

/*! Union details
*/
       union {
               uint8_t b_addr[NF_IPV6_ADDRU8_LEN];
                       /**< Byte addressable v6 address */
               uint32_t w_addr[NF_IPV6_ADDRU32_LEN];
                       /**< Word addressable v6 address */
       };
};

/*!
 * IP Version
 */
enum nf_ip_version {
	NF_IPV4 = 4, /**< IPv4 Version */
	NF_IPV6 = 6 /**< IPv6 Version */
};

/*!
 * IP address
 */
struct nf_ip_addr {
	enum nf_ip_version version; /**< IP Version */
/*! Union details
*/
	union {
		nf_ipv4_addr ipv4;
			/**< IPv4 Address */
		struct nf_ipv6_addr ipv6;
			/**< IPv6 Address */
	};
};

/*! IPv4/IPv6 address type. */
enum nf_ip_addr_type {
	NF_IPA_ANY = 0,/** None */
	NF_IPA_SINGLE ,/** Single IP address */
	NF_IPA_SUBNET,	/** Subnet */
	NF_IPA_RANGE,	/** Range of IP addresses */
	NF_IPA_NET_OBJ,	/** Single network object */
	NF_IPA_NET_GRP_OBJ	/** Group of network objects */
};


/*! IPv4 address type for single/rangle/subnet/object/object group. */
struct nf_ipv4_addr_info {

	uint8_t	type;		/**< Type of ipv4 address data.
				 * See "enum nf_ip_addr_type". */
/*! Union details
*/
	union {
/*! Struct details
*/
		struct {
			nf_ipv4_addr ip_addr; /**< Single IPv4 address */
		} single;

/*! Struct details
*/
		struct {
			nf_ipv4_addr addr; /**<  Network address */
			uint32_t prefix_len; /**< Prefix length */
		} subnet;

/*! Struct details
*/
		struct {
			nf_ipv4_addr begin; /**< Start of range of IPv4
					* addresses. */
			nf_ipv4_addr end; /**< End of range of
					IPv4 addresses. */
		} ip_range;

		uint32_t ip4_net_obj_id; /**< Network object  ID */

		uint32_t ip4_netgrp_obj_id; /**< Network group object ID  */
	};
};

/*! IPv6 address type for single/rangle/subnet/object/object group. */
struct nf_ipv6_addr_info {
	uint8_t	type;		/**< Type of ipv4 address data.
				 * See "enum nf_ip_addr_type". */
/*! Union details
*/
	union {
/*! Struct details
*/
		struct {
			struct nf_ipv6_addr ip; /**< Single IPv6 address */
		} single;
/*! Struct details
*/
		struct {
			struct nf_ipv6_addr addr; /**<  Network address */
			uint32_t prefix_len; /**< Prefix length */
		} subnet;
/*! Struct details
*/
		struct {
			struct nf_ipv6_addr begin; /**< Start of range of IPv6
						* addresses. */
			struct nf_ipv6_addr end; /**< End of range of
						IPv6 addresses. */
		} range;
		uint32_t ip6_net_obj_id; /**< Network object  ID */

		uint32_t ip6_netgrp_obj_id; /**< Network group object ID  */
	};
};

/*! Port type. */
enum nf_l4_port_type {
	NF_L4_PORT_ANY,		/**< Wild card */
	NF_L4_PORT_SINGLE,		/**< Single port */
	NF_L4_PORT_RANGE,		/**< Range of ports */
	NF_L4_PORT_SERVICE,		/**< Standard or custom service port */
	NF_L4_PORT_SERVICE_GRP		/**< Service group */
};

/*! Data type for service single/range/object. */
struct nf_l4_port {
	uint8_t	type;		/**< Type of port data. See "enum nf_l4_port_type". */
/*! Union details
*/
	union {
/*! Struct details
*/
		struct {
			uint16_t port;	/**< Single port */
		} single;
/*! Struct details
*/
		struct {
			uint16_t begin;	/**< Start of range of ports */
			uint16_t end;	/**< End of range of ports */
		} range;
		uint32_t srv_obj_id; /**< ID of standard or custom service
					record */
		uint32_t srv_grp_obj_id; /**< ID of service group record */
	};
};

/*!
 * Structure that defines the arguments for the call back API that registered by
 * the application to receive packets from DP/AIOP to CP/GPP
 */
struct nf_pkt_buf
{
     nf_ns_id nsid; /**< Namespace identifier */
     void *pkt; /**< Buffer from DP - TBD */
};

/*! Definition of response callback function for asynchronous API
 * call.
 */
typedef void (*nf_api_resp_cbfn)(void *cbarg, int32_t cbarg_len, void *outargs);

/*! API response arguments structure. */
struct nf_api_resp_args {
	nf_api_resp_cbfn cbfn; /**< Response callback function pointer */
	void *cbarg;	/**< Pointer to response callback argument data */
	int32_t cbarg_len;/**< Length of callback argument data */
};

#endif /* __COMMON_NFAPI_H */
/*! @} */
