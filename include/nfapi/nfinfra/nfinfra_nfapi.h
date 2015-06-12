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
 * @file  nfinfra_nfapi.h
 *
 * @brief  This file contains the NF-Infra Network Function API
 *
 * @addtogroup NF-INFRA
 * @{
*/
#ifndef __NFINFRA_NFAPI_H
#define __NFINFRA_NFAPI_H

#include "common_nfapi.h"

/*!
 * NFInfra packet meta information associated with the packet.
 */
struct nfinfra_pkt_meta {
	nf_ns_id nsid; /**< Namespace Identifier */
	uint16_t l2_proto; /**< L2 protocol of the packet */
	nf_if_id ifid; /**< Interface identifier. This value should be
		interpreted based on the current context of packet processing.
		This points to incoming network device in case of ingress and
		outgoing network device in case of egress context. */
	nf_if_id in_ifid; /**< Incoming interface identifier */
	uint8_t pkt_type; /**< Type of the packet */
	uint8_t reserved1; /**< Reserved field and not to be interpreted
		by user */
	uint16_t reserved2; /**< Reserved field and not to be interpreted
		by user */
};

/*!
 * @brief      Callback function to handle exception packet that is
 *             for reception.
 *
 * @details    Handle a packet in control plane. This hook typically
 *             gets called for unhandled packets in data-path due to
 *             unknown l2 protocol or due to a request from other
 *             data paths to push this packet to control path.
 *
 * @param[in]	pkt - pointer to the packet.
 *
 * @returns None.
 *
 * @ingroup NF-INFRA
 */
typedef void (*nfinfra_receive_packet_fn)(void *pkt);

/*!
 * @brief      Callback function to handle exception packet that is
 *             for transmission.
 *
 * @details    Handle packet transmission on an interface for which
 *             driver is not present in data path. Typically this
 *             happens when data path frind packet for transmission
 *             on a logical interface (e.g: gre, ipip)
 *
 * @param[in]	pkt - pointer to the packet.
 *
 * @returns None.
 *
 * @ingroup NF-INFRA
 */
typedef void (*nfinfra_transmit_packet_fn)(void *pkt);


/*! NFInfra notification hooks structure.
 * This contains hooks for receiving unsolicited notifications.
 */
struct nfinfra_notification_hooks {
	nfinfra_receive_packet_fn recv_fn; /*!<
			Funtion to handle packet meant for reception at
			control plane */
	nfinfra_transmit_packet_fn transmit_fn; /*!<
			Funtion to handle packet meant for transmission at
			control plane */
};

/*! Network namespace statistics structure. */
struct nfinfra_netns_stats {
	uint64_t in_pkts;	/*!< Ingress packets */
	uint64_t in_bytes;	/*!< Egress packets */
	uint64_t out_pkts;	/*!< Ingress bytes */
	uint64_t out_bytes;	/*!< Egress bytes */
};

/*! Network infra structure DP capabilities structure. */
struct nfinfra_capabilities {
	uint64_t capabilities; /*!< List of capabilities */
};

/*! Generic output parameters structure for NFInfra NF API. */
struct nfinfra_outargs{
	int32_t result;	/*!< Result code of the requested operation.
			Success or error code indicating failure */
};


/*! Output arguments structure for namespace statistics retrieval
 *  API
 */
struct nfinfra_netns_get_stats_outargs {
	int32_t result;	/*!< Result code of the requested operation.
			Success or error code indicating failure */
	struct nfinfra_netns_stats stats; /*!< namespace statistics */
};


/*!
 * @brief	Gets the version string of NFinfra NF API
 *
 * @param[out]	version - Pointer to string in which API version string is
 *		copied.
 * @returns	0 on Success or negative value on failure
 *
 * @ingroup NF-INFRA
 */
int32_t nfinfra_api_get_version(char *version);



/*!
 * @brief Gets the capabilities of NFInfra DP.
 *
 * @param[out]	capabilities - Pointer to nfinfra_capabilities structure.
 *
 * @returns  0 on Success or negative value on failure
 *
 * @ingroup NF-INFRA
 */
int32_t nfinfra_api_get_capabilities(struct nfinfra_capabilities *capabilities);


/*!
 * @brief   Adds a network namespace
 *
 * @details    This function first validates the incoming parameters and
 *             if all validations
 *             succeed, adds the entry in the database.
 *
 * @param[in]  nsid - Network namespace ID.
 *
 * @param[in]  flags - API behavioural flags.
 *
 * @param[out] out - output arguments structure.
 *
 * @param[in]  resp - Response arguments for asynchronous call.
 *
 * @returns    0 on Success or negative value on failure
 *
 * @ingroup NF-INFRA
 */
int32_t nfinfra_netns_add(
			nf_ns_id nsid,
			nf_api_control_flags flags,
			struct nfinfra_outargs *out,
			struct nf_api_resp_args *resp);


/*!
 * @brief   Deletes a network namespace in NFInfra DP.
 *
 * @param[in]  nsid - Network namespace ID.
 *
 * @param[in]  flags - API behavioural flags.
 *
 * @param[out] out - output arguments structure.
 *
 * @param[in] resp - Response arguments for asynchronous call.
 *
 * @returns   0 on Success or negative value on failure
 *
 * @ingroup NF-INFRA
 */
int32_t nfinfra_netns_delete(
			nf_ns_id nsid,
			nf_api_control_flags flags,
			struct nfinfra_outargs *out,
			struct nf_api_resp_args *resp);

/*!
 * Enumeration of network device types.
 */
enum nfinfra_netdev_type {
	NFINFRA_NETDEV_TYPE_UNKNOWN = 0, /*!< Unknown/Invalid */
	NFINFRA_NETDEV_TYPE_ETHER = 1, /*!< Ethernet */
	NFINFRA_NETDEV_TYPE_VLAN = 2, /*!< VLAN (8021q) */
	NFINFRA_NETDEV_TYPE_BRIDGE = 3, /*!< Bridge */
	NFINFRA_NETDEV_TYPE_IPIP = 4, /*!< IPv4 in IPv4 */
	NFINFRA_NETDEV_TYPE_IP6TUN = 5, /*!< IPv6 Tunnel Device */
	NFINFRA_NETDEV_TYPE_GRE = 6, /*!< GRE */
	NFINFRA_NETDEV_TYPE_SIT = 7, /*!< IPv6 in IPv4 Tunnel Device */
	NFINFRA_NETDEV_TYPE_PPP = 8, /*!< PPP */
	NFINFRA_NETDEV_TYPE_PIMREG = 9, /*!< PIMREG */
	NFINFRA_NETDEV_TYPE_LOOPBACK = 10, /*!< Loopback */
	NFINFRA_NETDEV_TYPE_UNUSED = 14, /*!< Start of unused IDs. */
	NFINFRA_NETDEV_TYPE_MAX = 24 /*!< */
};


/*!
 * This enumeration defines network device related flags. These
 * flags are not allowed to change after creation of network device.
 */
enum nfinfra_netdev_flags {
	NFINFRA_NETDEV_FLAGS_ETHER = BIT(0), /*!< Ethernet type of network
			device. e.g: Ethernet, VLAN, Bridge etc. */
	NFINFRA_NETDEV_FLAGS_P2P = BIT(1), /*!< Point to point type of network
			device. e.g: PPP, GRE, IPIP, SIT etc.*/
};


/*!
 * This enumeration defines operation flags of network device.
 * These flags are allowed to change at run-time.
 */
enum nfinfra_netdev_opflags {
	NFINFRA_NETDEV_OPFLAGS_UP = BIT(0), /*!< Administratively up or
			down */
	NFINFRA_NETDEV_OPFLAGS_LINK_UP = BIT(1), /*!< Underlying link is up or
			down. */
	NFINFRA_NETDEV_OPFLAGS_BRIDGE_PORT = BIT(2), /*!< Attached to a
			software based bridge or not. */
	NFINFRA_NETDEV_OPFLAGS_ARP = BIT(3), /*!< ARP enabled on this
			network device or not. This bit is valid only
			if NFINFRA_NETDEV_FLAGS_ETHER bit is set in flags. */
	NFINFRA_NETDEV_OPFLAGS_BCAST = BIT(4), /*!< Broadcast enabled on this
			network device or not. */
	NFINFRA_NETDEV_OPFLAGS_MCAST = BIT(5), /*!< Multicast enabled on this
			network device or not */
	NFINFRA_NETDEV_OPFLAGS_UNUSED = BIT(6), /*!< Start of unused flags and
			these can be used by other DPs. */
};

/*!
 * Maximum size of driver specific custom data
 */
#define NFINFRA_NETDRV_CDATA_MAX_SIZE (64)


/*! Network device add structure for NFInfra NF API. */
struct nfinfra_netdev_add {
        nf_if_id ifid;    /*!< Unique ID of this network device */
        enum nfinfra_netdev_type type;   /*!< Type of the network device */
        uint8_t flags; /*!< enum nfinfra_netdev_flags */
        uint16_t opflags; /*!< enum nfinfra_netdev_opflags */
        uint16_t mtu;   /*!< Maximum transmit unit */
        nf_ni_id pexi_niid; /*!< related ni-id of NI object for packet exchange
                        with CP. */
        uint8_t netdrv_cdata[NFINFRA_NETDRV_CDATA_MAX_SIZE]; /*!< Driver
			specific command data */
        uint8_t netdrv_cdata_len; /*!< Valid length of driver specific
                        command data */
};


/*! Network device add structure for NFInfra NF API. */
enum nfinfra_netdev_mod_flags {
	NFINFRA_NETDEV_MOD_FLAG_OPFLAGS = BIT(0), /*!< If set, opflags field
			is to be modified */
	NFINFRA_NETDEV_MOD_FLAG_MTU = BIT(1), /*!< If set, mtu field
			is to be modified */
	NFINFRA_NETDEV_MOD_FLAG_DRV_CDATA = BIT(2), /*!< If set, driver
			custom data field is to be modified */
};


/*! Network device modify structure for NFInfra NF API. */
struct nfinfra_netdev_mod {
        nf_if_id ifid;  /*!< Unique ID of this network device */
        uint32_t mod_flags; /*!< Boolean flags signifying which fields are
                        modified. */

        uint16_t opflags; /*!< enum nfinfra_netdev_opflags */
        uint16_t mtu;   /*!< Maximum transmit unit */
        uint8_t netdrv_cdata[NFINFRA_NETDRV_CDATA_MAX_SIZE]; /*!< Driver
			specific command data */
        uint8_t netdrv_cdata_len; /*!< Valid length of driver specific
                        command data */
};

/*! Network device delete structure for NFInfra NF API. */
struct nfinfra_netdev_del {
        nf_if_id ifid;    /*!< Unique ID of this network device */
};

/*!
 * @brief  Adds a network interface.
 *
 * @param[in]  nsid - Network namespace ID.
 *
 * @param[in]   in - Pointer to nfinfra_netdev_add structure containing
 *              information about network device.
 *
 * @param[in]  flags - API behavioural flags.
 *
 * @param[out]  out - output arguments structure.
 *
 * @param[in]  resp - Response arguments for asynchronous call.
 *
 * @returns  0 on Success or negative value on failure
 *
 * @ingroup NF-INFRA
 */
int32_t nfinfra_netdev_add(
			nf_ns_id nsid,
			const struct nfinfra_netdev_add *in,
			nf_api_control_flags flags,
			struct nfinfra_outargs *out,
			struct nf_api_resp_args *resp);

/*!
 * @brief  Modifies a network interface.
 *
 * @param[in]  nsid - Network namespace ID.
 *
 * @param[in]   in - Pointer to nfinfra_netdev_mod structure containing
 *              information about network device to modify.
 *
 * @param[in]  flags - API behavioural flags.
 *
 * @param[out]  out - output arguments structure.
 *
 * @param[in]  resp - Response arguments for asynchronous call.
 *
 * @returns  0 on Success or negative value on failure
 *
 * @ingroup NF-INFRA
 */
int32_t nfinfra_netdev_mod(
			nf_ns_id nsid,
			const struct nfinfra_netdev_mod *in,
			nf_api_control_flags flags,
			struct nfinfra_outargs *out,
			struct nf_api_resp_args *resp);

/*!
 * @brief  Deletes a network interface.
 *
 * @param[in]  nsid - Network namespace ID.
 *
 * @param[in]   in - Pointer to nfinfra_netdev_mod structure containing
 *              information about network device to delete.
 *
 * @param[in]  flags - API behavioural flags.
 *
 * @param[out]  out - output arguments structure.
 *
 * @param[in]  resp - Response arguments for asynchronous call.
 *
 * @returns  0 on Success or negative value on failure
 *
 * @ingroup NF-INFRA
 */
int32_t nfinfra_netdev_del(
			nf_ns_id nsid,
			const struct nfinfra_netdev_del *in,
			nf_api_control_flags flags,
			struct nfinfra_outargs *out,
			struct nf_api_resp_args *resp);



/*!
 * @brief    This API retrieves statistics of a given network namespace.
 *
 * @param[in]  nsid - Network namespace ID.
 *
 * @param[in]  flags - API behavioural flags.
 *
 * @param[out]  out - pointer to nfinfra_netns_get_stats_outargs structure.
 *
 * @param[in]  resp - Response arguments for asynchronous call.
 *
 * @returns   0 on Success or negative value on failure
 *
 * @ingroup NF-INFRA
 */
int32_t nfinfra_netns_stats_get(
			nf_ns_id nsid,
			nf_api_control_flags flags,
			struct nfinfra_netns_get_stats_outargs *out,
			struct nf_api_resp_args *resp);




/*!
 * @brief    Register callback hooks for receiving unsolicited notifications
 *               sent by NFInfra NF-DP.
 *
 * @param[out]   hooks - Pointer to nfinfra_notification_hooks structure
 *		 containing callback function pointers.
 *
 * @returns      0 on Success or negative value on failure
 *
 * @ingroup NF-INFRA
 */
int32_t nfinfra_notification_hooks_register(
			const struct nfinfra_notification_hooks *hooks);

/*!
 * @brief  Deregister NFInfra DP notification callback hooks.
 *
 * @returns  0 on Success or negative value on failure
 *
 * @ingroup NF-INFRA
 */
int32_t nfinfra_notification_hooks_deregister(void);

#endif /* __NFINFRA_NFAPI_H */
/*! @} */
