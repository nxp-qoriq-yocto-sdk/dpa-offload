/* Copyright (c) 2014 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
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

/*
 * IPSEC NF API library internal API
 */

#ifndef __IPSEC_H
#define __IPSEC_H

#include <stdbool.h>
#include <stdint.h>

#include <compat.h>
#include <fsl_bman.h>
#include <fsl_qman.h>
#include <mem_cache.h>

#include "common_nfapi.h"
#include "ipsec_nfapi.h"

/* IPSEC max capacity default values */
#define NF_IPSEC_MAX_SAS			256
#define NF_IPSEC_MAX_POLS			256
#define NF_IPSEC_MAX_SEL			10
#define NF_IPSEC_MAX_DSCP			10
#define NF_IPSEC_MAX_CRYPTO_KEY_BYTES		255
#define NF_IPSEC_MAX_LINK_NODES			256
#define NF_IPSEC_MAX_POOL_LINK_NODES		3

#define NF_IPSEC_DIR_INBOUND	0
#define NF_IPSEC_DIR_OUTBOUND	1
#define NF_IPSEC_DIR_NUM	2

#define FEATURE_SUPPORTED	1
#define FEATURE_UNSUPPORTED	0

#define ESP_PROTOCOL_NUMBER 50
#define AH_PROTOCOL_NUMBER 51

#define DPA_IPSEC_SA_START_SEQ_NUM_DEFAULT 1
/* Default value for L2 header size is set to not support VLAN */
#define DPA_IPSEC_SA_L2_HDR_SIZE_DEFAULT 14
/* Default value for SA work-queue is set to 0 - high priority */
#define DPA_IPSEC_SA_WQ_DEFAULT 0
/* Default value for SA enable statistics */
#define DPA_IPSEC_SA_EN_STATS_DEFAULT true
/* Default value for SA enable extended statistics */
#define DPA_IPSEC_SA_EN_EXT_STATS_DEFAULT true
/* A window of 32 bits, means a window of 4 bytes in NF API */
#define DPA_IPSEC_SA_ARW_32_BITS 4
/* DEfault value for variable IP header length */
#define DPA_IPSEC_SA_VAR_IPHDR_DEFAULT true

#define IPSEC_ENC_ATH_ALG_INVALID_SELECTION 0xFFFFFFFF

/* Macro for encryption algorithm IPSEC_ENC_ALG_NULL */
#define IPSEC_ALG_ENC_NULL(_auth)				\
	((_auth == NF_IPSEC_AUTH_ALG_MD5HMAC) ?			\
	  DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_96_MD5_128 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_SHA1HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_96_SHA_160 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_AESXCBC) ?			\
	  DPA_IPSEC_CIPHER_ALG_NULL_ENC_AES_XCBC_MAC_96 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_SHA2_256_HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_SHA_256_128 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_SHA2_384_HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_SHA_384_192 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_SHA2_512_HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_SHA_512_256 :	\
	  IPSEC_ENC_ATH_ALG_INVALID_SELECTION)

/* Macro for encryption algorithm IPSEC_ALG_ENC_3DES_CBC */
#define IPSEC_ALG_ENC_3DES_CBC(_auth)				\
	((_auth == NF_IPSEC_AUTH_ALG_MD5HMAC) ?			\
	  DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_96_MD5_128 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_SHA1HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_96_SHA_160 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_AESXCBC) ?			\
	  IPSEC_ENC_ATH_ALG_INVALID_SELECTION :			\
	 (_auth == NF_IPSEC_AUTH_ALG_SHA2_256_HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_256_128 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_SHA2_384_HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_384_192 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_SHA2_512_HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_512_256 :	\
	  IPSEC_ENC_ATH_ALG_INVALID_SELECTION)

/* Macro for encryption algorithm IPSEC_ALG_ENC_AES_CBC */
#define IPSEC_ALG_ENC_AES_CBC(_auth)				\
	((_auth == NF_IPSEC_AUTH_ALG_MD5HMAC) ?			\
	  DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_96_MD5_128 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_SHA1HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_96_SHA_160 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_AESXCBC) ?			\
	  DPA_IPSEC_CIPHER_ALG_AES_CBC_AES_XCBC_MAC_96 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_SHA2_256_HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_256_128 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_SHA2_384_HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_384_192 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_SHA2_512_HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_512_256 :	\
	  IPSEC_ENC_ATH_ALG_INVALID_SELECTION)

/* Macro for encryption algorithm IPSEC_ENC_ALG_AES_CTR */
#define IPSEC_ALG_ENC_AES_CTR(_auth)				\
	((_auth == NF_IPSEC_AUTH_ALG_MD5HMAC) ?			\
	  DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_MD5_128 :		\
	  (_auth == NF_IPSEC_AUTH_ALG_SHA1HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_96_SHA_160 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_AESXCBC) ?			\
	  DPA_IPSEC_CIPHER_ALG_AES_CTR_AES_XCBC_MAC_96 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_SHA2_256_HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_256_128 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_SHA2_384_HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_384_192 :	\
	 (_auth == NF_IPSEC_AUTH_ALG_SHA2_512_HMAC) ?		\
	  DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_512_256 :	\
	  IPSEC_ENC_ATH_ALG_INVALID_SELECTION)

#define IPSEC_ALGS(_enc, _auth)						    \
	((_enc == NF_IPSEC_ENC_ALG_NULL) ? IPSEC_ALG_ENC_NULL(_auth) :      \
	 (_enc == NF_IPSEC_ENC_ALG_DES_CBC) ?				    \
	  IPSEC_ENC_ATH_ALG_INVALID_SELECTION :				    \
	 (_enc == NF_IPSEC_ENC_ALG_3DES_CBC) ? IPSEC_ALG_ENC_3DES_CBC(_auth) : \
	 (_enc == NF_IPSEC_ENC_ALG_AES_CBC) ? IPSEC_ALG_ENC_AES_CBC(_auth) :\
	 (_enc == NF_IPSEC_ENC_ALG_AES_CTR) ? IPSEC_ALG_ENC_AES_CTR(_auth) :\
	  IPSEC_ENC_ATH_ALG_INVALID_SELECTION)


#define GET_POL_TABLE_IDX(_proto, _ip_ver)				\
	((_proto == IPPROTO_TCP)  ? DPA_IPSEC_PROTO_TCP_##_ip_ver :	\
	 (_proto == IPPROTO_UDP)  ? DPA_IPSEC_PROTO_UDP_##_ip_ver :	\
	((_proto == IPPROTO_ICMP) ||					\
	 (_proto == IPPROTO_ICMPV6)) ? DPA_IPSEC_PROTO_ICMP_##_ip_ver :	\
	 (_proto == IPPROTO_SCTP) ? DPA_IPSEC_PROTO_SCTP_##_ip_ver :	\
	  DPA_IPSEC_PROTO_ANY_##_ip_ver)

#define TABLE_KEY_SIZE(_tbl_params)					\
	((_tbl_params.type == DPA_CLS_TBL_HASH) ?			\
		tbl_params.hash_params.key_size :			\
		(_tbl_params.type == DPA_CLS_TBL_EXACT_MATCH) ?		\
			 tbl_params.exact_match_params.key_size : 0)

#define IP_DONTFRAG	0x4000      /* Flag: "Don't Fragment"       */
#define IP6_TC_OFF	20	    /* Traffic Class in IPv6 header */
#define BITS_IN_BYTE	8	    /* Number of bits in a byte	    */
#define MAX_VAL_16BITS  0xFFFF      /* Maximum value on 16 bits     */
#define MAX_VAL_32BITS	0x7FFFFFFF  /* Maximum value on 32 bits     */

#define PRIO_LOW_VAL	0
#define PRIO_HIGH_VAL	MAX_VAL_32BITS

#define DPA_IPSEC_PROTO_MASK	  false
#define DPA_IPSEC_L4_PROTO_MASK   0xFFFF
#define DPA_IPSEC_ICMP_PROTO_MASK 0xFF

#define IP_ADDR_LEN_T_IPv4	4

#define IP_ADDR(_nf_ipaddr, _dpa_ipaddr)				\
	if (_nf_ipaddr.version == NF_IPV4)				\
		_dpa_ipaddr.addr.ipv4.word = _nf_ipaddr.ipv4;		\
	else								\
		memcpy(_dpa_ipaddr.addr.ipv6.word, _nf_ipaddr.ipv6.w_addr, 4);

#define IP_ADDR_LEN(_version)						\
	((_version == NF_IPV4) ?					\
	 (IP_ADDR_LEN_T_IPv4) : (NF_IPV6_ADDRU8_LEN))

#define POL_STATE_INVALID  0x01 /* Policy is invalid */
#define POL_STATE_INIT	   0x02 /* Policy is initialized */
#define POL_STATE_REF	   0x04 /* Policy is referenced by an SA selector */
#define POL_STATE_INIT_REF (POL_STATE_INIT | POL_STATE_REF) /* Policy is initialized and referenced */

struct nf_ipsec_data {
	void *sa_mng[NF_IPSEC_DIR_NUM][NF_IPSEC_MAX_SAS]; /* Array of pointers of SA internal structures */
	void *pol_mng[NF_IPSEC_DIR_NUM][NF_IPSEC_MAX_POLS]; /* Array of pointers of policy internal structures */
	uint8_t pol_state[NF_IPSEC_DIR_NUM][NF_IPSEC_MAX_POLS]; /* Array of policy states */
	struct mem_cache_t *sa_nodes; /* List of free SA internal data */
	struct mem_cache_t *pol_nodes; /* List of free policy internal data */
	struct mem_cache_t *link_nodes[NF_IPSEC_MAX_POOL_LINK_NODES]; /* List of free link node */
	struct list_head sa_list[NF_IPSEC_DIR_NUM]; /* List of SAs, ordered by creation time */
	struct list_head pol_list[NF_IPSEC_DIR_NUM]; /* List of policies, ordered by priority */
	struct nf_ipsec_pol_data *def_pol; /* First policy created with 'no position' flag*/
	void *frag_nodes[NF_IPSEC_MAX_SAS]; /* Array of fragmentation nodes provided by application */
	uint16_t n_frag_nodes; /* Number of fragmentation nodes provided by application */
	bool used_frags[NF_IPSEC_MAX_SAS]; /* Fragmentation nodes 'in-use' */
	struct qman_fq local_fq; /* Queue handling object for manual enqueues */
	struct bman_pool *bm_pool; /* Buffer pool object for manual enqueues */
};

struct nf_ipsec_sa_data {
	int sa_id; /* SA ID returned by DPA IPSec */
	int dir; /* SA direction: inbound or outbound */
	uint32_t spi; /* SPI Value */
	struct nf_ip_addr dest_ip; /* Destination Gateway Address */
	uint8_t protocol; /* Security Protocol (ESP/AH) */
	struct list_head pol_list; /* List of policies linked with this SA */
	struct list_head node; /* Member of list of SAs, ordered by creation time */
	struct nf_ipsec_sa  sa_params; /* Copy of SA parameters */
	uint32_t n_sels; /* Number of selectors */
	struct nf_ipsec_sa_selector sels[NF_IPSEC_MAX_SEL]; /* Array of selectors */
	uint8_t auth_key[NF_IPSEC_MAX_CRYPTO_KEY_BYTES]; /* Authentication key */
	uint8_t cipher_key[NF_IPSEC_MAX_CRYPTO_KEY_BYTES]; /* Encryption/decryption key */
	uint8_t comb_key[NF_IPSEC_MAX_CRYPTO_KEY_BYTES]; /* Combined mode key */
	uint8_t iv[NF_IPSEC_MAX_CRYPTO_KEY_BYTES]; /* Initialization vector */
	int frag_hmd; /* Fragmentation header manipulation descriptor */
	int frag_node_idx; /* Index in the fragmentation nodes array */
};

struct nf_ipsec_pol_data {
	struct nf_ipsec_data *nf_ipsec_data; /* Pointer to NF IPSec data structure */
	int dir; /* Direction: Inbound or Outbound */
	uint32_t policy_id; /* Policy ID provided by NF API */
	struct list_head sa_list; /* List of SAs linked with this policy */
	struct list_head node; /* Member of list of policies, ordered by priority */
	int prio; /* Priority occupied by this policy */
	int entry_ids[NF_IPSEC_MAX_SEL]; /* Array of entry ids for outbound policy table */
	struct nf_ipsec_policy spd_params; /* Copy of NF policy params */
	uint32_t n_sels; /* Number of selectors */
	struct nf_ipsec_selector sels[NF_IPSEC_MAX_SEL]; /* Array of selectors */
	uint8_t n_dscp_ranges; /* Number of DSCP ranges */
	struct nf_ipsec_policy_rule_dscprange dscp_ranges[NF_IPSEC_MAX_DSCP]; /* Array of DSCP ranges */
};

struct nf_ipsec_sa_pol_link {
	int pool_id; /* ID of link nodes pool that this node belongs to  */
	int sa_id; /* SA ID provided by DPA IPSec */
	int policy_id; /* Policy ID provided by NF API */
	struct list_head sa_node; /* Node used to link to policy SA list */
	struct list_head pol_node; /* Node used to link to SA policy list */
};

struct nf_packet {
	uint32_t length; /* Length of the packet, in bytes */
	void *data; /* Actual data of the packet */
};

static inline void list_add_after(struct list_head *p, struct list_head *l)
{
	p->prev = l;
	p->next = l->next;
	l->next->prev = p;
	l->next = p;
}

static inline void list_add_before(struct list_head *p, struct list_head *l)
{
	p->next = l;
	p->prev = l->prev;
	l->prev->next = p;
	l->prev = p;
}
#endif	/* __IPSEC_H */

