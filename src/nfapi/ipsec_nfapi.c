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
 * IPSec NF API user space library implementation
 */

#include <error.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>

#include <compat.h>
#include <fsl_qman.h>
#include <fsl_bman.h>
#include <dma_mem.h>
#include <of.h>
#include <mem_cache.h>

#include "fsl_dpa_ipsec.h"

#include "common_nfapi.h"
#include "ipsec_nfapi.h"
#include "ipsec.h"
#include "init_nfapi.h"
#include "utils_nfapi.h"


/* Global nf_ipsec_data component */

extern struct nf_ipsec_data * gbl_nf_ipsec_data;
static int add_dpa_ipsec_in_pol(struct nf_ipsec_pol_data *pol,
				int idx, int sa_id);
static int rm_dpa_ipsec_in_pol(struct nf_ipsec_pol_data *pol,
			       int idx, int sa_id);

static int add_dpa_ipsec_out_pol(struct nf_ipsec_pol_data *pol,
				 int idx, struct nf_ipsec_sa_data *sa);
static int rm_dpa_ipsec_out_pol(struct nf_ipsec_pol_data *pol,
				int idx, struct nf_ipsec_sa_data *sa);

static int insert_out_pol_ipsec(struct nf_ipsec_pol_data *pol, int idx);
static int delete_out_pol(struct nf_ipsec_pol_data *pol, int idx);

static int release_sa_frag_hmd(struct nf_ipsec_sa_data *sa,
			       struct nf_ipsec_data *nf_ipsec_data);


static int check_sa_params(const struct nf_ipsec_sa_add_inargs *in)
{
	struct nf_ipsec_sa *nf_sa = in->sa_params;
	struct nf_ipsec_tunnel_end_addr *te_addr = &nf_sa->te_addr;
	uint32_t max_bits = NF_IPSEC_MAX_CRYPTO_KEY_BYTES * BITS_IN_BYTE;
	int i;

	/* Check SA parameters */
	if (in->dir != NF_IPSEC_INBOUND && in->dir != NF_IPSEC_OUTBOUND) {
		error(0, EINVAL, "Invalid SA direction %d. It should be %d or %d",
				in->dir, NF_IPSEC_INBOUND, NF_IPSEC_OUTBOUND);
		return -EINVAL;
	}

	if (!nf_sa->crypto_params.auth_key) {
		error(0, EINVAL, "Invalid authentication key");
		return -EINVAL;
	}

	if (nf_sa->crypto_params.auth_key_len_bits < 8 ||
	    nf_sa->crypto_params.auth_key_len_bits > max_bits) {
		error(0, EINVAL, "Authentication key bits (%d) must be in range (8 - %d)",
			nf_sa->crypto_params.auth_key_len_bits, max_bits);
		return -EINVAL;
	}

	if (!nf_sa->crypto_params.cipher_key) {
		error(0, EINVAL, "Invalid ciphey key");
		return -EINVAL;
	}

	if (nf_sa->crypto_params.cipher_key_len_bits < 8 ||
	    nf_sa->crypto_params.cipher_key_len_bits > max_bits) {
		error(0, EINVAL, "Cipher key bits (%d) must be in range (8 - %d)",
			nf_sa->crypto_params.cipher_key_len_bits, max_bits);
		return -EINVAL;
	}

	if (in->dir == NF_IPSEC_OUTBOUND) {
		if (nf_sa->outb.mtu > MAX_VAL_16BITS) {
			error(0, EINVAL, "Value of MTU bigger than %d is not supported",
					MAX_VAL_16BITS);
			return -EINVAL;
		}

		if (nf_sa->outb.iv && (nf_sa->outb.iv_len_bits > max_bits ||
				!nf_sa->outb.iv_len_bits)) {
			error(0, EINVAL, "Initialization vector bits (%d) must be in range (8 - %d)",
					nf_sa->outb.iv_len_bits, max_bits);
			return -EINVAL;
		}
	}

	if (te_addr->src_ip.version != NF_IPV4 &&
	    te_addr->src_ip.version != NF_IPV6) {
		error(0, EINVAL, "Invalid IP version for tunnel source address %d. It should be %d or %d",
			te_addr->src_ip.version, NF_IPV4, NF_IPV6);
		return -EINVAL;
	}

	if (te_addr->dest_ip.version != NF_IPV4 &&
	    te_addr->dest_ip.version != NF_IPV6) {
		error(0, EINVAL, "Invalid IP version for tunnel destination address %d. It should be %d or %d",
			te_addr->dest_ip.version, NF_IPV4, NF_IPV6);
		return -EINVAL;
	}

	if (nf_sa->n_selectors > NF_IPSEC_MAX_SEL) {
		error(0, EINVAL, "Exceeded maximum number of selectors %d",
			NF_IPSEC_MAX_SEL);
		return -EINVAL;
	}

	if (nf_sa->n_selectors > 0 && !nf_sa->selectors) {
		error(0, EINVAL, "Pointer to array of selectors cannot be NULL");
		return -EINVAL;
	}

	for (i = 0; i < nf_sa->n_selectors; i++) {
		struct nf_ipsec_selector *sel = &nf_sa->selectors[i].selector;

		if (sel->version == NF_IPV4) {
			if (sel->src_ip4.type != NF_IPA_SUBNET) {
				error(0, EINVAL, "Only address type SUBNET is supported for selector source IP");
				return -EINVAL;
			}
			if (sel->dest_ip4.type != NF_IPA_SUBNET) {
				error(0, EINVAL, "Only address type SUBNET is supported for selector destination IP");
				return -EINVAL;
			}
		} else if (sel->version == NF_IPV6) {
			if (sel->src_ip6.type != NF_IPA_SUBNET) {
				error(0, EINVAL, "Only address type SUBNET is supported for selector source IP");
				return -EINVAL;
			}
			if (sel->dest_ip6.type != NF_IPA_SUBNET) {
				error(0, EINVAL, "Only address type SUBNET is supported for selector destination IP");
				return -EINVAL;
			}
		} else {
			error(0, EINVAL, "Invalid selector IP version %d. It should be %d or %d",
				sel->version, NF_IPV4, NF_IPV6);
			return -EINVAL;
		}

		if (sel->protocol != NF_IPSEC_SEL_PROTOCOL_ANY &&
		    sel->protocol != IPPROTO_ICMP &&
		    sel->protocol != IPPROTO_ICMPV6 &&
		    (sel->src_port.type != NF_L4_PORT_SINGLE ||
		     sel->dest_port.type != NF_L4_PORT_SINGLE)) {
			error(0, EINVAL, "Only port type SINGLE is supported");
			return -EINVAL;
		}
	}

	return 0;
}

static int check_policy_params(const struct nf_ipsec_spd_add_inargs *in)
{
	const struct nf_ipsec_policy *spd_params = &in->spd_params;
	int i;

	/* Check SA parameters */
	if (in->dir != NF_IPSEC_INBOUND && in->dir != NF_IPSEC_OUTBOUND) {
		error(0, EINVAL, "Invalid policy direction %d. It should be %d or %d",
				in->dir, NF_IPSEC_INBOUND, NF_IPSEC_OUTBOUND);
		return -EINVAL;
	}

	if ((in->dir == NF_IPSEC_INBOUND) &&
	    (spd_params->action != NF_IPSEC_POLICY_ACTION_IPSEC)) {
		error(0, EINVAL, "For INBOUND direction only policy action IPSEC is supported");
		return -EINVAL;
	}

	if (spd_params->status == NF_IPSEC_POLICY_STATUS_DISABLE) {
		error(0, EINVAL, "Policy in disable mode is not currently supported");
		return -EINVAL;
	}

	if (spd_params->n_selectors > NF_IPSEC_MAX_SEL) {
		error(0, EINVAL, "Exceeded maximum number of selectors %d",
			NF_IPSEC_MAX_SEL);
		return -EINVAL;
	}

	if (spd_params->n_selectors > 0 && !spd_params->selectors) {
		error(0, EINVAL, "Number of selectors(%d) bigger than 0, pointer to array of selectors NULL",
				spd_params->n_selectors);
		return -EINVAL;
	}

	if (spd_params->n_dscp_ranges > NF_IPSEC_MAX_DSCP) {
		error(0, EINVAL, "Exceeded maximum number of DSCP ranges %d",
			NF_IPSEC_MAX_DSCP);
		return -EINVAL;
	}

	if (spd_params->n_dscp_ranges > 0 && !spd_params->dscp_ranges) {
		error(0, EINVAL, "Number of dscp ranges(%d) bigger than 0, pointer to array of dscp ranges NULL",
			spd_params->n_dscp_ranges);
		return -EINVAL;
	}

	if (spd_params->fragments_opts) {
		error(0, EINVAL, "Fragmentation options (%d) is not currently supported",
			spd_params->fragments_opts);
		return -EINVAL;
	}

	if (spd_params->n_selectors > NF_IPSEC_MAX_SEL) {
		error(0, EINVAL, "Exceeded maximum number of selectors %d",
			NF_IPSEC_MAX_SEL);
		return -EINVAL;
	}

	if (spd_params->n_selectors > 0 && !spd_params->selectors) {
		error(0, EINVAL, "Number of selectors(%d) bigger than 0, pointer to array of selectors NULL",
				spd_params->n_selectors);
		return -EINVAL;
	}

	for (i = 0; i < spd_params->n_selectors; i++) {
		struct nf_ipsec_selector *sel = &spd_params->selectors[i];

		if (sel->version == NF_IPV4) {
			if (sel->src_ip4.type != NF_IPA_SUBNET) {
				error(0, EINVAL, "Only address type SUBNET is supported for selector source IP");
				return -EINVAL;
			}
			if (sel->dest_ip4.type != NF_IPA_SUBNET) {
				error(0, EINVAL, "Only address type SUBNET is supported for selector destination IP");
				return -EINVAL;
			}
		} else if (sel->version == NF_IPV6) {
			if (sel->src_ip6.type != NF_IPA_SUBNET) {
				error(0, EINVAL, "Only address type SUBNET is supported for selector source IP");
				return -EINVAL;
			}
			if (sel->dest_ip6.type != NF_IPA_SUBNET) {
				error(0, EINVAL, "Only address type SUBNET is supported for selector destination IP");
				return -EINVAL;
			}

		} else {
			error(0, EINVAL, "Invalid selector IP version %d. It should be %d or %d",
				sel->version, NF_IPV4, NF_IPV6);
			return -EINVAL;
		}

		if (sel->protocol != NF_IPSEC_SEL_PROTOCOL_ANY &&
		   (sel->src_port.type != NF_L4_PORT_SINGLE ||
		    sel->dest_port.type != NF_L4_PORT_SINGLE)) {
			error(0, EINVAL, "Only port type SINGLE is supported");
			return -EINVAL;
		}
	}
	return 0;
}

static void *create_sa_node(struct nf_ipsec_data *nf_ipsec_data,
			    const struct nf_ipsec_sa_add_inargs *in,
			    int sa_id)
{
	struct nf_ipsec_sa *nf_sa = in->sa_params;
	struct nf_ipsec_sa_data *sa = NULL;
	int dir;

	/* Create SA internal structure and store it */
	sa = mem_cache_alloc(nf_ipsec_data->sa_nodes);
	if (!sa) {
		error(0, ENOMEM, "Could not allocate memory for SA control block");
		return NULL;
	}
	memset(sa, 0, sizeof(*sa));

	/* Store SA parameters */
	sa->sa_id = sa_id;
	sa->spi = nf_sa->spi;
	sa->protocol = nf_sa->protocol;
	memcpy(&sa->dest_ip, &nf_sa->te_addr.dest_ip, sizeof(sa->dest_ip));
	sa->dir = (in->dir == NF_IPSEC_INBOUND) ?
			NF_IPSEC_DIR_INBOUND : NF_IPSEC_DIR_OUTBOUND;

	/* Store user provided parameters */
	memset(&sa->sa_params, 0, sizeof(sa->sa_params));
	memcpy(&sa->sa_params, nf_sa, sizeof(sa->sa_params));

	/* Store array of SA selectors */
	if (nf_sa->selectors) {
		memcpy(&sa->sels, nf_sa->selectors,
		      nf_sa->n_selectors * sizeof(struct nf_ipsec_sa_selector));
	}
	sa->n_sels = nf_sa->n_selectors;

	/* Store crypto keys */
	memcpy(&sa->auth_key, nf_sa->crypto_params.auth_key,
	       nf_sa->crypto_params.auth_key_len_bits/BITS_IN_BYTE);
	memcpy(&sa->cipher_key, nf_sa->crypto_params.cipher_key,
	       nf_sa->crypto_params.cipher_key_len_bits/BITS_IN_BYTE);

	if (nf_sa->crypto_params.comb_key) {
		memcpy(&sa->comb_key, nf_sa->crypto_params.comb_key,
		       nf_sa->crypto_params.comb_key_len_bits/BITS_IN_BYTE);
	}

	if (in->dir == NF_IPSEC_OUTBOUND) {
		memcpy(&sa->iv, nf_sa->outb.iv,
		       nf_sa->outb.iv_len_bits/BITS_IN_BYTE);
	}

	/* Obtain direction */
	dir = (in->dir == NF_IPSEC_INBOUND) ?
			NF_IPSEC_DIR_INBOUND : NF_IPSEC_DIR_OUTBOUND;

	/* Initialize list of policies that are referenced by this SA */
	INIT_LIST_HEAD(&sa->pol_list);
	/* Add SA node at the end of the list */
	list_add_tail(&sa->node, &nf_ipsec_data->sa_list[dir]);
	/* Store SA data pointer */
	nf_ipsec_data->sa_mng[dir][sa->sa_id] = sa;
	/* Set fragmentation descriptor to invalid value */
	sa->frag_hmd = DPA_OFFLD_DESC_NONE;
	return sa;
}

static int remove_sa_node(struct nf_ipsec_data *nf_ipsec_data,
			  struct nf_ipsec_sa_data *sa)
{
	int ret = 0;

	/* First try and remove SA from DPA IPSec */
	ret = dpa_ipsec_remove_sa(sa->sa_id);
	if (ret < 0) {
		error(0, -ret, "Unable to remove DPA IPSec SA");
		return ret;
	}

	if (sa->frag_hmd != DPA_OFFLD_DESC_NONE) {
		ret = release_sa_frag_hmd(sa, nf_ipsec_data);
		if (ret < 0)
			return ret;
	}
	/* Set SA pointer to NULL */
	nf_ipsec_data->sa_mng[sa->dir][sa->sa_id] = NULL;
	list_del(&sa->node);
	mem_cache_free(nf_ipsec_data->sa_nodes, sa);
	return 0;
}

static void *create_pol_node(struct nf_ipsec_data *nf_ipsec_data,
			     int dir, int policy_id)
{
	struct nf_ipsec_pol_data *policy = NULL;

	/* Get memory for policy control block */
	policy = mem_cache_alloc(nf_ipsec_data->pol_nodes);
	if (!policy) {
		error(0, ENOMEM, "Could not allocate memory for policy control block");
		return NULL;
	}
	memset(policy, 0, sizeof(*policy));

	/* Save policy id, pointer to nf_ipsec_data and policy direction */
	policy->policy_id = policy_id;
	policy->nf_ipsec_data = nf_ipsec_data;
	policy->dir = dir;

	/* Initialize list of SAs that reference this policy */
	INIT_LIST_HEAD(&policy->sa_list);

	/* Save policy control block pointer */
	nf_ipsec_data->pol_mng[dir][policy_id] = policy;

	return policy;
}

static void remove_pol_node(struct nf_ipsec_pol_data *pol)
{
	struct nf_ipsec_data *nf_ipsec_data = pol->nf_ipsec_data;

	/* Release policy related resources */
	mem_cache_free(nf_ipsec_data->pol_nodes, pol);

	/* Set policy pointer to NULL */
	nf_ipsec_data->pol_mng[pol->dir][pol->policy_id] = NULL;

	/* Set policy state to 'INVALID' */
	nf_ipsec_data->pol_state[pol->dir][pol->policy_id] = POL_STATE_INVALID;
}

static void *create_link_node(struct nf_ipsec_sa_data *sa,
			      struct nf_ipsec_pol_data *pol)
{
	struct nf_ipsec_data *nf_ipsec_data = pol->nf_ipsec_data;
	struct nf_ipsec_sa_pol_link *link = NULL;
	uint32_t i;

	for (i = 0; i < NF_IPSEC_MAX_POOL_LINK_NODES; i++) {
		/* Try to allocate memory for link node between SA and policy */
		link = mem_cache_alloc(nf_ipsec_data->link_nodes[i]);
		if (link)
			break;
	}
	if (!link) {
		error(0, ENOMEM, "Could not allocate memory for link node");
		return NULL;
	}
	memset(link, 0, sizeof(*link));

	/* Save link nodes pool, SA and policy ids */
	link->pool_id = i;
	link->sa_id = sa->sa_id;
	link->policy_id = pol->policy_id;

	/* Link node both to SA and to policy */
	list_add_tail(&link->pol_node, &sa->pol_list);
	list_add_tail(&link->sa_node, &pol->sa_list);

	return link;
}

static void remove_link_node(struct nf_ipsec_data *nf_ipsec_data,
			     struct nf_ipsec_sa_pol_link *link)
{
	/* Remove this policy from SA list of policies*/
	list_del(&link->pol_node);

	/* Remove this SA from policy list of SAs */
	list_del(&link->sa_node);

	/* Nobody references it, so remove link node */
	mem_cache_free(nf_ipsec_data->link_nodes[link->pool_id], link);
}

static inline int addr_match_ipv4(struct nf_ipv4_addr_info *a1,
				  struct nf_ipv4_addr_info *a2)
{
	if (a1->type != a2->type)
		return false;
	if (a1->type != NF_IPA_SUBNET) {
		error(0, EINVAL, "Only addres type SUBNET is supported");
		return false;
	}
	if (a1->subnet.addr != a2->subnet.addr)
		return false;
	if (a1->subnet.prefix_len != a2->subnet.prefix_len)
		return false;

	return true;
}

static inline int addr_match_ipv6(struct nf_ipv6_addr_info *a1,
				  struct nf_ipv6_addr_info *a2)
{
	if (a1->type != a2->type)
		return false;
	if (a1->type != NF_IPA_SUBNET) {
		error(0, EINVAL, "Only addres type SUBNET is supported");
		return false;
	}
	if (memcmp(&a1->subnet.addr.b_addr, &a2->subnet.addr.b_addr,
				sizeof(a1->subnet.addr.b_addr)))
		return false;
	if (a1->subnet.prefix_len != a2->subnet.prefix_len)
		return false;

	return true;
}

static inline int port_match(struct nf_l4_port *p1,
			     struct nf_l4_port *p2)
{
	if (p1->type != p2->type)
		return false;
	if (p1->type != NF_L4_PORT_SINGLE) {
		error(0, EINVAL, "Only port type SINGLE is supported");
		return false;
	}
	if (p1->single.port != p2->single.port)
		return false;

	return true;
}

static bool selector_match(struct nf_ipsec_selector *psel,
			   struct nf_ipsec_selector *sel)
{
	if (sel->version != psel->version ||
	    sel->protocol != psel->protocol)
		return false;

	switch(sel->version) {
	case NF_IPV4:
		if (!addr_match_ipv4(&sel->src_ip4, &psel->src_ip4))
			return false;
		if (!addr_match_ipv4(&sel->dest_ip4, &psel->dest_ip4))
			return false;
		break;
	case NF_IPV6:
		if (!addr_match_ipv6(&sel->src_ip6, &psel->src_ip6))
			return false;
		if (!addr_match_ipv6(&sel->dest_ip6, &psel->dest_ip6))
			return false;
		break;
	default:
		error(0, EINVAL, "Invalid IP version");
		return false;
	}

	if (!port_match(&sel->src_port, &psel->src_port))
		return false;
	if (!port_match(&sel->dest_port, &psel->dest_port))
		return false;

	/* SA selector does not match any policy selector */
	return true;
}

static int find_pol_sel_idx(struct nf_ipsec_pol_data *pol,
			    struct nf_ipsec_selector *sel)
{
	int i;

	for (i = 0; i < pol->n_sels; i++) {
		if (!selector_match(sel, &pol->sels[i]))
			continue;
		return i;
	}
	/* SA selector does not match any policy selector */
	return -1;
}

static void *find_sa_node(struct nf_ipsec_data *nf_ipsec_data,
			  enum nf_ipsec_direction direction,
			  uint32_t spi,
			  struct nf_ip_addr dest_ip, uint8_t protocol)
{
	struct nf_ipsec_sa_data *sa = NULL;
	int dir, i;

	dir = (direction == NF_IPSEC_INBOUND) ?
			NF_IPSEC_DIR_INBOUND : NF_IPSEC_DIR_OUTBOUND;

	for (i = 0; i < NF_IPSEC_MAX_SAS; i++) {
		if (!nf_ipsec_data->sa_mng[dir][i])
			continue;

		sa = nf_ipsec_data->sa_mng[dir][i];
		if (sa->spi == spi &&
		    sa->protocol == protocol &&
		    memcmp(&sa->dest_ip, &dest_ip, sizeof(sa->dest_ip)) == 0) {
			return sa;
		}
	}
	return NULL;
}

static int get_out_pol_table(struct nf_ipsec_data *nf_ipsec_data,
			     struct nf_ipsec_selector *sel)
{
	struct dpa_ipsec_pre_sec_out_params *pre_sec_out = NULL;
	int td_idx = 0, td = 0;

	if (unlikely(!gbl_init))
		return -EBADF;

	pre_sec_out = &gbl_init->ipsec.ipsec_params.pre_sec_out_params;
	if (sel->version == NF_IPV4)
		td_idx = GET_POL_TABLE_IDX(sel->protocol, IPV4);
	else
		td_idx = GET_POL_TABLE_IDX(sel->protocol, IPV6);

	td = pre_sec_out->table[td_idx].dpa_cls_td;
	/*
	 * check if a valid desc for a proto specific table or an ANY table was
	 * provided
	 */
	if (td == DPA_OFFLD_DESC_NONE) {
		error(0, EBADF, "No suitable table found for this policy type!");
		return -EBADF;
	}
	return td;
}

static int fill_table_key(int td, struct nf_ipsec_selector *sel,
			  uint8_t key_fields,
			  uint8_t *key, uint8_t *mask, uint8_t *key_len)
{
	struct dpa_cls_tbl_params tbl_params;
	uint8_t off = 0, field_mask = 0, tbl_key_size = 0;
	int err = 0, i;

	/* Fill in the key components */
	for (i = 0; i < DPA_IPSEC_MAX_KEY_FIELDS; i++) {
		field_mask = (uint8_t) (1 << i);
		switch (key_fields & field_mask) {
		case DPA_IPSEC_KEY_FIELD_SIP:
			/* Copy IP source address and set mask */
			if (sel->version == NF_IPV4) {
				if (sel->src_ip4.type != NF_IPA_SUBNET) {
					error(0, EINVAL, "Only selector address type SUBNET is supported");
					return -EINVAL;
				}
				memcpy(key + off, &sel->src_ip4.subnet.addr,
						IP_ADDR_LEN_T_IPv4);
				set_ip_addr_mask(mask + off,
						sel->src_ip4.subnet.prefix_len);
			} else if (sel->version == NF_IPV6) {
				if (sel->src_ip6.type != NF_IPA_SUBNET) {
					error(0, EINVAL, "Only selector address type SUBNET is supported");
					return -EINVAL;
				}
				memcpy(key + off, &sel->src_ip6.subnet.addr,
						NF_IPV6_ADDRU32_LEN);
				set_ip_addr_mask(mask + off,
						sel->src_ip6.subnet.prefix_len);
			} else {
				error(0, EINVAL, "Selector version is not IPv4 or IPv6");
				return -EINVAL;
			}
			off += IP_ADDR_LEN(sel->version);
			break;

		case DPA_IPSEC_KEY_FIELD_DIP:
			/* Copy IP destination address and set mask */
			if (sel->version == NF_IPV4) {
				if (sel->dest_ip4.type != NF_IPA_SUBNET) {
					error(0, EINVAL, "Only selector address type SUBNET is supported");
					return -EINVAL;
				}
				memcpy(key + off, &sel->dest_ip4.subnet.addr,
						IP_ADDR_LEN_T_IPv4);
				set_ip_addr_mask(mask + off,
						sel->dest_ip4.subnet.prefix_len);
			} else if (sel->version == NF_IPV6) {
				if (sel->dest_ip6.type != NF_IPA_SUBNET) {
					error(0, EINVAL, "Only selector address type SUBNET is supported");
					return -EINVAL;
				}
				memcpy(key + off, &sel->dest_ip6.subnet.addr,
						NF_IPV6_ADDRU32_LEN);
				set_ip_addr_mask(mask + off,
						sel->dest_ip6.subnet.prefix_len);
			} else {
				error(0, EINVAL, "Selector version is not IPv4 or IPv6");
				return -EINVAL;
			}
			off += IP_ADDR_LEN(sel->version);
			break;

		case DPA_IPSEC_KEY_FIELD_PROTO:
			key[off] = sel->protocol;
			mask[off] = 0xFF;
			off += IP_PROTO_FIELD_LEN;
			break;

		/* case DPA_IPSEC_KEY_FIELD_ICMP_TYPE: */
		case DPA_IPSEC_KEY_FIELD_SPORT:
			if ((sel->protocol == IPPROTO_ICMP) ||
			   (sel->protocol == IPPROTO_ICMPV6)) {
				key[off] = (uint8_t)sel->src_port.single.port;
				mask[off] = 0xFF;
				off += ICMP_HDR_FIELD_LEN;
			} else {
				memcpy(key + off, (uint8_t *)
				       &(sel->src_port.single.port),
				       PORT_FIELD_LEN);
				mask[off] = 0xFF;
				mask[off+1] = 0xFF;
				off += PORT_FIELD_LEN;
			}
			break;

		/* case DPA_IPSEC_KEY_FIELD_ICMP_CODE: */
		case DPA_IPSEC_KEY_FIELD_DPORT:
			if ((sel->protocol == IPPROTO_ICMP) ||
			   (sel->protocol == IPPROTO_ICMPV6)) {
				key[off] = (uint8_t)sel->dest_port.single.port;
				mask[off] = 0xFF;
				off += ICMP_HDR_FIELD_LEN;
			} else {
				memcpy(key + off, (uint8_t *)
				       &(sel->dest_port.single.port),
				       PORT_FIELD_LEN);
				mask[off] = 0xFF;
				mask[off+1] = 0xFF;
				off += PORT_FIELD_LEN;
			}
			break;

		case DPA_IPSEC_KEY_FIELD_DSCP:
			if (sel->version == NF_IPV4) {
				memset(key + off, 0, DSCP_FIELD_LEN_IPv4);
				memset(mask + off, 0, DSCP_FIELD_LEN_IPv4);
				off += DSCP_FIELD_LEN_IPv4;
			} else if (sel->version == NF_IPV6) {
				memset(key + off, 0, DSCP_FIELD_LEN_IPv6);
				memset(mask + off, 0, DSCP_FIELD_LEN_IPv6);
				off += DSCP_FIELD_LEN_IPv6;
			}
			break;
		}
	}

	/*
	 * Add padding to compensate difference in size between table maximum
	 * key size and computed key size.
	 */

	/* get table params (including maximum key size) */
	err = dpa_classif_table_get_params(td, &tbl_params);
	if (err < 0) {
		error(0, EINVAL, "Could not retrieve table maximum key size!");
		return -EINVAL;
	}
	tbl_key_size = TABLE_KEY_SIZE(tbl_params);

	if (tbl_key_size < off) {
		error(0, EINVAL, "Policy key is greater than maximum table key size");
		return -EINVAL;
	}

	if (tbl_key_size > off) {
		for (i = 0; i < tbl_key_size - off; i++) {
			*(key + off + i) = DPA_IPSEC_DEF_PAD_VAL;
			/* ignore padding during classification (mask it) */
			*(mask + off + i) = 0x00;
		}
		off = tbl_key_size;
	}

	/* Store key length */
	*key_len = off;

	return 0;
}

static int create_out_tbl_key(struct nf_ipsec_data *nf_ipsec_data,
			      struct nf_ipsec_selector *sel, int *table,
			      struct dpa_offload_lookup_key *tbl_key)
{
	struct dpa_ipsec_pre_sec_out_params *pre_sec_out;
	uint8_t key_fields, key_len;
	int td_idx = 0, ret = 0;

	if (unlikely(!gbl_init)) {
		error(0, EBADF, "NFAPI not initialized");
		return -EBADF;
	}

	pre_sec_out = &gbl_init->ipsec.ipsec_params.pre_sec_out_params;
	if (sel->version == NF_IPV4)
		td_idx = GET_POL_TABLE_IDX(sel->protocol, IPV4);
	else
		td_idx = GET_POL_TABLE_IDX(sel->protocol, IPV6);

	*table = pre_sec_out->table[td_idx].dpa_cls_td;
	key_fields = pre_sec_out->table[td_idx].key_fields;

	/*
	 * check if a valid desc for a proto specific table or an ANY table was
	 * provided
	 */
	if (*table == DPA_OFFLD_DESC_NONE) {
		error(0, EBADF, "No suitable table found for this policy type!");
		return -EBADF;
	}

	/*
	 * Key may contain:
	 * IP SRC ADDR  - from Policy handle
	 * IP DST ADDR  - from Policy handle
	 * IP_PROTO     - from Policy handle
	 * SRC_PORT     - from Policy handle (for UDP & TCP & SCTP)
	 * DST_PORT     - from Policy handle (for UDP & TCP & SCTP)
	 * DSCP field   - from Policy handle
	 */
	ret = fill_table_key(*table, sel, key_fields,
			tbl_key->byte, tbl_key->mask, &key_len);
	if (ret)
		return ret;

	tbl_key->size = key_len;
	return 0;
}

static int create_frag_manip(struct nf_ipsec_sa_data *sa,
				 struct nf_ipsec_data *nf_ipsec_data)
{
	struct dpa_cls_hm_update_params hm;

	if (unlikely(!gbl_init))
		return -EBADF;

	/* Set fragmentation manip update parameters */
	memset(&hm, 0, sizeof(struct dpa_cls_hm_update_params));
	hm.op_flags = DPA_CLS_HM_UPDATE_NONE;
	hm.ip_frag_params.mtu = (uint16_t)sa->sa_params.outb.mtu;
	hm.ip_frag_params.scratch_bpid = gbl_init->ipsec.ipf_bpid;
	hm.ip_frag_params.df_action = DPA_CLS_HM_DF_ACTION_FRAG_ANYWAY;
	hm.fm_pcd = gbl_init->pcd_dev;

	return dpa_classif_set_update_hm(&hm,
			DPA_OFFLD_DESC_NONE, &sa->frag_hmd, true, NULL);
}

static int update_frag_manip(struct nf_ipsec_sa_data *sa,
			     struct nf_ipsec_data *nf_ipsec_data)
{
	struct dpa_cls_hm_update_params hm;
	struct dpa_cls_hm_update_resources hm_res;
	int i = 0, ret = 0;

	if (unlikely(!gbl_init))
		return -EBADF;

	/* Check to see if we still have a free hmd available */
	for (i = 0; i < nf_ipsec_data->n_frag_nodes; i++) {
		if (!nf_ipsec_data->used_frags[i])
			break;
	}
	if (i == nf_ipsec_data->n_frag_nodes) {
		error(0, EINVAL, "No more free fragmentation manipulation node");
		return -EINVAL;
	}

	/* Set fragmentation manip update parameters */
	memset(&hm, 0, sizeof(struct dpa_cls_hm_update_params));
	hm.op_flags = DPA_CLS_HM_UPDATE_NONE;
	hm.ip_frag_params.mtu = (uint16_t)sa->sa_params.outb.mtu;
	hm.ip_frag_params.scratch_bpid = gbl_init->ipsec.ipf_bpid;
	hm.ip_frag_params.df_action = DPA_CLS_HM_DF_ACTION_FRAG_ANYWAY;
	hm.fm_pcd = gbl_init->pcd_dev;

	/* Set fragmentation manip resources */
	memset(&hm_res, 0, sizeof(struct dpa_cls_hm_update_resources));
	hm_res.ip_frag_node = nf_ipsec_data->frag_nodes[i];

	ret = dpa_classif_set_update_hm(&hm,
			DPA_OFFLD_DESC_NONE, &sa->frag_hmd, false, &hm_res);
	if (!ret) {
		/* Fragmentation node is 'in-use' */
		nf_ipsec_data->used_frags[i] = true;
		sa->frag_node_idx = i;
	}
	return ret;
}

static int release_sa_frag_hmd(struct nf_ipsec_sa_data *sa,
			       struct nf_ipsec_data *nf_ipsec_data)
{
	int ret = 0;

	ret = dpa_classif_free_hm(sa->frag_hmd);
	if (ret < 0) {
		error(0, -ret, "Unable release header manipulation object %d", sa->frag_hmd);
		return ret;
	}
	nf_ipsec_data->used_frags[sa->frag_node_idx] = false;
	sa->frag_node_idx = DPA_OFFLD_DESC_NONE;
	return 0;
}

static int modify_out_sa_mtu(struct nf_ipsec_data *nf_ipsec_data,
			     struct nf_ipsec_sa_data *sa, uint32_t mtu)
{
	struct dpa_cls_hm_update_params hm_prm;
	int ret = 0;

	if (sa->dir != NF_IPSEC_DIR_OUTBOUND) {
		error(0, EINVAL, "Modify MTU is supported only on OUTBOUND SA");
		return -EINVAL;
	}

	if (mtu == 0 || mtu > MAX_VAL_16BITS) {
		error(0, EINVAL, "MTU value(%d) must be greater than 0 and less than %d",
			mtu, MAX_VAL_16BITS);
		return -EINVAL;
	}

	memset(&hm_prm, 0, sizeof(struct dpa_cls_hm_update_params));
	hm_prm.ip_frag_params.mtu = (uint16_t)mtu;

	ret = dpa_classif_modify_update_hm(sa->frag_hmd,
			&hm_prm, DPA_CLS_HM_UPDATE_MOD_IP_FRAG_MTU);
	if (ret < 0)
		return ret;

	/* Save new MTU value */
	sa->sa_params.outb.mtu = mtu;

	return 0;
}

static inline bool is_other_sel_link_to_policy(struct nf_ipsec_sa_data *sa,
					       uint32_t idx, uint32_t policy_id)
{
	uint32_t i;

	/* Search if other sel points to the same policy */
	for (i = 0; i < sa->n_sels; i++) {
		if (i != idx && sa->sels[i].policy_id == policy_id)
			return true;
	}
	return false;
}

static int set_dpa_ipsec_sa_crypto_params(struct nf_ipsec_sa_crypto_params *nf,
					 struct dpa_ipsec_sa_crypto_params *dpa)
{
	if (nf->auth_algo == NF_IPSEC_AUTH_ALG_NONE) {
		error(0, EINVAL, "Combined mode algorithms are not supported");
		return -EINVAL;
	}
	dpa->cipher_key = nf->cipher_key;
	dpa->cipher_key_len = nf->cipher_key_len_bits/BITS_IN_BYTE;
	dpa->auth_key = nf->auth_key;
	dpa->auth_key_len = nf->auth_key_len_bits/BITS_IN_BYTE;
	dpa->alg_suite = IPSEC_ALGS(nf->cipher_algo, nf->auth_algo);
	if (dpa->alg_suite == IPSEC_ENC_ATH_ALG_INVALID_SELECTION) {
		error(0, EINVAL, "Invalid combination of encryption(%d) and authentication(%d) algorithms",
			nf->cipher_algo, nf->auth_algo);
		return -EINVAL;
	}
	return 0;
}

static int add_dpa_ipsec_in_sa(nf_ns_id nsid, struct nf_ipsec_sa *nf_sa,
			       struct dpa_ipsec_sa_params *dpa_sa, int *sa_id)
{
	struct dpa_ipsec_sa_in_params *dpa_sa_in = &dpa_sa->sa_in_params;
	uint8_t arw_size = nf_sa->inb.anti_replay_window_size;

	/* Set SA params depending on flag selection */
	dpa_sa->use_ext_seq_num = (nf_sa->cmn_flags &
			NF_IPSEC_SA_USE_ESN) ? true : false;
	dpa_sa->sa_mode = (nf_sa->cmn_flags &
			NF_IPSEC_SA_ENCAP_TRANSPORT_MODE) ?
			DPA_IPSEC_SA_MODE_TRANSPORT : DPA_IPSEC_SA_MODE_TUNNEL;
	dpa_sa->hdr_upd_flags |= (nf_sa->inb.flags &
			NF_IPSEC_INB_SA_PROPOGATE_ECN) ?
			DPA_IPSEC_HDR_COPY_ECN : 0;
	dpa_sa->hdr_upd_flags |= DPA_IPSEC_HDR_DEC_TTL;

	if (nf_sa->cmn_flags & NF_IPSEC_SA_DO_ANTI_REPLAY_CHECK) {
		/* The DPAA supports only windows sizes of 32 and 64 bits */
		if (arw_size <= DPA_IPSEC_SA_ARW_32_BITS)
			dpa_sa_in->arw = DPA_IPSEC_ARS32;
		else
			dpa_sa_in->arw = DPA_IPSEC_ARS64;
	} else {
		/* Anti-replay protection is not enabled */
		dpa_sa_in->arw = DPA_IPSEC_ARSNONE;
	}

	dpa_sa_in->use_var_iphdr_len = DPA_IPSEC_SA_VAR_IPHDR_DEFAULT;

	/* Copy NF IP source address in DPA IP source address */
	dpa_sa_in->src_addr.version = nf_sa->te_addr.src_ip.version;
	IP_ADDR(nf_sa->te_addr.src_ip, dpa_sa_in->src_addr);

	/* Copy NF IP destination address in DPA IP destination address */
	dpa_sa_in->dest_addr.version = nf_sa->te_addr.dest_ip.version;
	IP_ADDR(nf_sa->te_addr.dest_ip, dpa_sa_in->dest_addr);

	dpa_sa_in->use_udp_encap = (nf_sa->cmn_flags &
		NF_IPSEC_SA_DO_UDP_ENCAP_FOR_NAT_TRAVERSAL) ? true : false;

	/* Copy UDP source/destination ports */
	dpa_sa_in->src_port = nf_sa->nat_info.src_port;
	dpa_sa_in->dest_port = nf_sa->nat_info.dest_port;

	/* Frames that failed inbound policy verification will be dropped */
	memset(&dpa_sa_in->policy_miss_action,
			0, sizeof(struct dpa_cls_tbl_action));
	dpa_sa_in->policy_miss_action.type = DPA_CLS_TBL_ACTION_DROP;

	/* Frames that pass will be sent to default queue */
	memset(&dpa_sa_in->post_ipsec_action,
			0, sizeof(struct dpa_cls_tbl_action));
	dpa_sa_in->post_ipsec_action.type = DPA_CLS_TBL_ACTION_ENQ;
	dpa_sa_in->post_ipsec_action.enq_params.override_fqid = false;
	dpa_sa_in->post_ipsec_action.enq_params.hmd = DPA_OFFLD_DESC_NONE;

	/* Offload SA to DPAA */
	return dpa_ipsec_create_sa(nsid, dpa_sa, sa_id);
}

static int add_dpa_ipsec_out_sa(nf_ns_id nsid, struct nf_ipsec_sa *nf_sa,
				struct dpa_ipsec_sa_params *dpa_sa, int *sa_id)
{
	struct dpa_ipsec_sa_out_params *dpa_sa_out = &dpa_sa->sa_out_params;
	struct dpa_ipsec_init_vector init_vector;
	struct iphdr outer_iphdr;
	struct ip6_hdr outer_ip6hdr;
	struct udphdr udp_hdr;

	/* Set SA params depending on flag selection */
	dpa_sa->use_ext_seq_num = (nf_sa->cmn_flags &
			NF_IPSEC_SA_USE_ESN) ? true : false;
	dpa_sa->sa_mode = (nf_sa->cmn_flags & NF_IPSEC_SA_ENCAP_TRANSPORT_MODE) ?
			DPA_IPSEC_SA_MODE_TRANSPORT : DPA_IPSEC_SA_MODE_TUNNEL;

	memset(dpa_sa_out, 0, sizeof(struct dpa_ipsec_sa_out_params));

	/* Set header update flags */
	if (nf_sa->outb.dscp_handle == NF_IPSEC_DSCP_COPY)
		dpa_sa->hdr_upd_flags |= DPA_IPSEC_HDR_COPY_DSCP;
	if (nf_sa->outb.df_bit_handle == NF_IPSEC_DF_COPY)
		dpa_sa->hdr_upd_flags |= DPA_IPSEC_HDR_COPY_DF;
	dpa_sa->hdr_upd_flags |= DPA_IPSEC_HDR_DEC_TTL;

	/* Set the initialization vector */
	if (nf_sa->outb.iv) {
		dpa_sa_out->init_vector = &init_vector;
		dpa_sa_out->init_vector->init_vector = nf_sa->outb.iv;
		dpa_sa_out->init_vector->length =
				nf_sa->outb.iv_len_bits/BITS_IN_BYTE;
	} else {
		dpa_sa_out->init_vector = NULL;
	}

	dpa_sa_out->ip_ver = nf_sa->te_addr.src_ip.version;
	if (nf_sa->te_addr.src_ip.version == NF_IPV4) {
		memset(&outer_iphdr, 0, sizeof(outer_iphdr));
		outer_iphdr.version = IPVERSION;
		outer_iphdr.ihl = sizeof(outer_iphdr) / sizeof(u32);
		outer_iphdr.ttl = IPDEFTTL;
		outer_iphdr.tot_len = sizeof(outer_iphdr);

		if (nf_sa->outb.df_bit_handle == NF_IPSEC_DF_SET)
			outer_iphdr.frag_off = IP_DONTFRAG;

		if (nf_sa->outb.dscp_handle == NF_IPSEC_DSCP_SET)
			outer_iphdr.tos = nf_sa->outb.dscp;

		if (nf_sa->cmn_flags & NF_IPSEC_SA_DO_UDP_ENCAP_FOR_NAT_TRAVERSAL)
			outer_iphdr.tot_len += sizeof(udp_hdr);

		outer_iphdr.saddr = nf_sa->te_addr.src_ip.ipv4;
		outer_iphdr.daddr = nf_sa->te_addr.dest_ip.ipv4;
		outer_iphdr.protocol = IPPROTO_ESP;
		dpa_sa_out->outer_ip_header = &outer_iphdr;
		dpa_sa_out->ip_hdr_size = sizeof(outer_iphdr);
	} else {
		memset(&outer_ip6hdr, 0, sizeof(outer_ip6hdr));
		memcpy(&outer_ip6hdr.ip6_src, nf_sa->te_addr.src_ip.ipv6.b_addr,
			sizeof(nf_sa->te_addr.src_ip.ipv6.b_addr));
		memcpy(&outer_ip6hdr.ip6_dst, nf_sa->te_addr.dest_ip.ipv6.b_addr,
			sizeof(nf_sa->te_addr.dest_ip.ipv6.b_addr));

		if (nf_sa->outb.dscp_handle == NF_IPSEC_DSCP_SET)
			outer_ip6hdr.ip6_flow = nf_sa->outb.dscp << IP6_TC_OFF;

		outer_ip6hdr.ip6_nxt = IPPROTO_ESP;
		outer_ip6hdr.ip6_hlim = IPDEFTTL;
		dpa_sa_out->outer_ip_header = &outer_ip6hdr;
		dpa_sa_out->ip_hdr_size = sizeof(outer_ip6hdr);
	}

	if (nf_sa->cmn_flags & NF_IPSEC_SA_DO_UDP_ENCAP_FOR_NAT_TRAVERSAL) {
		memset(&udp_hdr, 0, sizeof(udp_hdr));
		udp_hdr.source = nf_sa->nat_info.src_port;
		udp_hdr.dest =  nf_sa->nat_info.dest_port;
		dpa_sa_out->outer_udp_header = (void *)&udp_hdr;
	}
	/* SA verification inside DPA IPSec module is disabled */
	dpa_sa_out->post_sec_flow_id = 0;

	/* Set SA per DSCP range values */
	dpa_sa_out->dscp_start = (uint16_t)nf_sa->outb.dscp_start;
	dpa_sa_out->dscp_end = (uint16_t)nf_sa->outb.dscp_end;

	/* Offload SA to DPAA */
	return dpa_ipsec_create_sa(nsid, dpa_sa, sa_id);
}

static int process_in_sa_selector(struct nf_ipsec_data *nf_ipsec_data,
				  struct nf_ipsec_sa_data *sa, int pos)
{
	struct nf_ipsec_sa_selector *sel = &sa->sels[pos];
	struct nf_ipsec_sa_pol_link *link = NULL;
	struct nf_ipsec_pol_data *pol = NULL;
	int policy_id = sel->policy_id;
	int idx, ret = 0, dir = NF_IPSEC_DIR_INBOUND;

	switch (nf_ipsec_data->pol_state[dir][policy_id]) {
	case POL_STATE_INVALID:
		/* Create policy node */
		pol = create_pol_node(nf_ipsec_data, dir, policy_id);
		if (!pol)
			return -ENOMEM;

		/* Create link node between SA and policy */
		link = create_link_node(sa, pol);
		if (!link) {
			remove_pol_node(pol);
			return -ENOMEM;
		}
		/* Set policy state to 'REFERENCED' */
		nf_ipsec_data->pol_state[dir][policy_id] = POL_STATE_REF;
		break;
	case POL_STATE_INIT:
		/* Obtain policy control block */
		pol = nf_ipsec_data->pol_mng[dir][policy_id];

		idx = find_pol_sel_idx(pol, &sel->selector);
		if (idx >= 0) {
			/* SA sel points to a valid policy sel, offload policy*/
			ret = add_dpa_ipsec_in_pol(pol, idx, sa->sa_id);
			if (ret < 0)
				return ret;
		}

		/* Create link node between SA and policy */
		link = create_link_node(sa, pol);
		if (!link)
			return -ENOMEM;

		/* Change policy state to INIT and_REFERENCED */
		nf_ipsec_data->pol_state[dir][policy_id] = POL_STATE_INIT_REF;
		break;
	case POL_STATE_REF:
		/* Obtain policy control block */
		pol = nf_ipsec_data->pol_mng[dir][policy_id];

		/* If link node already created, finish processing */
		list_for_each_entry(link, &pol->sa_list, sa_node) {
			if (link->sa_id == sa->sa_id)
				return 0;
		}
		/* Create link node between SA and policy */
		link = create_link_node(sa, pol);
		if (!link)
			return -ENOMEM;
		break;
	case POL_STATE_INIT_REF:
		/* Obtain policy control block */
		pol = nf_ipsec_data->pol_mng[dir][policy_id];

		idx = find_pol_sel_idx(pol, &sel->selector);
		if (idx >= 0) {
			/* SA sel points to a valid policy sel, offload policy*/
			ret = add_dpa_ipsec_in_pol(pol, idx, sa->sa_id);
			if (ret < 0)
				return ret;
		}

		/* If link node already created, finish processing */
		list_for_each_entry(link, &pol->sa_list, sa_node) {
			if (link->sa_id == sa->sa_id)
				return 0;
		}
		/* Create link node between SA and policy */
		link = create_link_node(sa, pol);
		if (!link)
			return -ENOMEM;
		break;
	default:
		break;
	}

	return 0;
}

static int process_out_sa_selector(struct nf_ipsec_data *nf_ipsec_data,
				   struct nf_ipsec_sa_data *sa, int pos)
{
	struct nf_ipsec_sa_selector *sel = &sa->sels[pos];
	struct nf_ipsec_sa_pol_link *link = NULL;
	struct nf_ipsec_pol_data *pol = NULL;
	int policy_id = sel->policy_id;
	int idx, ret = 0, dir = NF_IPSEC_DIR_OUTBOUND;

	switch (nf_ipsec_data->pol_state[dir][policy_id]) {
	case POL_STATE_INVALID:
		/* Create policy node */
		pol = create_pol_node(nf_ipsec_data, dir, policy_id);
		if (!pol)
			return -ENOMEM;

		/* Create link node between SA and policy */
		link = create_link_node(sa, pol);
		if (!link) {
			remove_pol_node(pol);
			return -ENOMEM;
		}
		/* Set policy state to 'REFERENCED' */
		nf_ipsec_data->pol_state[dir][policy_id] = POL_STATE_REF;
		break;
	case POL_STATE_INIT:
		/* Obtain policy control block */
		pol = nf_ipsec_data->pol_mng[dir][policy_id];

		idx = find_pol_sel_idx(pol, &sel->selector);
		if (idx >= 0 &&
		    pol->spd_params.action == NF_IPSEC_POLICY_ACTION_IPSEC) {

			/* Remove keys inserted in outbound policy table */
			ret = delete_out_pol(pol, idx);
			if (ret < 0)
				return ret;

			/* SA sel points to a valid policy sel, offload policy*/
			ret = add_dpa_ipsec_out_pol(pol, idx, sa);
			if (ret < 0)
				return ret;
		}

		/* Create link node between SA and policy */
		link = create_link_node(sa, pol);
		if (!link)
			return -ENOMEM;

		/* Change policy state to INIT_AND_REFERENCED */
		nf_ipsec_data->pol_state[dir][policy_id] = POL_STATE_INIT_REF;
		break;

	case POL_STATE_REF:
		/* Obtain policy control block */
		pol = nf_ipsec_data->pol_mng[dir][policy_id];

		/* If link node already created, finish processing */
		list_for_each_entry(link, &pol->sa_list, sa_node) {
			if (link->sa_id == sa->sa_id)
				return 0;
		}
		/* Create link node between SA and policy */
		link = create_link_node(sa, pol);
		if (!link)
			return -ENOMEM;
		break;
	case POL_STATE_INIT_REF:
		/* Obtain policy control block */
		pol = nf_ipsec_data->pol_mng[dir][policy_id];

		idx = find_pol_sel_idx(pol, &sel->selector);
		if (idx >= 0 && pol->spd_params.action ==
				NF_IPSEC_POLICY_ACTION_IPSEC) {
			if (pol->entry_ids[idx] != DPA_OFFLD_DESC_NONE)  {
				/*
				 * Remove inserted key from
				 * outbound policy table
				 */
				ret = delete_out_pol(pol, idx);
				if (ret < 0)
					return ret;
			}

			/* SA sel points to a valid selector, offload new one */
			ret = add_dpa_ipsec_out_pol(pol, idx, sa);
			if (ret < 0)
				return ret;
		}
		/* If link node already created, finish processing */
		list_for_each_entry(link, &pol->sa_list, sa_node) {
			if (link->sa_id == sa->sa_id)
				return 0;
		}
		/* Create link node between SA and policy */
		link = create_link_node(sa, pol);
		if (!link)
			return -ENOMEM;
		break;
	default:
		break;
	}
	return 0;
}

static int delete_sa_selector(struct nf_ipsec_data *nf_ipsec_data,
			      struct nf_ipsec_sa_data *sa,
			      struct nf_ipsec_sa_selector *sel)
{
	struct nf_ipsec_sa_pol_link *link = NULL;
	struct nf_ipsec_pol_data *pol = NULL;
	int id = sel->policy_id;
	int idx = -1, i = 0, pos = -1, ret = 0;

	/* Determine position for this SA selector */
	for (i = 0; i < sa->n_sels; i++) {
		struct nf_ipsec_sa_selector *curr = &sa->sels[i];

		if (curr->policy_id == sel->policy_id &&
		    selector_match(&curr->selector, &sel->selector)) {
			pos = i;
			break;
		}
	}
	if (pos < 0) {
		error(0, EINVAL, "Selector is not part of SA array of selectors");
		return -EINVAL;
	}

	switch (nf_ipsec_data->pol_state[sa->dir][sel->policy_id]) {
	case POL_STATE_REF: {
		/* Obtain policy control block */
		pol = nf_ipsec_data->pol_mng[sa->dir][id];

		/* If other sel points to policy, finish processing */
		if (is_other_sel_link_to_policy(sa, pos, id))
			break;

		/* No other sel points to policy, remove link node */
		list_for_each_entry(link, &pol->sa_list, sa_node) {
			if (link->sa_id == sa->sa_id) {
				remove_link_node(nf_ipsec_data, link);
				break;
			}
		}

		/* Policy sa list empty, set policy state to invalid */
		if (list_empty(&pol->sa_list))
			remove_pol_node(pol);
		break;
	case POL_STATE_INIT_REF:
		/* Obtain policy control block */
		pol = nf_ipsec_data->pol_mng[sa->dir][id];

		/* Determine sel position in POL selector list */
		idx = find_pol_sel_idx(pol, &sel->selector);
		if (idx < 0)
			goto rm_sa_pol_link;

		/* Remove DPA IPSec policy */
		if (pol->dir == NF_IPSEC_DIR_INBOUND) {
			ret = rm_dpa_ipsec_in_pol(pol, idx, sa->sa_id);
			if (ret < 0)
				return ret;
		} else if (pol->entry_ids[idx] == DPA_OFFLD_DESC_NONE) {
			ret = rm_dpa_ipsec_out_pol(pol, idx, sa);
			if (ret < 0)
				return ret;
			ret = insert_out_pol_ipsec(pol, idx);
			if (ret < 0)
				return ret;
		}
rm_sa_pol_link:
		/* If other sel points to policy, finish processing */
		if (is_other_sel_link_to_policy(sa, pos, id))
			break;

		/* No other sel points to policy, remove link node */
		list_for_each_entry(link, &pol->sa_list, sa_node) {
			if (link->sa_id == sa->sa_id) {
				remove_link_node(nf_ipsec_data, link);
				break;
			}
		}
		if (list_empty(&pol->sa_list))
			nf_ipsec_data->pol_state[pol->dir][id] = POL_STATE_INIT;
		break;
	}
	default:
		break;
	}
	/* Operation was successful, shift everything */
	memcpy(&sa->sels[pos], &sa->sels[pos + 1],
		(sa->n_sels - pos - 1) *
		sizeof(struct nf_ipsec_sa_selector));

	/* Mark SA selector as being INVALID */
	memset(&sa->sels[sa->n_sels], 0,
		sizeof(struct nf_ipsec_sa_selector));
	sa->sels[sa->n_sels].policy_id = DPA_OFFLD_DESC_NONE;

	/* Update the number of SA selectors */
	sa->n_sels--;
	return 0;
}

static int rm_sa_resources(struct nf_ipsec_data *nf_ipsec_data,
			   struct nf_ipsec_sa_data *sa)
{
	struct list_head *pos = NULL;
	struct nf_ipsec_sa_pol_link *link = NULL;
	struct nf_ipsec_pol_data *pol = NULL;
	struct nf_ipsec_pol_data *out_pols[NF_IPSEC_MAX_SEL];
	int psel_idx[NF_IPSEC_MAX_SEL];
	int idx, i, j = 0, ret;
	uint8_t *st;

	memset(&out_pols, 0, sizeof(*out_pols) * NF_IPSEC_MAX_SEL);
	memset(&psel_idx, 0, sizeof(int) * NF_IPSEC_MAX_SEL);

	/* DPA IPSec policies will be removed inside by the
	 * remove SA operation, we just destroy the link nodes */
	list_for_each(pos, &sa->pol_list) {
		link = list_entry(pos, struct nf_ipsec_sa_pol_link, pol_node);
		pol = nf_ipsec_data->pol_mng[sa->dir][link->policy_id];
		st = &nf_ipsec_data->pol_state[sa->dir][link->policy_id];

		/* Destroy link node */
		remove_link_node(nf_ipsec_data, link);

		if (*st == POL_STATE_INIT_REF &&
		    pol->dir == NF_IPSEC_DIR_OUTBOUND &&
		    pol->spd_params.action == NF_IPSEC_POLICY_ACTION_IPSEC) {
			for (i = 0; i < sa->n_sels; i++) {
				struct nf_ipsec_sa_selector *sel = &sa->sels[i];

				if (sel->policy_id != pol->policy_id)
					continue;

				idx = find_pol_sel_idx(pol, &sel->selector);
				if (idx < 0)
					continue;
				out_pols[j] = pol;
				psel_idx[j] = idx;
				j++;
			}
		}

		/* Nobody references it, change the state */
		if (list_empty(&pol->sa_list)) {
			if (*st == POL_STATE_REF)
				remove_pol_node(pol);
			else
				*st = POL_STATE_INIT;
		}
	}

	/* This SA doesn't reference any policy anymore, go and remove it */
	ret = remove_sa_node(nf_ipsec_data, sa);
	if (ret < 0) {
		error(0, -ret, "Unable to remove SA");
		return ret;
	}

	for (i = 0; i < NF_IPSEC_MAX_SEL && out_pols[i]; i++) {
		ret = insert_out_pol_ipsec(out_pols[i], psel_idx[i]);
		if (ret < 0)
			return ret;
	}
	return ret;
}

static void fetch_sa_params(struct nf_ipsec_sa_data *sa,
			    struct nf_ipsec_sa *prm)
{
	struct nf_ipsec_sa_crypto_params *scrypt = &sa->sa_params.crypto_params;
	struct nf_ipsec_sa_crypto_params *dcrypt = &prm->crypto_params;

	/* First copy the stored parameters */
	prm->spi = sa->sa_params.spi;
	prm->protocol = sa->sa_params.protocol;

	/* Copy crypto parameters */
	dcrypt->auth_algo = scrypt->auth_algo;
	if (dcrypt->auth_key) {
		memcpy(dcrypt->auth_key, &sa->auth_key,
				scrypt->auth_key_len_bits/BITS_IN_BYTE);
	}
	dcrypt->auth_key_len_bits = scrypt->auth_key_len_bits;
	dcrypt->comb_algo = scrypt->comb_algo;
	if (dcrypt->comb_key) {
		memcpy(dcrypt->comb_key, &sa->comb_key,
				scrypt->comb_key_len_bits/BITS_IN_BYTE);
	}
	dcrypt->comb_key_len_bits = scrypt->comb_key_len_bits;
	dcrypt->cipher_algo = scrypt->cipher_algo;
	if (dcrypt->cipher_key) {
		memcpy(dcrypt->cipher_key, &sa->cipher_key,
				scrypt->cipher_key_len_bits/BITS_IN_BYTE);
	}
	dcrypt->cipher_key_len_bits = scrypt->cipher_key_len_bits;
	if (sa->dir == NF_IPSEC_DIR_OUTBOUND && prm->outb.iv) {
		memcpy(prm->outb.iv, &sa->iv,
			sa->sa_params.outb.iv_len_bits/BITS_IN_BYTE);
	}

	prm->periodic_time_interval = sa->sa_params.periodic_time_interval;
	prm->soft_kilobytes_limit = sa->sa_params.soft_kilobytes_limit;
	prm->hard_kilobytes_limit = sa->sa_params.hard_kilobytes_limit;
	prm->soft_pkt_limit = sa->sa_params.soft_pkt_limit;
	prm->hard_pkt_limit = sa->sa_params.hard_pkt_limit;
	prm->soft_seconds_limit = sa->sa_params.soft_seconds_limit;
	prm->hard_seconds_limit = sa->sa_params.hard_seconds_limit;
	memcpy(&prm->nat_info, &sa->sa_params.nat_info, sizeof(prm->nat_info));
	memcpy(&prm->te_addr, &sa->sa_params.te_addr, sizeof(prm->te_addr));

	prm->n_selectors = sa->n_sels;
	if (prm->selectors) {
		memcpy(prm->selectors, &sa->sels, sa->n_sels *
				sizeof(sizeof(struct nf_ipsec_selector)));
	}
}

static int fetch_sa_stats(struct nf_ipsec_sa_data *sa,
			   struct nf_ipsec_sa_stats *stats)
{
	struct dpa_ipsec_sa_stats sa_stats;
	int ret;

	ret = dpa_ipsec_sa_get_stats(sa->sa_id, &sa_stats);
	if (ret) {
		return ret;
	}
	stats->received_pkts = sa_stats.input_packets;
	stats->processed_pkts = sa_stats.packets_count;
	stats->processed_bytes = sa_stats.bytes_count;

	return 0;
}

static void set_pol_position_begin(struct list_head *pol_list,
				   struct nf_ipsec_pol_data *pol)
{
	struct nf_ipsec_pol_data *f = NULL;

	if (list_empty(pol_list)) {
		/* List is empty, this is the first node */
		pol->prio = (PRIO_HIGH_VAL - PRIO_LOW_VAL)/2;
		list_add_tail(&pol->node, pol_list);
	} else {
		/* Add policy before first node from the list */
		f = list_entry(pol_list->next, struct nf_ipsec_pol_data, node);
		if (f->prio == PRIO_LOW_VAL)
			error(0, 0, "warn: no more space, policy added with same priority as FIRST entry in the SPD");
		pol->prio = (f->prio - PRIO_LOW_VAL)/2;
		list_add(&pol->node, pol_list);
	}
}

static int set_pol_position_before(struct list_head *pol_list,
				   struct nf_ipsec_pol_data *pol)
{
	struct nf_ipsec_policy *prm = &pol->spd_params;
	struct nf_ipsec_data *nf_ipsec_data = pol->nf_ipsec_data;
	struct nf_ipsec_pol_data *rel = NULL, *p = NULL;

	if (!nf_ipsec_data->pol_mng[pol->dir][prm->relative_policy_id]) {
		error(0, EINVAL, "Policy with id %d was not created",
				prm->relative_policy_id);
		return -EINVAL;
	}
	rel = nf_ipsec_data->pol_mng[pol->dir][prm->relative_policy_id];

	if (rel->node.prev == pol_list) {
		/* This is the first node from the list */
		if (rel->prio == PRIO_LOW_VAL)
			error(0, 0, "warn: no more space, policy added with same priority as FIRST entry in the SPD");
		pol->prio = (rel->prio - PRIO_LOW_VAL)/2;
	} else {
		/* Get node before this relative policy */
		p = list_entry(rel->node.prev, struct nf_ipsec_pol_data, node);
		if (rel->prio == p->prio)
			error(0, 0, "warn: no more space, policy added with same priority as relative policy ID");
		pol->prio = p->prio + (rel->prio - p->prio)/2;
	}
	list_add_before(&pol->node, &rel->node);
	return 0;
}

static int set_pol_position_after(struct list_head *pol_list,
				  struct nf_ipsec_pol_data *pol)
{
	struct nf_ipsec_policy *prm = &pol->spd_params;
	struct nf_ipsec_data *nf_ipsec_data = pol->nf_ipsec_data;
	struct nf_ipsec_pol_data *rel = NULL, *n = NULL;

	if (!nf_ipsec_data->pol_mng[pol->dir][prm->relative_policy_id]) {
		error(0, EINVAL, "Policy with id %d does not exist",
			prm->relative_policy_id);
		return -EINVAL;
	}
	rel = nf_ipsec_data->pol_mng[pol->dir][prm->relative_policy_id];

	if (rel->node.next == pol_list) {
		/* This becomes the last node from the list */
		if (rel->prio == PRIO_HIGH_VAL)
			error(0, 0, "warn: no more space, policy added with same priority as LAST entry in the SPD");
		pol->prio = rel->prio + (PRIO_HIGH_VAL - rel->prio)/2;
	} else {
		/* Get node after this relative policy */
		n = list_entry(rel->node.next, struct nf_ipsec_pol_data, node);
		if (rel->prio == n->prio)
			error(0, 0, "warn: no more space, policy added with same priority as relative policy ID");
		pol->prio = rel->prio + (n->prio - rel->prio)/2;
	}
	list_add_after(&pol->node, &rel->node);
	return 0;
}

static void set_pol_position_end(struct list_head *pol_list,
				 struct nf_ipsec_pol_data *pol)
{
	struct nf_ipsec_data *nf_ipsec_data = pol->nf_ipsec_data;
	struct nf_ipsec_pol_data *def_pol = nf_ipsec_data->def_pol;
	struct nf_ipsec_pol_data *i = NULL;

	if (list_empty(pol_list)) {
		/* First node added to the list */
		pol->prio = (PRIO_HIGH_VAL - PRIO_LOW_VAL)/2;
		list_add_tail(&pol->node, pol_list);
	} else {
		if (def_pol) {
			if (def_pol->node.prev == &def_pol->node) {
				/* There are only nodes with 'no priority' so
				 * add policy before first one */
				pol->prio = (PRIO_HIGH_VAL - PRIO_LOW_VAL)/2;
				list_add_before(&pol->node, &def_pol->node);
			} else {
				/* Priority is between last END and first node
				 * with 'no priority' */
				i = list_entry(&def_pol->node.prev,
					struct nf_ipsec_pol_data, node);
				if (i->prio == PRIO_HIGH_VAL)
					error(0, 0, "warn: no more space, policy added with same priority as LAST entry in the SPD");
				pol->prio = i->prio +
					(PRIO_HIGH_VAL - i->prio)/2;
				list_add_before(&pol->node, &def_pol->node);
			}
		} else {
			/* There aren't nodes with 'no priority' */
			i = list_entry(pol_list->prev,
				       struct nf_ipsec_pol_data, node);
			if (i->prio == PRIO_HIGH_VAL)
				error(0, 0, "warn: no more space, policy added with same priority as LAST entry in the SPD");
			pol->prio = i->prio + (PRIO_HIGH_VAL - i->prio)/2;
			list_add_after(&pol->node, &i->node);
		}
	}
}

static int store_spd_pol_params(const struct nf_ipsec_policy *spd_prm,
				struct nf_ipsec_pol_data *pol)
{
	struct nf_ipsec_data *nf_ipsec_data = pol->nf_ipsec_data;
	struct list_head *pol_list = NULL;
	int ret = 0;

	/* Reset the memory area and then copy the user-provided parameters */
	memset(&pol->spd_params, 0, sizeof(pol->spd_params));
	memcpy(&pol->spd_params, spd_prm, sizeof(struct nf_ipsec_policy));

	/* Copy the dscp ranges */
	if (spd_prm->dscp_ranges) {
		memcpy(&pol->dscp_ranges, spd_prm->dscp_ranges,
		       spd_prm->n_dscp_ranges *
		       sizeof(struct nf_ipsec_policy_rule_dscprange));
	}
	/* Copy the selector array */
	if (spd_prm->selectors) {
		memcpy(&pol->sels, spd_prm->selectors,
		       spd_prm->n_selectors * sizeof(struct nf_ipsec_selector));
	}
	pol->n_dscp_ranges = spd_prm->n_dscp_ranges;
	pol->n_sels = spd_prm->n_selectors;

	memset(&pol->entry_ids, DPA_OFFLD_DESC_NONE,
			NF_IPSEC_MAX_SEL * sizeof(int));
	/* determine policy priority based on position */
	pol_list = &nf_ipsec_data->pol_list[pol->dir];

	switch (spd_prm->position) {
	case NF_IPSEC_POLICY_POSITION_BEGIN:
		set_pol_position_begin(pol_list, pol);
		break;
	case NF_IPSEC_POLICY_POSITION_BEFORE:
		ret = set_pol_position_before(pol_list, pol);
		break;
	case NF_IPSEC_POLICY_POSITION_AFTER:
		ret = set_pol_position_after(pol_list, pol);
		break;
	case NF_IPSEC_POLICY_POSITION_END:
		set_pol_position_end(pol_list, pol);
		break;
	default:
		/* Consider as position the END */
		pol->prio = PRIO_HIGH_VAL;
		list_add_tail(&pol->node, pol_list);
		if (!nf_ipsec_data->def_pol)
			nf_ipsec_data->def_pol = pol;
		break;
	}
	return ret;
}

static int set_dpa_ipsec_pol_params(struct dpa_ipsec_policy_params *dpa_pol,
				    struct nf_ipsec_selector *sel)
{
	struct dpa_offload_ip_address *dpa_src_addr, *dpa_dst_addr;

	dpa_src_addr = &dpa_pol->src_addr;
	dpa_dst_addr = &dpa_pol->dest_addr;

	memset(dpa_pol, 0, sizeof(struct dpa_ipsec_policy_params));

	/* Configure IP source and destination address version */
	dpa_pol->src_addr.version = sel->version;
	dpa_pol->dest_addr.version = sel->version;

	if (sel->version == NF_IPV4) {
		if (sel->src_ip4.type == NF_IPA_SUBNET) {
			dpa_src_addr->addr.ipv4.word =
				sel->src_ip4.subnet.addr;
			dpa_pol->src_prefix_len =
				sel->src_ip4.subnet.prefix_len;
		} else {
			error(0, EINVAL, "Selector address type RANGE is not supported");
			return -EINVAL;
		}
	} else {
		if (sel->src_ip6.type == NF_IPA_SUBNET) {
			memcpy(dpa_src_addr->addr.ipv6.word,
			       sel->src_ip6.subnet.addr.w_addr, 4);
			dpa_pol->src_prefix_len =
			       sel->src_ip6.subnet.prefix_len;
		} else {
			error(0, EINVAL, "Selector address type RANGE is not supported");
			return -EINVAL;
		}
	}

	/* Configure IP destination address */
	if (sel->version == NF_IPV4) {
		if (sel->dest_ip4.type == NF_IPA_SUBNET) {
			dpa_dst_addr->addr.ipv4.word =
				sel->dest_ip4.subnet.addr;
			dpa_pol->dest_prefix_len =
				sel->dest_ip4.subnet.prefix_len;
		} else {
			error(0, EINVAL, "Selector address type RANGE is not supported");
			return -EINVAL;
		}
	} else {
		if (sel->dest_ip6.type == NF_IPA_SUBNET) {
			memcpy(dpa_dst_addr->addr.ipv6.word,
				sel->dest_ip6.subnet.addr.w_addr, 4);
			dpa_pol->dest_prefix_len =
				sel->dest_ip6.subnet.prefix_len;
		} else {
			error(0, EINVAL, "Selector address type RANGE is not supported");
			return -EINVAL;
		}
	}

	/* Save protocol number */
	dpa_pol->protocol = sel->protocol;
	dpa_pol->masked_proto = DPA_IPSEC_PROTO_MASK;

	if (sel->dest_port.type != NF_L4_PORT_SINGLE ||
	    sel->src_port.type != NF_L4_PORT_SINGLE) {
		error(0, EINVAL, "Only selector port type SINGLE is supported");
		return -EINVAL;
	}

	if (sel->protocol == IPPROTO_ICMP ||
	    sel->protocol == IPPROTO_ICMPV6) {
		/* ICMP protocol support */
		/*
		 * XXX: no idea if this is good, I just transformed the old
		 * code. The convention to set code in destination port and type
		 * in source port is nowhere to be found.
		 */
		dpa_pol->icmp.icmp_code = (uint8_t)sel->dest_port.single.port;
		dpa_pol->icmp.icmp_type = (uint8_t)sel->src_port.single.port;
		dpa_pol->icmp.icmp_code_mask = DPA_IPSEC_ICMP_PROTO_MASK;
		dpa_pol->icmp.icmp_type_mask = DPA_IPSEC_ICMP_PROTO_MASK;
	} else {
		/* Layer 4 protocol support */
		dpa_pol->l4.src_port = sel->src_port.single.port;
		dpa_pol->l4.dest_port = sel->dest_port.single.port;
		dpa_pol->l4.src_port_mask = DPA_IPSEC_L4_PROTO_MASK;
		dpa_pol->l4.dest_port_mask = DPA_IPSEC_L4_PROTO_MASK;
	}
	return 0;
}

static int add_dpa_ipsec_in_pol(struct nf_ipsec_pol_data *pol,
				int idx, int sa_id)
{
	struct dpa_ipsec_policy_params dpa_pol;
	int ret = 0;

	ret = set_dpa_ipsec_pol_params(&dpa_pol, &pol->sels[idx]);
	if (ret < 0)
		return ret;

	switch (pol->spd_params.action) {
	case NF_IPSEC_POLICY_ACTION_IPSEC:
		/* Enqueue the frame in default base queue */
		dpa_pol.dir_params.type = DPA_IPSEC_POL_DIR_PARAMS_ACT;
		dpa_pol.dir_params.in_action.type = DPA_CLS_TBL_ACTION_ENQ;
		dpa_pol.dir_params.in_action.enq_params.override_fqid = false;
		dpa_pol.dir_params.in_action.enq_params.hmd =
							DPA_OFFLD_DESC_NONE;
		break;
	case NF_IPSEC_POLICY_ACTION_DISCARD:
		/* Drop the frame that */
		dpa_pol.dir_params.type = DPA_IPSEC_POL_DIR_PARAMS_ACT;
		dpa_pol.dir_params.in_action.type = DPA_CLS_TBL_ACTION_DROP;
		break;
	case NF_IPSEC_POLICY_ACTION_BYPASS:
		break;
	default:
		break;
	}
	return dpa_ipsec_sa_add_policy(sa_id, &dpa_pol);
}

static int rm_dpa_ipsec_in_pol(struct nf_ipsec_pol_data *pol,
			       int idx, int sa_id)
{
	struct dpa_ipsec_policy_params dpa_pol;
	int ret = 0;

	ret = set_dpa_ipsec_pol_params(&dpa_pol, &pol->sels[idx]);
	if (ret < 0)
		return ret;

	switch (pol->spd_params.action) {
	case NF_IPSEC_POLICY_ACTION_IPSEC:
		/* Enqueue the frame in default base queue */
		dpa_pol.dir_params.type = DPA_IPSEC_POL_DIR_PARAMS_ACT;
		dpa_pol.dir_params.in_action.type = DPA_CLS_TBL_ACTION_ENQ;
		dpa_pol.dir_params.in_action.enq_params.override_fqid = false;
		dpa_pol.dir_params.in_action.enq_params.hmd =
							DPA_OFFLD_DESC_NONE;
		break;
	case NF_IPSEC_POLICY_ACTION_DISCARD:
		/* Drop the frame that */
		dpa_pol.dir_params.type = DPA_IPSEC_POL_DIR_PARAMS_ACT;
		dpa_pol.dir_params.in_action.type = DPA_CLS_TBL_ACTION_DROP;
		break;
	case NF_IPSEC_POLICY_ACTION_BYPASS:
		break;
	default:
		break;
	}
	return dpa_ipsec_sa_remove_policy(sa_id, &dpa_pol);
}

static int add_dpa_ipsec_out_pol(struct nf_ipsec_pol_data *pol,
				 int idx, struct nf_ipsec_sa_data *nf_sa)
{
	struct nf_ipsec_data *nf_ipsec_data = pol->nf_ipsec_data;
	struct nf_ipsec_sa *prm = &nf_sa->sa_params;
	struct dpa_ipsec_policy_params dpa_pol;
	bool use_dscp = false, alloc_frag_fmd = false;
	uint32_t mtu = prm->outb.mtu;
	int i, ret = 0;

	/* If SA per DSCP enabled, check that this policy can be offloaded */
	if (pol->n_dscp_ranges > 0) {
		for (i = 0; i < pol->n_dscp_ranges; i++) {
			if (prm->outb.dscp_start <= pol->dscp_ranges[i].start &&
			    prm->outb.dscp_end >= pol->dscp_ranges[i].end) {
				/* We found one policy DSCP range that is a
				 * superset for the SA DSCP range */
				use_dscp = true;
				break;
			}
		}
		if (!use_dscp) {
			error(0, EINVAL, "Policy range of DSCP values is not a superset of SA DSCP range");
			return -EINVAL;
		}
	}

	ret = set_dpa_ipsec_pol_params(&dpa_pol, &pol->sels[idx]);
	if (ret < 0)
		return ret;

	if ((pol->spd_params.redside ==
	     NF_IPSEC_POLICY_REDSIDE_FRAGMENTATION_ENABLE) && mtu > 0) {
		if (nf_sa->frag_hmd == DPA_OFFLD_DESC_NONE) {
			if (nf_ipsec_data->n_frag_nodes)
				ret = update_frag_manip(nf_sa, nf_ipsec_data);
			else
				ret = create_frag_manip(nf_sa, nf_ipsec_data);
			if (ret < 0)
				return ret;
			/* Fragmentation descriptor was allocated */
			alloc_frag_fmd = true;
		}
		/* The fragmentation manip was already created, just use it */
		dpa_pol.dir_params.type = DPA_IPSEC_POL_DIR_PARAMS_MANIP;
		dpa_pol.dir_params.manip_desc = nf_sa->frag_hmd;
	} else {
		dpa_pol.dir_params.type = DPA_IPSEC_POL_DIR_PARAMS_NONE;
	}
	dpa_pol.use_dscp = use_dscp;

	ret = dpa_ipsec_sa_add_policy(nf_sa->sa_id, &dpa_pol);
	if (ret && alloc_frag_fmd)
		release_sa_frag_hmd(nf_sa, pol->nf_ipsec_data);

	return ret;
}

static int rm_dpa_ipsec_out_pol(struct nf_ipsec_pol_data *pol,
				int idx, struct nf_ipsec_sa_data *sa)
{
	struct dpa_ipsec_policy_params dpa_pol;
	int ret = 0;

	ret = set_dpa_ipsec_pol_params(&dpa_pol, &pol->sels[idx]);
	if (ret < 0)
		return ret;

	if ((pol->spd_params.redside ==
	     NF_IPSEC_POLICY_REDSIDE_FRAGMENTATION_ENABLE) &&
	     sa->sa_params.outb.mtu > 0) {
		dpa_pol.dir_params.type = DPA_IPSEC_POL_DIR_PARAMS_MANIP;
		dpa_pol.dir_params.manip_desc = sa->frag_hmd;
	} else
		dpa_pol.dir_params.type = DPA_IPSEC_POL_DIR_PARAMS_NONE;

	return dpa_ipsec_sa_remove_policy(sa->sa_id, &dpa_pol);
}

static int insert_out_pol_ipsec(struct nf_ipsec_pol_data *pol, int idx)
{
	struct nf_ipsec_data *nf_ipsec_data = pol->nf_ipsec_data;
	struct dpa_cls_tbl_action action;
	struct dpa_offload_lookup_key key;
	uint8_t key_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t mask_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	int tbl = 0, ret = 0;

	/* If there is no SA that points to this policy, insert it in the table
	 * with action "enqueue to default queue" */
	key.byte = key_data;
	key.mask = mask_data;
	ret = create_out_tbl_key(nf_ipsec_data, &pol->sels[idx], &tbl, &key);
	if (ret < 0) {
		error(0, -ret, "Could not create key for OUTBOUND policy table!");
		return ret;
	}

	/* Frames will be sent to default queue */
	memset(&action, 0, sizeof(action));
	action.type = DPA_CLS_TBL_ACTION_ENQ;
	action.enq_params.override_fqid = false;
	action.enq_params.hmd = DPA_OFFLD_DESC_NONE;

	ret = dpa_classif_table_insert_entry(tbl, &key, &action,
				      0,
				      &pol->entry_ids[idx]);
	if (ret < 0) {
		error(0, -ret, "Could not add key in exact match table for ipsec action!");
		return ret;
	}
	return 0;
}

static int insert_out_pol_discard(struct nf_ipsec_pol_data *pol)
{
	struct dpa_cls_tbl_action action;
	struct dpa_offload_lookup_key key;
	uint8_t key_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t mask_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	int tbl = DPA_OFFLD_DESC_NONE;
	int i, ret = 0;

	key.byte = key_data;
	key.mask = mask_data;
	for (i = 0; i < pol->n_sels; i++) {
		ret = create_out_tbl_key(pol->nf_ipsec_data,
					 &pol->sels[i], &tbl, &key);
		if (ret < 0) {
			error(0, -ret, "Could not create key for OUTBOUND policy table!");
			return ret;
		}

		memset(&action, 0, sizeof(action));
		action.type = DPA_CLS_TBL_ACTION_DROP;

		ret = dpa_classif_table_insert_entry(tbl, &key, &action,
						     0, &pol->entry_ids[i]);
		if (ret < 0) {
			error(0, -ret, "Could not add key in exact match table!");
			return ret;
		}
	}
	return 0;
}

static int insert_out_pol_bypass(struct nf_ipsec_pol_data *pol)
{
	struct dpa_cls_tbl_action action;
	struct dpa_offload_lookup_key key;
	uint8_t key_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t mask_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	int tbl = DPA_OFFLD_DESC_NONE;
	int i, ret;

	if (unlikely(!gbl_init))
		return -EBADF;

	key.byte = key_data;
	key.mask = mask_data;

	for (i = 0; i < pol->n_sels; i++) {
		ret = create_out_tbl_key(pol->nf_ipsec_data,
					 &pol->sels[i], &tbl, &key);
		if (ret < 0) {
			error(0, -ret, "Could not create key for OUTBOUND policy table!");
			return ret;
		}

		memset(&action, 0, sizeof(action));
		action.type = DPA_CLS_TBL_ACTION_ENQ;
		action.enq_params.override_fqid = true;
		action.enq_params.new_fqid = gbl_init->ipsec.fqid;
		action.enq_params.hmd = DPA_OFFLD_DESC_NONE;

		ret = dpa_classif_table_insert_entry(tbl, &key, &action,
						     0, &pol->entry_ids[i]);
		if (ret < 0) {
			error(0, -ret, "Could not add key in exact match table!");
			return ret;
		}
	}
	return 0;
}

static int delete_out_pol(struct nf_ipsec_pol_data *pol, int idx)
{
	int td = DPA_OFFLD_DESC_NONE;
	int ret = 0;

	/* Determine DPA outbound table from which to remove policy */
	td = get_out_pol_table(pol->nf_ipsec_data, &pol->sels[idx]);
	if (td == DPA_OFFLD_DESC_NONE)
		return -EBADF;

	/* Remove policy */
	ret = dpa_classif_table_delete_entry_by_ref(td, pol->entry_ids[idx]);
	if (ret < 0) {
		error(0, -ret, "Could not remove key for OUTBOUND policy table!");
		return ret;
	}
	pol->entry_ids[idx] = DPA_OFFLD_DESC_NONE;
	return 0;
}

static int add_pol_init_state(struct nf_ipsec_data *nf_ipsec_data,
			      int dir, const struct nf_ipsec_policy *spd_params)
{
	struct nf_ipsec_pol_data *pol = NULL;
	int i, policy_id = spd_params->policy_id;
	int ret = 0;

	/* Create policy node */
	pol = create_pol_node(nf_ipsec_data, dir, policy_id);
	if (!pol)
		return -ENOMEM;

	/* Copy user-provided policy parameters */
	ret = store_spd_pol_params(spd_params, pol);
	if (ret < 0) {
		remove_pol_node(pol);
		return ret;
	}

	/* Set policy state to 'INIT' */
	nf_ipsec_data->pol_state[dir][policy_id] = POL_STATE_INIT;

	/* If no selectors are provided or direction is INBOUND, finish processing */
	if (dir == NF_IPSEC_DIR_INBOUND || !pol->n_sels)
		return 0;

	/* Perform different operations based on action */
	switch (pol->spd_params.action) {
	case NF_IPSEC_POLICY_ACTION_DISCARD:
		ret = insert_out_pol_discard(pol);
		if (ret < 0) {
			remove_pol_node(pol);
			return ret;
		}
		break;
	case NF_IPSEC_POLICY_ACTION_BYPASS:
		ret = insert_out_pol_bypass(pol);
		if (ret < 0) {
			remove_pol_node(pol);
			return ret;
		}
		break;
	case NF_IPSEC_POLICY_ACTION_IPSEC:
		for (i = 0; i < pol->n_sels; i++) {
			ret = insert_out_pol_ipsec(pol, i);
			if (ret < 0) {
				remove_pol_node(pol);
				return ret;
			}
		}
		break;
	default:
		error(0, EINVAL, "Invalid policy action for policy %d",
				policy_id);
		return -EINVAL;
	}
	return 0;
}

static int add_in_pol_ref_state(struct nf_ipsec_pol_data *pol)
{
	struct nf_ipsec_data *nf_ipsec_data = pol->nf_ipsec_data;
	struct nf_ipsec_sa_data *sa = NULL;
	struct nf_ipsec_sa_pol_link *link = NULL;
	int i, idx, ret = 0;

	/* Search through list of SA link nodes the ones that reference this policy */
	list_for_each_entry(link, &pol->sa_list, sa_node) {
		sa = nf_ipsec_data->sa_mng[pol->dir][link->sa_id];

		for (i = 0; i < sa->n_sels; i++) {
			struct nf_ipsec_sa_selector *sel = &sa->sels[i];

			if (sel->policy_id != pol->policy_id)
				continue;

			idx = find_pol_sel_idx(pol, &sel->selector);
			if (idx < 0)
				continue;

			ret = add_dpa_ipsec_in_pol(pol, idx, link->sa_id);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}

static int del_in_pol_ref_state(struct nf_ipsec_pol_data *pol)
{
	struct nf_ipsec_data *nf_ipsec_data = pol->nf_ipsec_data;
	struct nf_ipsec_sa_data *sa = NULL;
	struct nf_ipsec_sa_pol_link *link = NULL;
	struct list_head *pos = NULL;
	int i, idx, ret = 0;

	/* Search through list of SA link nodes the ones that reference this policy */
	list_for_each(pos, &pol->sa_list) {
		link = list_entry(pos, struct nf_ipsec_sa_pol_link, sa_node);
		sa = nf_ipsec_data->sa_mng[pol->dir][link->sa_id];

		for (i = 0; i < sa->n_sels; i++) {
			struct nf_ipsec_sa_selector *sel = &sa->sels[i];

			if (sel->policy_id != pol->policy_id)
				continue;

			idx = find_pol_sel_idx(pol, &sel->selector);
			if (idx < 0)
				continue;

			ret = rm_dpa_ipsec_in_pol(pol, idx, link->sa_id);
			if (ret < 0)
				return ret;
		}
		remove_link_node(nf_ipsec_data, link);
	}
	return 0;
}

static int add_out_pol_ref_state(struct nf_ipsec_pol_data *pol)
{
	struct nf_ipsec_data *nf_ipsec = pol->nf_ipsec_data;
	struct nf_ipsec_sa_pol_link *link = NULL;
	struct nf_ipsec_sa_data *sa = NULL;
	int dpa_pol[NF_IPSEC_MAX_SEL];
	int i, idx, ret = 0;

	memset(&dpa_pol, 0, pol->n_sels * sizeof(int));

	/* Search through list of SA link nodes the ones that reference this policy */
	list_for_each_entry(link, &pol->sa_list, sa_node) {
		sa = nf_ipsec->sa_mng[pol->dir][link->sa_id];
		for (i = 0; i < sa->n_sels; i++) {
			struct nf_ipsec_sa_selector *sel = &sa->sels[i];

			if (sel->policy_id != pol->policy_id)
				continue;

			idx = find_pol_sel_idx(pol, &sel->selector);
			if (idx < 0)
				continue;

			ret = add_dpa_ipsec_out_pol(pol, idx, sa);
			if (ret < 0)
				return ret;

			/* Mark policy as being offloaded */
			dpa_pol[idx] = 1;
		}
	}

	for (i = 0; i < pol->n_sels; i++) {
		if (dpa_pol[i])
			continue;

		ret = insert_out_pol_ipsec(pol, i);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int del_out_pol_ref_state(struct nf_ipsec_pol_data *pol)
{
	struct nf_ipsec_data *nf_ipsec_data = pol->nf_ipsec_data;
	struct nf_ipsec_sa_pol_link *link = NULL;
	struct nf_ipsec_sa_data *sa = NULL;
	struct list_head *pos = NULL;
	int i, idx, ret = 0;

	/* Search through list of SA link nodes the ones that reference this policy */
	list_for_each(pos, &pol->sa_list) {
		link = list_entry(pos, struct nf_ipsec_sa_pol_link, sa_node);
		sa = nf_ipsec_data->sa_mng[pol->dir][link->sa_id];

		if (pol->spd_params.action == NF_IPSEC_POLICY_ACTION_IPSEC) {
			for (i = 0; i < sa->n_sels; i++) {
				struct nf_ipsec_sa_selector *sel = &sa->sels[i];

				if (sel->policy_id != pol->policy_id)
					continue;

				idx = find_pol_sel_idx(pol, &sel->selector);
				if (idx < 0)
					continue;

				ret = rm_dpa_ipsec_out_pol(pol, idx, sa);
				if (ret < 0)
					return ret;
			}
		}
		remove_link_node(nf_ipsec_data, link);
	}

	for (i = 0; i < pol->n_sels; i++) {
		if (pol->entry_ids[i] == DPA_OFFLD_DESC_NONE)
			continue;
		ret = delete_out_pol(pol, i);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int add_pol_ref_state(struct nf_ipsec_data *nf_ipsec_data,
			     int dir, const struct nf_ipsec_policy *spd_params)
{
	struct nf_ipsec_pol_data *pol = NULL;
	int ret = 0;

	/* Obtain policy control block */
	pol = nf_ipsec_data->pol_mng[dir][spd_params->policy_id];

	/* Copy user-provided policy params */
	ret = store_spd_pol_params(spd_params, pol);
	if (ret < 0) {
		remove_pol_node(pol);
		return ret;
	}

	/* Set policy state to 'INIT and REF' */
	nf_ipsec_data->pol_state[dir][pol->policy_id] = POL_STATE_INIT_REF;

	/* If no selectors are provided, finish processing */
	if (!pol->n_sels)
		return 0;

	if (dir == NF_IPSEC_DIR_INBOUND) {
		ret = add_in_pol_ref_state(pol);
	} else {
		/* Perform different operations based on action */
		switch (pol->spd_params.action) {
		case NF_IPSEC_POLICY_ACTION_DISCARD:
			ret = insert_out_pol_discard(pol);
			if (ret < 0)
				return ret;
			break;
		case NF_IPSEC_POLICY_ACTION_BYPASS:
			ret = insert_out_pol_bypass(pol);
			if (ret < 0)
				return ret;
			break;
		case NF_IPSEC_POLICY_ACTION_IPSEC:
			ret = add_out_pol_ref_state(pol);
			break;
		default:
			error(0, EINVAL, "Invalid policy action for policy %d",
					pol->policy_id);
			return -EINVAL;
		}
	}
	return ret;
}

static int delete_pol(struct nf_ipsec_pol_data *pol)
{
	struct nf_ipsec_data *nf_ipsec_data = pol->nf_ipsec_data;
	uint8_t *st = &nf_ipsec_data->pol_state[pol->dir][pol->policy_id];
	int ret = 0, i;

	switch (*st) {
	case POL_STATE_INIT:
		if (pol->dir == NF_IPSEC_DIR_OUTBOUND && pol->n_sels) {
			for (i = 0; i < pol->n_sels; i++) {
				/* Remove keys inserted in out policy table */
				ret = delete_out_pol(pol, i);
				if (ret < 0)
					return ret;
			}
		}
		/* Release policy related resources */
		remove_pol_node(pol);
		break;
	case POL_STATE_INIT_REF:
		if (pol->dir == NF_IPSEC_DIR_INBOUND)
			ret = del_in_pol_ref_state(pol);
		else
			ret = del_out_pol_ref_state(pol);
		/* Set policy state to 'REFERENCED' */
		*st = POL_STATE_REF;
		break;
	default:
		error(0, EINVAL, "Policy with id %d was not previously added",
				pol->policy_id);
		return -EINVAL;
	}
	return ret;
}

static void fetch_pol_params(struct nf_ipsec_pol_data *pol,
			     struct nf_ipsec_policy *prm)
{
	prm->policy_id = pol->policy_id;
	prm->action = pol->spd_params.action;
	prm->status = pol->spd_params.status;
	prm->position = pol->spd_params.position;
	prm->relative_policy_id = pol->spd_params.relative_policy_id;
	prm->n_dscp_ranges = pol->n_dscp_ranges;
	/* Copy the dscp ranges */
	if (prm->dscp_ranges) {
		memcpy(prm->dscp_ranges, &pol->dscp_ranges,
			pol->n_dscp_ranges *
			sizeof(struct nf_ipsec_policy_rule_dscprange));
	}
	prm->redside = pol->spd_params.redside;
	prm->fragments_opts = pol->spd_params.fragments_opts;
	prm->n_selectors = pol->n_sels;
	/* Copy the selector array */
	if (prm->selectors) {
		memcpy(prm->selectors, &pol->sels,
			pol->n_sels * sizeof(struct nf_ipsec_selector));
	}
}

int32_t nf_ipsec_sa_add(
	nf_ns_id nsid,
	const struct nf_ipsec_sa_add_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_sa_add_outargs *out,
	struct nf_api_resp_args *resp)
{
	struct nf_ipsec_sa *nf_sa = in->sa_params;
	struct nf_ipsec_data *nf_ipsec_data = NULL;
	struct nf_ipsec_sa_data *sa = NULL;
	struct dpa_ipsec_sa_params dpa_sa;
	int i, sa_id = DPA_OFFLD_DESC_NONE, ret = 0;

	if (unlikely(!gbl_init))
		return -EBADF;

	nf_ipsec_data = gbl_nf_ipsec_data;

	if (flags == NF_API_CTRL_FLAG_ASYNC) {
		error(0, EINVAL, "Asynchronous call is not currently supported");
		return -EINVAL;
	}

	if (flags == NF_API_CTRL_FLAG_NO_RESP_EXPECTED) {
		error(0, EINVAL, "Call without response is not currently supported");
		return -EINVAL;
	}

	/* Check SA user-provided parameters */
	ret = check_sa_params(in);
	if (ret < 0)
		return ret;

	sa = find_sa_node(nf_ipsec_data,
			in->dir,
			in->sa_params->spi,
			in->sa_params->te_addr.dest_ip,
			in->sa_params->protocol);
	if (sa) {
		error(0, EINVAL, "SA was previously added");
		return -EINVAL;
	}

	memset(&dpa_sa, 0, sizeof(struct dpa_ipsec_sa_params));
	dpa_sa.start_seq_num = DPA_IPSEC_SA_START_SEQ_NUM_DEFAULT;
	dpa_sa.l2_hdr_size = DPA_IPSEC_SA_L2_HDR_SIZE_DEFAULT;
	dpa_sa.sa_wqid = DPA_IPSEC_SA_WQ_DEFAULT;
	dpa_sa.enable_stats = DPA_IPSEC_SA_EN_STATS_DEFAULT;
	dpa_sa.enable_extended_stats = DPA_IPSEC_SA_EN_EXT_STATS_DEFAULT;
	dpa_sa.sa_bpid = gbl_init->ipsec.user_data.bpid;
	dpa_sa.sa_bufsize =  gbl_init->ipsec.user_data.bufsize;

	/* Copy SPI field */
	dpa_sa.spi = nf_sa->spi;

	/* Protocol number should either be ESP or AH */
	if (nf_sa->protocol == ESP_PROTOCOL_NUMBER) {
		dpa_sa.sa_proto = DPA_IPSEC_SA_PROTO_ESP;
	} else if (nf_sa->protocol == AH_PROTOCOL_NUMBER) {
		dpa_sa.sa_proto = DPA_IPSEC_SA_PROTO_AH;
	} else {
		error(0, EINVAL, "Invalid SA protocol %d", nf_sa->protocol);
		return -EINVAL;
	}

	/* Translate NF crypto parameters into DPA crypto parameters */
	ret = set_dpa_ipsec_sa_crypto_params(&nf_sa->crypto_params,
					     &dpa_sa.crypto_params);
	if (ret < 0)
		return ret;

	switch (in->dir) {
	case NF_IPSEC_INBOUND:
		/* Set INBOUND direction parameters */
		dpa_sa.sa_dir = DPA_IPSEC_INBOUND;
		ret = add_dpa_ipsec_in_sa(nsid, nf_sa, &dpa_sa, &sa_id);
		if (ret < 0) {
			error(0, -ret, "Unable to add inbound DPA IPSec SA");
			return ret;
		}
		break;
	case NF_IPSEC_OUTBOUND:
		/* Set OUTBOUND direction parameters */
		dpa_sa.sa_dir = DPA_IPSEC_OUTBOUND;
		ret = add_dpa_ipsec_out_sa(nsid, nf_sa, &dpa_sa, &sa_id);
		if (ret < 0) {
			error(0, -ret, "Unable to add outbound DPA IPSec SA");
			return ret;
		}
		break;
	default:
		error(0, EINVAL, "Invalid SA direction %d", in->dir);
		return -EINVAL;
	}

	/* Create SA control block and store it */
	sa = create_sa_node(nf_ipsec_data, in, sa_id);
	if (!sa) {
		dpa_ipsec_remove_sa(sa_id);
		return -ENOMEM;
	}

	/* If SA has no selectors, finish processing */
	if (!nf_sa->n_selectors)
		return 0;

	if (in->dir == NF_IPSEC_INBOUND) {
		/* For every selector, offload the policy */
		for (i = 0; i < nf_sa->n_selectors; i++) {
			ret = process_in_sa_selector(nf_ipsec_data, sa, i);
			if (ret < 0)
				return ret;
		}
	} else {
		/* For every selector, offload the policy */
		for (i = 0; i < nf_sa->n_selectors; i++) {
			ret = process_out_sa_selector(nf_ipsec_data, sa, i);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}

int32_t nf_ipsec_sa_del(
	nf_ns_id nsid,
	const struct nf_ipsec_sa_del_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_sa_del_outargs *out,
	struct nf_api_resp_args *resp)
{
	struct nf_ipsec_data *nf_ipsec_data = NULL;
	struct nf_ipsec_sa_data *sa = NULL;

	nf_ipsec_data = gbl_nf_ipsec_data;

	if (flags == NF_API_CTRL_FLAG_ASYNC) {
		error(0, EINVAL, "Asynchronous call is not currently supported");
		return -EINVAL;
	}

	if (flags == NF_API_CTRL_FLAG_NO_RESP_EXPECTED) {
		error(0, EINVAL, "Call without response is not currently supported");
		return -EINVAL;
	}

	/* Check SA parameters */
	if (in->dir != NF_IPSEC_INBOUND && in->dir != NF_IPSEC_OUTBOUND) {
		error(0, EINVAL, "Invalid SA direction %d. It should be %d or %d",
				in->dir, NF_IPSEC_INBOUND, NF_IPSEC_OUTBOUND);
		return -EINVAL;
	}

	sa = find_sa_node(nf_ipsec_data, in->dir, in->sa_id.spi,
			  in->sa_id.dest_ip, in->sa_id.protocol);
	if (!sa) {
		error(0, EINVAL, "SA was not previously added");
		return -EINVAL;
	}
	return rm_sa_resources(nf_ipsec_data, sa);
}

int32_t nf_ipsec_sa_mod(
	nf_ns_id nsid,
	const struct nf_ipsec_sa_mod_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_sa_mod_outargs *out,
	struct nf_api_resp_args *resp)
{
	struct nf_ipsec_data *nf_ipsec_data = NULL;
	struct nf_ipsec_sa_data *sa = NULL;
	int ret = 0;

	nf_ipsec_data = gbl_nf_ipsec_data;

	if (flags == NF_API_CTRL_FLAG_ASYNC) {
		error(0, EINVAL, "Asynchronous call is not currently supported");
		return -EINVAL;
	}

	if (flags == NF_API_CTRL_FLAG_NO_RESP_EXPECTED) {
		error(0, EINVAL, "Call without response is not currently supported");
		return -EINVAL;
	}

	/* Check SA parameters */
	if (in->dir != NF_IPSEC_INBOUND && in->dir != NF_IPSEC_OUTBOUND) {
		error(0, EINVAL, "Invalid SA direction %d. It should be %d or %d",
				in->dir, NF_IPSEC_INBOUND, NF_IPSEC_OUTBOUND);
		return -EINVAL;
	}

	/* Find SA node */
	sa = find_sa_node(nf_ipsec_data, in->dir, in->sa_id.spi,
			  in->sa_id.dest_ip, in->sa_id.protocol);
	if (!sa) {
		error(0, EINVAL, "SA was not previously added");
		return -EINVAL;
	}

	if (in->flags == NF_IPSEC_SA_MODIFY_LOCAL_GW_INFO) {
		error(0, EINVAL, "Modify local gateway information is not currently supported");
		return -EINVAL;
	}

	if (in->flags == NF_IPSEC_SA_MODIFY_PEER_GW_INFO) {
		error(0, EINVAL, "Modify peer gateway information is not currently supported");
		return -EINVAL;
	}

	if (in->flags == NF_IPSEC_SA_MODIFY_REPLAY_INFO) {
		error(0, EINVAL, "Modify replay window information is not currently supported");
		return -EINVAL;
	}

	if (in->flags == NF_IPSEC_SA_ADD_SEL) {
		const struct nf_ipsec_selector *sel = &in->selector.selector;

		if (sa->n_sels == NF_IPSEC_MAX_SEL) {
			error(0, EINVAL, "Reached maximum number of SA selectors");
			return -EINVAL;
		}
		if (sel->version != NF_IPV4 && sel->version != NF_IPV6) {
			error(0, EINVAL, "Invalid selector IP version %d. It should be %d or %d",
					sel->version, NF_IPV4, NF_IPV6);
			return -EINVAL;
		}

		/* Copy new SA selector on free position */
		memcpy(&sa->sels[sa->n_sels], &in->selector,
			sizeof(struct nf_ipsec_sa_selector));

		if (in->dir == NF_IPSEC_INBOUND) {
			ret = process_in_sa_selector(
					nf_ipsec_data, sa, sa->n_sels);
			if (ret < 0)
				return ret;
		} else {
			ret = process_out_sa_selector(
					nf_ipsec_data, sa, sa->n_sels);
			if (ret < 0)
				return ret;
		}
		/* Operation was successful */
		sa->n_sels++;
		return 0;
	}

	if (in->flags == NF_IPSEC_SA_DEL_SEL) {
		struct nf_ipsec_sa_selector *sa_sel =
				(struct nf_ipsec_sa_selector *)&in->selector;

		if (sa_sel->selector.version != NF_IPV4 &&
		    sa_sel->selector.version != NF_IPV6) {
			error(0, EINVAL, "Invalid selector IP version %d. It should be %d or %d",
				sa_sel->selector.version, NF_IPV4, NF_IPV6);
			return -EINVAL;
		}

		ret = delete_sa_selector(nf_ipsec_data, sa, sa_sel);
		if (ret < 0)
			error(0, -ret, "Failed to delete SA selector");
		return ret;
	}

	if (in->flags == NF_IPSEC_SA_MODIFY_REPLAY_INFO)
		return 0;

	if (in->flags == NF_IPSEC_SA_MODIFY_MTU) {
		ret = modify_out_sa_mtu(nf_ipsec_data, sa, in->mtu);
		if (ret < 0)
			return ret;
		return 0;
	}

	return 0;
}

int32_t nf_ipsec_sa_get(
	nf_ns_id nsid,
	const struct nf_ipsec_sa_get_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_sa_get_outargs *out,
	struct nf_api_resp_args *resp)
{
	struct nf_ipsec_data *nf_ipsec_data = NULL;
	struct list_head *sa_list = NULL;
	struct nf_ipsec_sa_data *sa = NULL;
	int ret;

	nf_ipsec_data = gbl_nf_ipsec_data;

	if (flags == NF_API_CTRL_FLAG_ASYNC) {
		error(0, EINVAL, "Asynchronous call is not currently supported");
		return -EINVAL;
	}

	if (flags == NF_API_CTRL_FLAG_NO_RESP_EXPECTED) {
		error(0, EINVAL, "Call without response is not currently supported");
		return -EINVAL;
	}

	/* Check SA parameters */
	if (in->dir != NF_IPSEC_INBOUND && in->dir != NF_IPSEC_OUTBOUND) {
		error(0, EINVAL, "Invalid SA direction %d. It should be %d or %d",
				in->dir, NF_IPSEC_INBOUND, NF_IPSEC_OUTBOUND);
		return -EINVAL;
	}

	sa_list = (in->dir == NF_IPSEC_INBOUND) ?
			&nf_ipsec_data->sa_list[NF_IPSEC_DIR_INBOUND] :
			&nf_ipsec_data->sa_list[NF_IPSEC_DIR_OUTBOUND];
	if (list_empty(sa_list)) {
		error(0, EINVAL, "SA database is empty");
		return -EINVAL;
	}

	switch (in->operation) {
	case NF_IPSEC_SA_GET_FIRST:
		sa = list_entry(sa_list->next, struct nf_ipsec_sa_data, node);
		break;
	case NF_IPSEC_SA_GET_NEXT: {
		/* Find SA node */
		sa = find_sa_node(nf_ipsec_data, in->dir, in->sa_id.spi,
				in->sa_id.dest_ip, in->sa_id.protocol);
		if (!sa) {
			error(0, EINVAL, "SA was not previously added");
			return -EINVAL;
		}
		if (sa->node.next == sa_list) {
			error(0, EINVAL, "SA is last entry in the SA database");
			return -EINVAL;
		}
		/* Get next SA */
		sa = list_entry(sa->node.next, struct nf_ipsec_sa_data, node);
		break;
	}
	case NF_IPSEC_SA_GET_EXACT:
		/* Find SA node */
		sa = find_sa_node(nf_ipsec_data, in->dir, in->sa_id.spi,
				in->sa_id.dest_ip, in->sa_id.protocol);
		if (!sa) {
			error(0, EINVAL, "SA was not previously added");
			return -EINVAL;
		}
		break;
	default:
		error(0, EINVAL, "Invalid SA fetch operation");
		return -EINVAL;
	}


	if (in->flags & NF_IPSEC_SA_GET_PARAMS) {
		fetch_sa_params(sa, &out->sa_params);
	}
	if (in->flags & NF_IPSEC_SA_GET_STATS) {
		ret = fetch_sa_stats(sa, &out->stats);
		if (ret) {
			error(0, -ret, "Failed to acqure SA statistics for sa id %d",
					sa->sa_id);
			return ret;
		}
	}
	return 0;
}

int32_t nf_ipsec_sa_flush(
	nf_ns_id nsid,
	nf_api_control_flags flags,
	struct nf_api_resp_args *resp)
{
	struct nf_ipsec_data *nf_ipsec_data = NULL;
	struct nf_ipsec_sa_data *sa = NULL;
	int ret = 0, i;

	nf_ipsec_data = gbl_nf_ipsec_data;

	if (flags == NF_API_CTRL_FLAG_ASYNC) {
		error(0, EINVAL, "Asynchronous call is not currently supported");
		return -EINVAL;
	}

	if (flags == NF_API_CTRL_FLAG_NO_RESP_EXPECTED) {
		error(0, EINVAL, "Call without response is not currently supported");
		return -EINVAL;
	}

	for (i = 0; i < NF_IPSEC_DIR_NUM; i++) {
		list_for_each_entry(sa, &nf_ipsec_data->sa_list[i], node) {
			ret = rm_sa_resources(nf_ipsec_data, sa);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}

int32_t nf_ipsec_spd_add(
	nf_ns_id nsid,
	const struct nf_ipsec_spd_add_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_spd_add_outargs *out,
	struct nf_api_resp_args *resp)
{
	struct nf_ipsec_data *nf_ipsec_data = NULL;
	int policy_id = in->spd_params.policy_id;
	int dir, ret = 0;

	nf_ipsec_data = gbl_nf_ipsec_data;

	if (flags == NF_API_CTRL_FLAG_ASYNC) {
		error(0, EINVAL, "Asynchronous call is not currently supported");
		return -EINVAL;
	}

	if (flags == NF_API_CTRL_FLAG_NO_RESP_EXPECTED) {
		error(0, EINVAL, "Call without response is not currently supported");
		return -EINVAL;
	}

	ret = check_policy_params(in);
	if (ret < 0)
		return ret;

	/* Obtain direction */
	dir = (in->dir == NF_IPSEC_INBOUND) ?
			NF_IPSEC_DIR_INBOUND : NF_IPSEC_DIR_OUTBOUND;

	if (nf_ipsec_data->pol_state[dir][policy_id] == POL_STATE_INVALID) {
		ret = add_pol_init_state(nf_ipsec_data, dir, &in->spd_params);
		if (ret < 0)
			return ret;
	} else if (nf_ipsec_data->pol_state[dir][policy_id] == POL_STATE_REF) {
		ret = add_pol_ref_state(nf_ipsec_data, dir, &in->spd_params);
		if (ret < 0)
			return ret;
	} else {
		error(0, EINVAL, "Policy with id %d was previously added",
				policy_id);
		return -EINVAL;
	}

	return 0;
}

int32_t nf_ipsec_spd_del(
	nf_ns_id nsid,
	const struct nf_ipsec_spd_del_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_spd_del_outargs *out,
	struct nf_api_resp_args *resp)
{
	struct nf_ipsec_data *nf_ipsec_data = NULL;
	int dir, st;

	nf_ipsec_data = gbl_nf_ipsec_data;

	if (flags == NF_API_CTRL_FLAG_ASYNC) {
		error(0, EINVAL, "Asynchronous call is not currently supported");
		return -EINVAL;
	}

	if (flags == NF_API_CTRL_FLAG_NO_RESP_EXPECTED) {
		error(0, EINVAL, "Call without response is not currently supported");
		return -EINVAL;
	}

	if (in->dir != NF_IPSEC_INBOUND && in->dir != NF_IPSEC_OUTBOUND) {
		error(0, EINVAL, "Invalid policy direction %d. It should be %d or %d",
				in->dir, NF_IPSEC_INBOUND, NF_IPSEC_OUTBOUND);
		return -EINVAL;
	}

	/* Set direction */
	dir = (in->dir == NF_IPSEC_INBOUND) ?
			NF_IPSEC_DIR_INBOUND : NF_IPSEC_DIR_OUTBOUND;

	st = nf_ipsec_data->pol_state[dir][in->policy_id];
	if (!(st & POL_STATE_INIT)) {
		error(0, EINVAL, "Policy %d was not created", in->policy_id);
		return -EINVAL;
	}
	return delete_pol(nf_ipsec_data->pol_mng[dir][in->policy_id]);
}

int32_t nf_ipsec_spd_mod(
	nf_ns_id nsid,
	const struct nf_ipsec_spd_mod_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_spd_mod_outargs *out,
	struct nf_api_resp_args *resp)
{
	error(0, EINVAL, "Function nf_ipsec_spd_mod is not currently supported");
	return -EINVAL;
}

int32_t nf_ipsec_spd_get(
	nf_ns_id nsid,
	const struct nf_ipsec_spd_get_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_spd_get_outargs *out,
	struct nf_api_resp_args *resp)
{
	struct nf_ipsec_data *nf_ipsec_data = NULL;
	struct nf_ipsec_pol_data *pol = NULL;
	struct list_head *plist = NULL;
	int st, dir;

	nf_ipsec_data = gbl_nf_ipsec_data;

	if (flags == NF_API_CTRL_FLAG_ASYNC) {
		error(0, EINVAL, "Asynchronous call is not currently supported");
		return -EINVAL;
	}

	if (flags == NF_API_CTRL_FLAG_NO_RESP_EXPECTED) {
		error(0, EINVAL, "Call without response is not currently supported");
		return -EINVAL;
	}

	if (in->dir != NF_IPSEC_INBOUND && in->dir != NF_IPSEC_OUTBOUND) {
		error(0, EINVAL, "Invalid policy direction %d. It should be %d or %d",
				in->dir, NF_IPSEC_INBOUND, NF_IPSEC_OUTBOUND);
		return -EINVAL;
	}

	/* Set direction */
	dir = (in->dir == NF_IPSEC_INBOUND) ?
			NF_IPSEC_DIR_INBOUND : NF_IPSEC_DIR_OUTBOUND;

	plist = &nf_ipsec_data->pol_list[dir];
	if (list_empty(plist)) {
		error(0, EINVAL, "SPD database is empty");
		return -EINVAL;
	}

	switch (in->operation) {
	case NF_IPSEC_SPD_GET_FIRST:
		pol = list_entry(plist->next, struct nf_ipsec_pol_data, node);
		fetch_pol_params(pol, &out->spd_params);
		break;
	case NF_IPSEC_SPD_GET_NEXT: {
		struct nf_ipsec_pol_data *next = NULL;

		st = nf_ipsec_data->pol_state[dir][in->policy_id];
		if (!(st & POL_STATE_INIT)) {
			error(0, EINVAL, "Policy %d is not created",
					in->policy_id);
			return -EINVAL;
		}
		pol = nf_ipsec_data->pol_mng[dir][in->policy_id];
		if (pol->node.next == plist) {
			error(0, EINVAL, "Policy is last entry in the SPD database");
			return -EINVAL;
		}
		/* Get next policy */
		next = list_entry(pol->node.next,
				struct nf_ipsec_pol_data, node);
		fetch_pol_params(next, &out->spd_params);
		break;
	}
	case NF_IPSEC_SPD_GET_EXACT:
		st = nf_ipsec_data->pol_state[dir][in->policy_id];
		if (!(st & POL_STATE_INIT)) {
			error(0, EINVAL, "Policy %d is not created",
					in->policy_id);
			return -EINVAL;
		}
		pol = nf_ipsec_data->pol_mng[dir][in->policy_id];
		fetch_pol_params(pol, &out->spd_params);
		break;
	default:
		error(0, EINVAL, "Invalid SPD fetch operation");
		return -EINVAL;
	}
	return 0;
}

int32_t nf_ipsec_spd_flush(
	nf_ns_id nsid,
	nf_api_control_flags flags,
	struct nf_api_resp_args *resp)
{
	struct nf_ipsec_data *nf_ipsec_data = NULL;
	struct nf_ipsec_pol_data *pol = NULL;
	int ret, i;

	nf_ipsec_data = gbl_nf_ipsec_data;

	if (flags == NF_API_CTRL_FLAG_ASYNC) {
		error(0, EINVAL, "Asynchronous call is not currently supported");
		return -EINVAL;
	}

	if (flags == NF_API_CTRL_FLAG_NO_RESP_EXPECTED) {
		error(0, EINVAL, "Call without response is not currently supported");
		return -EINVAL;
	}

	for (i = 0; i < NF_IPSEC_DIR_NUM; i++) {
		list_for_each_entry(pol, &nf_ipsec_data->pol_list[i], node) {
			if (pol->policy_id == DPA_OFFLD_DESC_NONE)
				continue;
			ret = delete_pol(pol);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}

int32_t nf_ipsec_icmp_err_msg_typecode_add(
	nf_ns_id nsid,
	const struct nf_ipsec_icmp_err_msg_typecode_add_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_icmp_err_msg_typecode_add_outargs *out,
	struct nf_api_resp_args *resp)
{
	error(0, EINVAL, "Function nf_ipsec_icmp_err_msg_typecode_add is not currently supported");
	return -EINVAL;
}

int32_t nf_ipsec_icmp_err_msg_typecode_del(
	nf_ns_id nsid,
	const struct nf_ipsec_icmp_err_msg_typecode_del_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_icmp_err_msg_typecode_del_outargs *out,
	struct nf_api_resp_args *resp)
{
	error(0, EINVAL, "Function nf_ipsec_icmp_err_msg_typecode_del is not currently supported");
	return -EINVAL;
}

int32_t nf_ipsec_icmp_err_msg_typecode_mod(
	nf_ns_id nsid,
	const struct nf_ipsec_icmp_err_msg_typecode_mod_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_icmp_err_msg_typecode_mod_outargs *out,
	struct nf_api_resp_args *resp)
{
	error(0, EINVAL, "Function nf_ipsec_icmp_err_msg_typecode_mod is not currently supported");
	return -EINVAL;
}

int32_t nf_ipsec_icmp_err_msg_typecode_get(
	nf_ns_id nsid,
	const struct nf_ipsec_icmp_err_msg_typecode_get_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_icmp_err_msg_typecode_get_outargs *out,
	struct nf_api_resp_args *resp)
{
	error(0, EINVAL, "Function nf_ipsec_icmp_err_msg_typecode_get is not currently supported");
	return -EINVAL;
}

int32_t nf_ipsec_set_icmp_err_msg_process_status(
	nf_ns_id nsid,
	enum nf_ipsec_icmp_err_msg_process_status_flag status,
	nf_api_control_flags flags,
	struct nf_api_resp_args *resp)
{
	error(0, EINVAL, "Function nf_ipsec_set_icmp_err_msg_process_status is not currently supported");
	return -EINVAL;
}

int32_t nf_ipsec_global_stats_get(
	nf_ns_id nsid,
	const struct nf_ipsec_global_stats_get_inargs *in,
	nf_api_control_flags flags,
	struct nf_ipsec_global_stats_get_outargs *out,
	struct nf_api_resp_args *resp)
{
	struct nf_ipsec_data *nf_ipsec_data = NULL;
	struct nf_ipsec_sa_data *sa = NULL;
	struct nf_ipsec_pol_data *pol = NULL;
	struct dpa_ipsec_sa_stats sa_stats;
	struct dpa_cls_tbl_entry_stats tbl_entry_stats;

	uint8_t pol_state;
	int i, j, ret, td;

	if (flags == NF_API_CTRL_FLAG_ASYNC) {
		error(0, EINVAL, "Asynchronous call is not supported");
		return -EINVAL;
	}

	if (flags == NF_API_CTRL_FLAG_NO_RESP_EXPECTED) {
		error(0, EINVAL, "Call without response is not supported");
		return -EINVAL;
	}

	nf_ipsec_data = gbl_nf_ipsec_data;

	memset(out, 0, sizeof(*out));
	out->stats.outb_received_pkts	= nf_ipsec_data->stats.encrypt_and_send;
	out->stats.outb_processed_pkts	= nf_ipsec_data->stats.encrypt_and_send;
	out->stats.inb_received_pkts	= nf_ipsec_data->stats.decrypt_and_send;
	out->stats.inb_processed_pkts	= nf_ipsec_data->stats.decrypt_and_send;

	/* Get statistics from OUTBOUND SA. */
	for (i = 0; i < NF_IPSEC_MAX_SAS; i++) {
		sa = nf_ipsec_data->sa_mng[NF_IPSEC_DIR_OUTBOUND][i];
		if (!sa) {
			continue;
		}
		memset(&sa_stats, 0, sizeof(sa_stats));
		ret = dpa_ipsec_sa_get_stats(sa->sa_id, &sa_stats);
		if (ret) {
			error(0, -ret, "Failed to get statistics for OUTB SA");
			return ret;
		}
		out->stats.outb_received_pkts += sa_stats.input_packets;
		out->stats.outb_sec_applied_pkts += sa_stats.packets_count;
	}

	/* Get statistics from INBOUND SA. */
	for (i = 0; i < NF_IPSEC_MAX_SAS; i++) {
		sa = nf_ipsec_data->sa_mng[NF_IPSEC_DIR_INBOUND][i];
		if (!sa)
			continue;
		memset(&sa_stats, 0, sizeof(sa_stats));
		ret = dpa_ipsec_sa_get_stats(sa->sa_id, &sa_stats);
		if (ret) {
			error(0, -ret, "Failed to get statistics for INB SA");
			return ret;
		}
		out->stats.inb_received_pkts += sa_stats.input_packets;
		out->stats.inb_sec_applied_pkts += sa_stats.packets_count;
	}

	/* Get statistics from OUTBOUND policies. */
	for (i = 0; i < NF_IPSEC_MAX_POLS; i++) {
		pol = nf_ipsec_data->pol_mng[NF_IPSEC_DIR_OUTBOUND][i];
		pol_state = nf_ipsec_data->pol_state[NF_IPSEC_DIR_OUTBOUND][i];
		if (!pol || (pol_state & POL_STATE_INVALID))
			continue;

		for (j = 0; j < pol->n_sels; j++) {
			if (pol->entry_ids[j] == DPA_OFFLD_DESC_NONE)
				continue;

			td = get_out_pol_table(nf_ipsec_data, &pol->sels[j]);
			if (td < 0)
				continue;

			ret = dpa_classif_table_get_entry_stats_by_ref(
					td,
					pol->entry_ids[j],
					&tbl_entry_stats);
			if (ret) {
				error(0, -ret, "Failed to get statistics for policy with id %" PRIu32,
						pol->policy_id);
				return ret;
			}
			out->stats.outb_processed_pkts += tbl_entry_stats.pkts;
			if (pol->spd_params.action ==
					NF_IPSEC_POLICY_ACTION_IPSEC)
				out->stats.outb_pkts_to_apply_sec +=
					tbl_entry_stats.pkts;
		}
	}

	return 0;
}

int32_t nf_ipsec_encrypt_and_send(
	nf_ns_id nsid,
	const struct nf_ipsec_encrypt_inject *in)
{
	struct nf_ipsec_data *nf_ipsec_data = NULL;
	struct nf_ipsec_pol_data *pol = NULL;
	struct nf_ipsec_sa_data *sa = NULL;
	struct nf_ipsec_sa_pol_link *link = NULL;
	uint32_t fqid;
	int i, ret = 0, sa_found = 0;
	struct bm_buffer bm_buf;
	struct qm_fd fd;
	dma_addr_t phys_addr;

	if (unlikely(!gbl_init))
		return -EBADF;

	nf_ipsec_data = gbl_nf_ipsec_data;

	switch (in->flags) {
	case NF_IPSEC_INJECT_POLICY_INFO:
		pol = nf_ipsec_data->
				pol_mng[NF_IPSEC_DIR_OUTBOUND][in->policy_id];
		if (!pol ||
		    !(nf_ipsec_data->pol_state[NF_IPSEC_DIR_OUTBOUND]
		    [in->policy_id] & POL_STATE_INIT)) {
			error(0, EINVAL, "Outbound policy with id %d does not exist",
					in->policy_id);
			return -EINVAL;
		}

		/* Search for a SA selector matching this policy id */
		list_for_each_entry(link, &pol->sa_list, sa_node) {
			sa = nf_ipsec_data->sa_mng[pol->dir][link->sa_id];
			for (i = 0; i < sa->n_sels; i++) {
				if (0 <= find_pol_sel_idx(pol,
						&sa->sels[i].selector)) {
					sa_found = 1;
					break;
				}
			}
			if (sa_found)
				break;
		}

		if (!sa_found) {
			error(0, EINVAL, "Outbound policy with id %d does not have reference to an existing SA",
					in->policy_id);
			return -EINVAL;
		}
		break;
	case NF_IPSEC_INJECT_SA_IDENTIFIER_INFO:
		sa = find_sa_node(nf_ipsec_data,
				NF_IPSEC_OUTBOUND,
				in->sa_id.spi,
				in->sa_id.dest_ip,
				in->sa_id.protocol);
		if (!sa) {
			error(0, EINVAL, "SA with the requested parameters does not exist");
			return -EINVAL;
		}
		break;
	default:
		error(0, EINVAL, "Call without proper input flag");
		return -EINVAL;
	}

	ret = dpa_ipsec_sa_get_out_path(sa->sa_id, &fqid);
	if (ret) {
		error(0, -ret, "Failed to get outbound path for SA with id %d",
				sa->sa_id);
		return ret;
	}

	/* Create frame to be enqueued in the frame queue. */
	ret = bman_acquire(nf_ipsec_data->bm_pool, &bm_buf, 1, 0);
	if (ret < 0) {
		error(0, -ret, "Failed to acquire buffer from buffer pool with id %d",
				gbl_init->ipsec.bpid);
		return ret;
	}

	phys_addr = bm_buf_addr(&bm_buf);
	memcpy(__dma_mem_ptov(phys_addr),
			((struct nf_packet *) in->pkt)->data,
			((struct nf_packet *) in->pkt)->length);

	memset(&fd, 0, sizeof(fd));
	qm_fd_addr_set64(&fd, phys_addr);
	fd.format = qm_fd_contig;
	fd.length20 = ((struct nf_packet *) in->pkt)->length;
	fd.cmd = 0;
	fd.offset = 0;
	fd.bpid = gbl_init->ipsec.bpid;

	/* Enqueue the frame in the frame queue. */
	nf_ipsec_data->local_fq.fqid = fqid;
	ret = qman_enqueue(&nf_ipsec_data->local_fq, &fd, 0);
	if (ret) {
		error(0, -ret, "Failed to enqueue frame");
		return ret;
	}

	return 0;
}

int32_t nf_ipsec_decrypt_and_send(const struct nf_ipsec_decrypt_inject *in)
{
	error(0, EINVAL, "Function nf_ipsec_decrypt_and_send is not currently supported");
	return -EINVAL;
}

int32_t nf_ipsec_get_capabilities(
	nf_api_control_flags flags,
	struct nf_ipsec_cap_get_outargs *out,
	struct nf_api_resp_args *resp)
{
	struct nf_ipsec_capabilities *cap = &out->cap;

	memset(cap, 0, sizeof(*cap));

	cap->sel_store_in_spd = FEATURE_SUPPORTED;
	cap->ah_protocol = FEATURE_UNSUPPORTED;
	cap->esp_protocol = FEATURE_SUPPORTED;
	cap->ipcomp_protocol = FEATURE_UNSUPPORTED;
	cap->tunnel_mode = FEATURE_SUPPORTED;
	cap->transport_mode = FEATURE_SUPPORTED;
	cap->esn = FEATURE_SUPPORTED;
	cap->multi_sec_protocol = FEATURE_UNSUPPORTED;
	cap->lifetime_in_sec = FEATURE_UNSUPPORTED;
	cap->lifetime_in_kbytes = FEATURE_UNSUPPORTED;
	cap->lifetime_in_packet_cnt = FEATURE_UNSUPPORTED;
	cap->udp_encap = FEATURE_SUPPORTED;
	cap->redside_frag = FEATURE_SUPPORTED;
	cap->peer_gw_adaptation = FEATURE_UNSUPPORTED;
	cap->local_gw_adaptation = FEATURE_UNSUPPORTED;
	cap->tfc = FEATURE_UNSUPPORTED;
	cap->icmp_error_msg_process = FEATURE_UNSUPPORTED;

	/* Authentication Algorithm Capabilities */
	cap->auth_algo_cap.md5 = FEATURE_SUPPORTED;
	cap->auth_algo_cap.sha1 = FEATURE_SUPPORTED;
	cap->auth_algo_cap.sha2 = FEATURE_SUPPORTED;
	cap->auth_algo_cap.aes_xcbc = FEATURE_SUPPORTED;
	cap->auth_algo_cap.none = FEATURE_UNSUPPORTED;

	/* Encryption Algorithm Capabilities */
	cap->cipher_algo_cap.des = FEATURE_UNSUPPORTED;
	cap->cipher_algo_cap.des_3 = FEATURE_SUPPORTED;
	cap->cipher_algo_cap.aes = FEATURE_SUPPORTED;
	cap->cipher_algo_cap.aes_ctr = FEATURE_SUPPORTED;
	cap->cipher_algo_cap.null = FEATURE_SUPPORTED;

	/* Combined mode Algorithm Capabilities */
	cap->comb_algo_cap.aes_ccm = FEATURE_UNSUPPORTED;
	cap->comb_algo_cap.aes_gcm = FEATURE_UNSUPPORTED;
	cap->comb_algo_cap.aes_gmac = FEATURE_UNSUPPORTED;

	cap->max_name_spaces = 1;
	cap->max_tunnels = 1;
	cap->max_spd_policies = NF_IPSEC_MAX_POLS/NF_IPSEC_DIR_NUM;
	cap->max_sas =  NF_IPSEC_MAX_SAS/NF_IPSEC_DIR_NUM;
	cap->max_icmp_policies = 0;
	return 0;
}

int32_t nf_ipsec_api_get_version(char *version)
{
	error(0, EINVAL, "Function nf_ipsec_api_get_version is not currently supported");
	return -EINVAL;
}

int32_t nf_ipsec_dp_set_status(
	nf_ns_id nsid,
	enum nf_ipsec_status_flag status,
	nf_api_control_flags flags,
	struct nf_api_resp_args *resp)
{
	error(0, EINVAL, "Function nf_ipsec_dp_set_status is not currently supported");
	return -EINVAL;
}

int32_t nf_ipsec_dp_revalidate(
	nf_ns_id nsid,
	nf_api_control_flags flags,
	struct nf_api_resp_args *resp)
{
	error(0, EINVAL, "Function nf_ipsec_dp_revalidate is not currently supported");
	return -EINVAL;
}

int32_t nf_ipsec_notification_hooks_register(
		const struct nf_ipsec_notification_hooks *hooks)
{
	error(0, EINVAL, "Function nf_ipsec_notification_hooks_register is not currently supported");
	return -EINVAL;
}

int32_t nf_ipsec_notification_hooks_deregister(void)
{
	error(0, EINVAL, "Function nf_ipsec_notification_hooks_deregister is not currently supported");
	return -EINVAL;
}
