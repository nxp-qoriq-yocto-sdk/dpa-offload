#include <stdbool.h>
#include <stdint.h>
#include <net/if.h>
#include <errno.h>

#include <usdpaa_netcfg.h>

#include "fsl_dpa_classifier.h"

#include "init_nfapi.h"
#include "ipfwd.h"
#include "nfinfra_nfapi.h"
#include "neigh_nfapi.h"
#include "nd_nfapi.h"
#include "rule_nfapi.h"
#include "fib_nfapi.h"

/* TTL decrement header manip */
static int create_ttl_hhm(int *hmd)
{
	int ret;
	struct dpa_cls_hm_update_params ttl_dec_hm;

	if (unlikely(!gbl_init))
		return -EINVAL;

	*hmd = DPA_OFFLD_DESC_NONE;
	memset(&ttl_dec_hm, 0, sizeof(ttl_dec_hm));
	ttl_dec_hm.op_flags = DPA_CLS_HM_UPDATE_IPv6_UPDATE;
	ttl_dec_hm.update.l3.field_flags =
				DPA_CLS_HM_IP_UPDATE_TTL_HOPL_DECREMENT;
	ttl_dec_hm.fm_pcd = gbl_init->pcd_dev;
	ret = dpa_classif_set_update_hm(&ttl_dec_hm, DPA_OFFLD_DESC_NONE,
					hmd, false, NULL);
	return ret;
}

/* Ethernet header replacement header manip,
 * chained with TTL decrement header manip */
static int create_fwd_hhm(int *hmd,
			  int ttl_hmd,
			  struct ether_addr *saddr,
			  struct ether_addr *daddr)
{
	struct dpa_cls_hm_fwd_params fwd_params;
	int ret;

	if (unlikely(!gbl_init))
		return -EINVAL;

	*hmd = DPA_OFFLD_DESC_NONE;
	memset(&fwd_params, 0, sizeof(fwd_params));
	fwd_params.fm_pcd = gbl_init->pcd_dev;
	fwd_params.out_if_type = DPA_CLS_HM_IF_TYPE_ETHERNET;
	memcpy(fwd_params.eth.macda, daddr, ETH_ALEN);
	memcpy(fwd_params.eth.macsa, saddr, ETH_ALEN);

	ret = dpa_classif_set_fwd_hm(&fwd_params, ttl_hmd,
				     hmd, true, NULL);
	return ret;
}

/* Returns first Tx FQID of shared mac interface */
static inline uint32_t shmac_tx_fqid(char *ifname)
{
	int i;
	struct fm_eth_port_cfg *port_cfg;
	struct net_if *_if;
	for (i = 0; i < gbl_init->netcfg->num_ethports; i++) {
		port_cfg = &gbl_init->netcfg->port_cfg[i];
		if (strcmp(port_cfg->fman_if->shared_mac_info.shared_mac_name,
			   ifname))
			continue;
		list_for_each_entry(_if, &gbl_init->ifs, node) {
			if (_if->cfg->fman_if == port_cfg->fman_if)
				return qman_fq_fqid(_if->tx_fqs);
		}
	}
	return 0;
}

/* Updates all routes going through this neighbor with header manips
 * and Tx port information. When the ARP entry is deleted initial header manips
 * are removed frames are enqueued to default queues */
static int update_neigh_rt_list(struct nfapi_neigh_t *neigh,
				uint32_t tx_fqid, int fwd_hmd, int ttl_hmd)
{
	struct nfapi_rt_id *curr;
	struct dpa_cls_tbl_action def_action;
	struct dpa_cls_tbl_entry_mod_params mod_params;
	int i, ret = 0, td;

	if (fwd_hmd == DPA_OFFLD_INVALID_OBJECT_ID &&
	    ttl_hmd == DPA_OFFLD_INVALID_OBJECT_ID &&
	    neigh->refcnt == 1) {
		dpa_classif_free_hm(neigh->hmd[0]);
		dpa_classif_free_hm(neigh->hmd[1]);
	}

	neigh->hmd[0] = fwd_hmd;
	neigh->hmd[1] = ttl_hmd;
	neigh->tx_fqid = tx_fqid;
	memset(&def_action, 0, sizeof(def_action));
	memset(&mod_params, 0, sizeof(mod_params));
	def_action.type = DPA_CLS_TBL_ACTION_ENQ;
	def_action.enable_statistics = false;
	def_action.enq_params.new_fqid = neigh->tx_fqid;
	if (neigh->tx_fqid) {
		def_action.enq_params.override_fqid = true;
		def_action.enq_params.hmd = neigh->hmd[0];
	} else
		def_action.enq_params.hmd = DPA_OFFLD_INVALID_OBJECT_ID;
	mod_params.type = DPA_CLS_TBL_MODIFY_ACTION;
	mod_params.action = &def_action;
	for (curr = neigh->rt_list_head; curr; curr = curr->next) {
		for (i = 0; i < gbl_nf_ipfwd_data->ip6fwd_route_nf_res->num_td; i++) {
			td = gbl_nf_ipfwd_data->ip6fwd_route_nf_res->nf_cc[i].td;
			ret = dpa_classif_table_modify_entry_by_ref(td,
								  curr->rt_id,
								  &mod_params);
			if (ret < 0)
				break;
		}
	}
	return ret;
}

static inline int create_hms(int *fwd_hmd, int *ttl_hmd,
			     struct ether_addr *saddr,
			     struct ether_addr *daddr)
{
	int ret;

	/* create header manips */
	ret = create_ttl_hhm(ttl_hmd);
	if (ret != 0)
		return ret;

	ret = create_fwd_hhm(fwd_hmd, *ttl_hmd, saddr, daddr);
	if (ret != 0) {
		dpa_classif_free_hm(*ttl_hmd);
		return ret;
	}

	return 0;
}

static inline int modify_hms(int fwd_hmd,
			     struct ether_addr *saddr,
			     struct ether_addr *daddr)
{
	int ret;
	int modify_flags;
	struct dpa_cls_hm_fwd_params new_fwd_params;

	modify_flags = DPA_CLS_HM_FWD_MOD_ETH_MACSA |
			DPA_CLS_HM_FWD_MOD_ETH_MACDA;

	memset(&new_fwd_params, 0, sizeof(struct dpa_cls_hm_fwd_params));

	new_fwd_params.out_if_type = DPA_CLS_HM_IF_TYPE_ETHERNET;
	new_fwd_params.fm_pcd = gbl_init->pcd_dev;
	memcpy(new_fwd_params.eth.macda, daddr, ETH_ALEN);
	memcpy(new_fwd_params.eth.macsa, saddr, ETH_ALEN);
	ret = dpa_classif_modify_fwd_hm(fwd_hmd, &new_fwd_params, modify_flags);

	return ret;
}

static inline void ifs_add_tail(int ifid, struct nfapi_neigh_t *neigh)
{
	int num_ifs;
	struct nfapi_eth_ifs *eth_if;

	/* add the neighbor to the corresponding interface list given by ifid */
	eth_if = gbl_nf_ipfwd_data->eth_if;
	num_ifs = sizeof(gbl_nf_ipfwd_data->eth_if) / sizeof(eth_if[0]);
	if(ifid < num_ifs) {
		if (!eth_if[ifid].init6) {
			INIT_LIST_HEAD(&eth_if[ifid].if_list_head6);
			eth_if[ifid].init6 = true;
		}
		list_add_tail(&neigh->neigh_node, &eth_if[ifid].if_list_head6);
	}
}

int32_t nf_nd_add_entry(
		nf_ns_id nsid,
		const struct nf_nd_entry *in,
		nf_api_control_flags flags,
		struct nf_nd_outargs *out,
		struct nf_api_resp_args *resp)
{
	struct nfapi_neigh_table_t *neigh_tbl;
	struct nfapi_neigh_t *neigh;
	int fwd_hmd, ttl_hmd, ret = 0;
	char ifname[IFNAMSIZ];
	struct ether_addr saddr;
	uint32_t tx_fqid;
	uint32_t proto_len;
	uint32_t neigh_key[5];
	int idx;

	neigh_tbl = gbl_nf_ipfwd_data->neigh_tbl;

	memset(neigh_key, 0 , sizeof(neigh_key));
	proto_len = sizeof(struct in6_addr);

	memcpy(neigh_key, in->ip_address.w_addr, proto_len);
	idx = proto_len / sizeof(neigh_key[0]);
	memcpy(neigh_key + idx, &in->ifid, sizeof(in->ifid));

	memset(ifname, 0, sizeof(ifname));
	if (!if_indextoname(in->ifid, ifname))
		return -errno;
	ret = get_mac_addr(ifname, &saddr);
	if (ret)
		return ret;
	tx_fqid = shmac_tx_fqid(ifname);

	fwd_hmd = DPA_OFFLD_INVALID_OBJECT_ID;
	ttl_hmd = DPA_OFFLD_INVALID_OBJECT_ID;
	neigh = nfapi_neigh_lookup(&neigh_tbl[IPv6], neigh_key,
				   sizeof(neigh_key));

	/* neighbor bound, update routes with Tx info */
	if (neigh) {
		if (!neigh->tx_fqid) {
			/* create header manips */
			ret = create_hms(&fwd_hmd, &ttl_hmd, &saddr,
					(struct ether_addr *)in->mac_addr);
			if (ret)
				return ret;
			/*
			 * add the neighbor to the eth interface list
			 * identified by ifid
			 */
			ifs_add_tail(in->ifid, neigh);
			/* add the neigh to the neigh table list */
			list_add_tail(&neigh->neigh_tbl_node,
				      &neigh_tbl[IPv6].neigh_list);
			neigh->refcnt++;
			memcpy(&neigh->eth_addr, in->mac_addr, ETH_ALEN);
			neigh->ifid = in->ifid;
			neigh->state = in->state;
			ret = update_neigh_rt_list(neigh, tx_fqid, fwd_hmd,
						   ttl_hmd);
			return ret;
		}
		return -EEXIST;
	}

	/* neighbor not bound, create it */
	neigh = nfapi_neigh_create(&neigh_tbl[IPv6]);
	if (!neigh) {
		ret = -ENOMEM;
		goto out;
	}

	/* create header manips */
	ret = create_hms(&fwd_hmd, &ttl_hmd, &saddr,
			 (struct ether_addr *)(in->mac_addr));
	if (ret) {
		neigh_free(neigh, &neigh_tbl[IPv6]);
		return ret;
	}

	nfapi_neigh_init(&neigh_tbl[IPv6], neigh, neigh_key);
	neigh->hmd[0] = fwd_hmd;
	neigh->hmd[1] = ttl_hmd;
	neigh->tx_fqid = tx_fqid;
	neigh->ifid = in->ifid;
	neigh->state = in->state;
	memcpy(&neigh->eth_addr, in->mac_addr, ETH_ALEN);
	if (!nfapi_neigh_add(&neigh_tbl[IPv6], neigh)) {
		neigh_free(neigh, &neigh_tbl[IPv6]);
		ret = -ENOMEM;
		goto out;
	}
	neigh->refcnt++;

	/* add the neighbor to the eth interface list identified by ifid */
	ifs_add_tail(in->ifid, neigh);
	/* add the neigh to the neigh table list */
	list_add_tail(&neigh->neigh_tbl_node, &neigh_tbl[IPv6].neigh_list);

	return ret;
out:
	dpa_classif_free_hm(fwd_hmd);
	dpa_classif_free_hm(ttl_hmd);
	return ret;
}

int32_t nf_nd_del_entry(
		nf_ns_id nsid,
		const struct nf_nd_entry_del *in,
		nf_api_control_flags flags,
		struct nf_nd_outargs *out,
		struct nf_api_resp_args *resp)
{
	int ret = 0;
	struct nfapi_neigh_table_t *neigh_tbl;
	struct nfapi_neigh_t *neigh;
	uint32_t proto_len;
	uint32_t neigh_key[5];
	int idx;

	neigh_tbl = gbl_nf_ipfwd_data->neigh_tbl;

	memset(neigh_key, 0 , sizeof(neigh_key));
	proto_len = sizeof(struct in6_addr);

	memcpy(neigh_key, in->ip_address.w_addr, proto_len);
	idx = proto_len / sizeof(neigh_key[0]);
	memcpy(neigh_key + idx, &in->ifid, sizeof(in->ifid));
	neigh = nfapi_neigh_lookup(&neigh_tbl[IPv6], neigh_key,
				   sizeof(neigh_key));
	if (unlikely(!neigh))
		return -ENOENT;

	/*
	 * remove the neigh from the corresponding
	 * interface list (ifid) if its tx_fqid is not 0 and update the
	 * neigh rt list.
	 */
	if (neigh->tx_fqid) {
		list_del(&neigh->neigh_node);
		list_del(&neigh->neigh_tbl_node);

		/* remove Tx info */
		ret = update_neigh_rt_list(neigh, 0,
					   DPA_OFFLD_INVALID_OBJECT_ID,
					   DPA_OFFLD_INVALID_OBJECT_ID);
		neigh->refcnt--;
	}

	/* remove neighbor if this is the last ref */
	if (!neigh->refcnt)
		nfapi_neigh_remove(&neigh_tbl[IPv6], neigh_key,
				   sizeof(neigh_key));

	return ret;
}

int32_t nf_nd_modify_entry(
		nf_ns_id nsid,
		const struct nf_nd_entry_mod *in,
		nf_api_control_flags flags,
		struct nf_nd_outargs *out,
		struct nf_api_resp_args *resp)
{
	int ret;
	struct nfapi_neigh_t *neigh;
	uint32_t proto_len;
	char ifname[IFNAMSIZ];
	struct ether_addr saddr;
	uint32_t tx_fqid;
	uint32_t neigh_key[5];
	int idx;

	memset(neigh_key, 0 , sizeof(neigh_key));
	proto_len = sizeof(struct in6_addr);

	memcpy(neigh_key, in->ip_address.w_addr, proto_len);
	idx = proto_len / sizeof(neigh_key[0]);
	memcpy(neigh_key + idx, &in->ifid, sizeof(in->ifid));

	neigh = nfapi_neigh_lookup(&gbl_nf_ipfwd_data->neigh_tbl[IPv6],
			neigh_key, sizeof(neigh_key));
	if (unlikely(!neigh))
		return -ENOENT;

	memset(ifname, 0, sizeof(ifname));
	if (!if_indextoname(in->ifid, ifname))
		return -errno;

	ret = get_mac_addr(ifname, &saddr);
	if (ret)
		return ret;

	tx_fqid = shmac_tx_fqid(ifname);

	/* update fwd hm */
	ret = modify_hms(neigh->hmd[0], &saddr,
			 (struct ether_addr *)in->mac_addr);

	if (ret)
		return ret;

	neigh->tx_fqid = tx_fqid;
	memcpy(&neigh->eth_addr, in->mac_addr, ETH_ALEN);
	neigh->state = in->state;
	neigh->ifid = in->ifid;

	return 0;
}

int32_t nf_nd_flush_entries( nf_ns_id nsid,
		  const struct nf_nd_entry *in,
		  nf_api_control_flags flags,
		  struct nf_nd_outargs *out,
		  struct nf_api_resp_args *resp)
{
	int ret = 0;
	struct nfapi_neigh_t *neigh, *n;
	struct nfapi_eth_ifs *eth_if;
	int num_ifs;
	uint32_t neigh_key[5];
	int idx;

	/* add the neighbor to the corresponding interface list given by ifid */
	eth_if = gbl_nf_ipfwd_data->eth_if;
	num_ifs = sizeof(gbl_nf_ipfwd_data->eth_if) / sizeof(eth_if[0]);

	if ((in->ifid >= num_ifs) || (!eth_if[in->ifid].init6) ||
	      list_empty(&eth_if[in->ifid].if_list_head6))
		return -ENOENT;

	list_for_each_entry_safe(neigh, n,
				 &eth_if[in->ifid].if_list_head6, neigh_node) {
		ret |= update_neigh_rt_list(neigh, 0,
					   DPA_OFFLD_INVALID_OBJECT_ID,
					   DPA_OFFLD_INVALID_OBJECT_ID);
		/*
		 * remove the neigh from the corresponding
		 * interface list - ifid
		 */
		list_del(&neigh->neigh_node);

		/* remove the neigh from the corresponding neigh table list */
		list_del(&neigh->neigh_tbl_node);

		neigh->refcnt--;
		/*
		 * remove neighbor if this is the last ref and no routes
		 * are present
		 */
		if (!neigh->refcnt) {
			memset(neigh_key, 0 , sizeof(neigh_key));
			memcpy(neigh_key, neigh->ip_address,
			       neigh->nt->proto_len);
			idx = neigh->nt->proto_len / sizeof(neigh_key[0]);
			memcpy(neigh_key + idx, &in->ifid, sizeof(in->ifid));
			nfapi_neigh_remove(neigh->nt, neigh_key,
						  sizeof(neigh_key));
		}
	}

	return ret;
}

int32_t nf_nd_entry_get(
		nf_ns_id    nsid,
		const struct nf_nd_get_inargs *in,
		nf_api_control_flags flags,
		struct nf_nd_get_outargs *out,
		struct nf_api_resp_args *resp)
{
	struct nfapi_neigh_table_t *neigh_tbl;
	struct nfapi_neigh_t *neigh;
	uint32_t proto_len;
	uint32_t neigh_key[5];
	int idx;

	neigh_tbl = gbl_nf_ipfwd_data->neigh_tbl;

	memset(neigh_key, 0 , sizeof(neigh_key));
	proto_len = sizeof(struct in6_addr);

	memcpy(neigh_key, &in->ip_address.w_addr, proto_len);
	idx = proto_len / sizeof(neigh_key[0]);
	memcpy(neigh_key + idx, &in->ifid, sizeof(in->ifid));

	switch(in->operation) {
	case ND_GET_FIRST_RECORD:
		if (list_empty(&neigh_tbl[IPv6].neigh_list))
			return -ENOENT;

		neigh = list_entry(neigh_tbl[IPv6].neigh_list.next,
				   struct nfapi_neigh_t, neigh_tbl_node);
		break;
	case ND_GET_FIRST_NEXT:
		neigh = nfapi_neigh_lookup(&neigh_tbl[IPv6], neigh_key,
					   sizeof(neigh_key));
		if (!neigh)
			goto out;

		if (&neigh_tbl[IPv6].neigh_list != neigh->neigh_tbl_node.next)
			neigh = list_entry(neigh->neigh_tbl_node.next,
					   struct nfapi_neigh_t,
					   neigh_tbl_node);
		break;
	case ND_GET_EXACT:
		neigh = nfapi_neigh_lookup(&neigh_tbl[IPv6], neigh_key,
					   sizeof(neigh_key));
		if (!neigh)
			goto out;

		break;
	default:
		return -ENOTSUP;
	}

	memcpy(out->nd_entry.mac_addr, &neigh->eth_addr, ETH_ALEN);
	memcpy(&out->nd_entry.ip_address.w_addr, &neigh->ip_address,
		sizeof(struct in6_addr));
	memcpy(&out->nd_entry.ifid, &neigh->ifid, sizeof(neigh->ifid));
	memcpy(&out->nd_entry.state, &neigh->state, sizeof(neigh->state));
	return 0;

out:
	return -ENOENT;
}
