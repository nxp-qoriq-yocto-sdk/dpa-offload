#include <stdint.h>
#include <errno.h>
#include <netinet/ether.h>

#include <usdpaa_netcfg.h>

#include "fsl_dpa_offload.h"
#include "fsl_dpa_classifier.h"

#include "init_nfapi.h"
#include "ipfwd.h"
#include "nfinfra_nfapi.h"
#include "fib_nfapi.h"
#include "rule_nfapi.h"
#include "ipmr_nfapi.h"
#include "ip4_mcfwd_nfapi.h"

#define VIF_EXISTS(_mrt, _idx) ((_mrt)->vif_table[_idx].tx_fqid != 0)

struct __nf_mc_out {
	int id, td, gd, count, maxvif;
	int md[NF_IP4_MCFWD_MAX_VIFS];
	int hmd[NF_IP4_MCFWD_MAX_VIFS];
};

static int __ttl = DPA_OFFLD_DESC_NONE;

static int __nf_add_group_addr(struct dpa_offload_lookup_key *dpa_key,
			      int iif, int *id)
{
	int ret = 0, i, td;
	bool entry = false;
	struct dpa_cls_tbl_action action;

	ret = set_action(iif, &action);
	if (ret < 0)
		return ret;

	for (i = 0; i < gbl_nf_ipfwd_data->ip4_mc_iif_grp_nf_res->num_td; i++) {
		/* if input interface was specified add entry
		 only in the corresponding route ccnode */
		if (gbl_nf_ipfwd_data->ip4_mc_iif_grp_nf_res->nf_cc[i].ifid != iif)
			continue;

		td = gbl_nf_ipfwd_data->ip4_mc_iif_grp_nf_res->nf_cc[i].td;
		ret = dpa_classif_table_insert_entry(td, dpa_key, &action,
						     0, id);
		if (ret < 0)
			goto out;

		entry = true;
		break;
	}

	if (entry)
		return 0;
	else
		return -ENOENT;

out:
	td = gbl_nf_ipfwd_data->ip4_mc_iif_grp_nf_res->nf_cc[i].td;
	ret |= dpa_classif_table_delete_entry_by_ref(td, *id);

	return ret;
}

static int __nf_find_group_addr(struct dpa_offload_lookup_key *dpa_key, int iif)
{
	int ret = 0, i, td;
	struct dpa_cls_tbl_action action;

	for (i = 0; i < gbl_nf_ipfwd_data->ip4_mc_iif_grp_nf_res->num_td; i++) {
		if (gbl_nf_ipfwd_data->ip4_mc_iif_grp_nf_res->nf_cc[i].ifid != iif)
			continue;

		td = gbl_nf_ipfwd_data->ip4_mc_iif_grp_nf_res->nf_cc[i].td;
		ret = dpa_classif_table_lookup_by_key(td, dpa_key, &action);
		break;
	}

	return ret;
}

static int __nf_remove_group_addr(int id, int iif)
{
	int i, td, ret = 0;

	for (i = 0; i < gbl_nf_ipfwd_data->ip4_mc_iif_grp_nf_res->num_td; i++) {
		if (gbl_nf_ipfwd_data->ip4_mc_iif_grp_nf_res->nf_cc[i].ifid != iif)
			continue;

		td = gbl_nf_ipfwd_data->ip4_mc_iif_grp_nf_res->nf_cc[i].td;
		ret = dpa_classif_table_delete_entry_by_ref(td, id);
		break;
	}

	return ret;
}

/* updates an entry in the ccnode table given by input interface id */
static inline int __update_cc_entry(struct vif_device *v,
				    struct nfapi_mfc_t *mfc,
				    struct dpa_cls_tbl_action *action,
				    struct dpa_offload_lookup_key *dpa_key)
{
	int td = DPA_OFFLD_DESC_NONE, ret, id, i;

	for (i = 0; i < gbl_nf_ipfwd_data->ip4_mc_route_nf_res->num_td; i++) {
		if (gbl_nf_ipfwd_data->ip4_mc_route_nf_res->nf_cc[i].ifid != v->link)
			continue;

		td = gbl_nf_ipfwd_data->ip4_mc_route_nf_res->nf_cc[i].td;
		break;
	}

	if (unlikely(td == DPA_OFFLD_DESC_NONE))
		return -EINVAL;
	/*
	 * if the input interface is changed, it means that the
	 * route was added on another port. it will be deleted
	 * from previous ccnode
	 */
	if (td != mfc->td) {
		ret = dpa_classif_table_insert_entry(td, dpa_key, action, 0,
						     &id);
		if (ret < 0)
			return ret;

		ret = dpa_classif_table_delete_entry_by_ref(mfc->td,
							   mfc->entry_id);
		if (unlikely(ret < 0))
			return ret;

		mfc->td = td;
		mfc->entry_id = id;
		mfc->vif_id = v - gbl_nf_ipfwd_data->mr_tbl[IPv4].vif_table;
	}

	return 0;
}

/* Ethernet header manip - update source and dest mac addresses */
static int create_fwd_hm(int *hmd,
		  struct ether_addr *saddr,
		  struct ether_addr *daddr)
{
	struct dpa_cls_hm_fwd_params fwd_params;
	int ret;

	if (unlikely(!gbl_nf_ipfwd_data->ip4_mc_route_nf_res))
		return -EINVAL;

	*hmd = DPA_OFFLD_DESC_NONE;
	memset(&fwd_params, 0, sizeof(fwd_params));
	fwd_params.fm_pcd = gbl_init->pcd_dev;
	fwd_params.out_if_type = DPA_CLS_HM_IF_TYPE_ETHERNET;
	memcpy(fwd_params.eth.macda, daddr, ETH_ALEN);
	memcpy(fwd_params.eth.macsa, saddr, ETH_ALEN);

	ret = dpa_classif_set_fwd_hm(&fwd_params, DPA_OFFLD_DESC_NONE,
				     hmd, true, NULL);
	return ret;
}

/* calculate Ethernet MAC address from multicast group address */
static inline void ip_eth_mc_map(u32 naddr, char *buf)
{
	u32 addr = ntohl(naddr);
	buf[0] = 0x01;
	buf[1] = 0x00;
	buf[2] = 0x5e;
	buf[5] = addr & 0xFF;
	addr >>= 8;
	buf[4] = addr & 0xFF;
	addr >>= 8;
	buf[3] = addr & 0x7F;
}

/*
 * configure the fwd manip
 * if it does not exist, create the manip and add it in the manip hash
 * if it exists return it from hash
 */
static int __get_fwd_manip(struct vif_device *v,
			    uint32_t gaddr, int *hmd)
{
	uint32_t key[5];
	int ret;
	struct ether_addr saddr;
	char ifname[IFNAMSIZ];
	char daddr[ETH_ALEN];
	struct nfapi_fwd_manip_table_t *manip_tbl;
	struct nfapi_fwd_manip_t *m_fwd = NULL;

	manip_tbl = gbl_nf_ipfwd_data->manip_tbl;

	if (!if_indextoname(v->link, ifname))
		return -ENXIO;

	ret = get_mac_addr(ifname, &saddr);
	if (ret)
		return -EINVAL;

	ip_eth_mc_map(gaddr, daddr);

	*hmd = DPA_OFFLD_DESC_NONE;

	memset(key, 0, sizeof(key));

	/* build the lookup key (output portid, group addr) */
	key[0] = v->link;
	memcpy(&key[1], &gaddr, sizeof(struct in_addr));

	m_fwd = nfapi_manip_lookup(&manip_tbl[IPv4], key, sizeof(key));
	if (!m_fwd) {
		m_fwd = nfapi_manip_create(&manip_tbl[IPv4]);
		if (!m_fwd)
			return -ENOMEM;

		memset(m_fwd, 0, sizeof(*m_fwd));
		m_fwd->link = key[0];
		memcpy(m_fwd->mcastgrp, &gaddr, sizeof(struct in_addr));
		m_fwd->manip_table = &manip_tbl[IPv4];
		/*create the fwd hmd */
		ret = create_fwd_hm(&m_fwd->hmd, &saddr,
				     (struct ether_addr *)daddr);
		if (ret < 0)
			return ret;

		if (!nfapi_manip_add(&manip_tbl[IPv4], m_fwd))
			return -EINVAL;
	}
	*hmd = m_fwd->hmd;
	m_fwd->users++;
	return 0;
}

/* release a fwd manip. in case that ref count reaches 0, free the fwd manip. */
static inline void __put_fwd_manip(struct vif_device *v,
				   uint32_t gaddr)
{
	uint32_t key[5];
	int ret;
	struct ether_addr saddr;
	char ifname[IFNAMSIZ];
	char daddr[ETH_ALEN];
	struct nfapi_fwd_manip_table_t *manip_tbl;
	struct nfapi_fwd_manip_t *m_fwd = NULL;

	manip_tbl = gbl_nf_ipfwd_data->manip_tbl;

	if (!if_indextoname(v->link, ifname))
		return;

	ret = get_mac_addr(ifname, &saddr);
	if (ret)
		return;

	ip_eth_mc_map(gaddr, daddr);
	memset(key, 0, sizeof(key));
	/* build the lookup key (output portid, group addr) */
	key[0] = v->link;
	memcpy(&key[1], &gaddr, sizeof(struct in_addr));

	m_fwd = nfapi_manip_lookup(&manip_tbl[IPv4], key, sizeof(key));
	if (!m_fwd)
		return;

	m_fwd->users--;
	if (!m_fwd->users) {
		dpa_classif_free_hm(m_fwd->hmd);
		nfapi_manip_remove(&manip_tbl[IPv4], key, sizeof(key));
	}
}

/*
 *  change the action of all entries that have v as input interface.
 * action will be changed from drop to enqueue
 */
static inline int __validate_entries(struct vif_device *v)
{
	int ret = 0;
	struct nfapi_mfc_t *mfc;
	struct dpa_cls_tbl_action action;
	struct dpa_cls_tbl_entry_mod_params mod_params;
	struct dpa_offload_lookup_key dpa_key;
	uint32_t rt_key[8];


	if (list_empty(&v->mr_list))
		return ret;
	/*
	 * this vif is input interface for routes in mr_list
	 * change the routes action from drop to enqueue.
	 * if the vif link id is changed, the routes from list must
	 * be moved to the new ccnode table corresponding to the physical
	 * interface
	 */
	list_for_each_entry(mfc, &v->mr_list, mr_vif_node) {
		memset(&action, 0, sizeof(struct dpa_cls_tbl_action));
		action.type = DPA_CLS_TBL_ACTION_MCAST;
		action.enable_statistics = 0;
		action.mcast_params.grpd = mfc->grpd;
		action.mcast_params.hmd = __ttl;
		/* change the action from drop to multicast group grpd */
		memset(&mod_params, 0, sizeof(mod_params));
		mod_params.type = DPA_CLS_TBL_MODIFY_ACTION;
		mod_params.action = &action;
		ret = dpa_classif_table_modify_entry_by_ref(mfc->td,
					    mfc->entry_id, &mod_params);

		if (ret < 0)
			return ret;

		memset(&dpa_key, 0, sizeof(dpa_key));
		memset(rt_key, 0, sizeof(rt_key));
		memcpy(rt_key, mfc->mfc_origin, sizeof(struct in_addr));
		memcpy(&rt_key[1], mfc->mfc_mcastgrp,
			sizeof(struct in_addr));
		dpa_key.byte = (uint8_t *)rt_key;
		dpa_key.mask = NULL;
		dpa_key.size = gbl_nf_ipfwd_data->ip4_mc_route_nf_res->keysize;

		ret = __update_cc_entry(v, mfc, &action, &dpa_key);
		if (ret < 0)
			return ret;
	}

	return ret;
}

static int __vif_add(const struct nf_ip4_mcfwd_vif_entry *vif)
{
	char ifname[IFNAMSIZ];
	struct nfapi_mfc_t *mfc;
	int i, td, id, ret, md, vifi;
	struct nfapi_mr_table_t *mr_tbl = gbl_nf_ipfwd_data->mr_tbl;
	struct vif_device *v = &mr_tbl[IPv4].vif_table[vif->vif_id];
	struct dpa_cls_tbl_enq_action_desc member;
	struct dpa_cls_tbl_action action;
	struct dpa_cls_tbl_entry_mod_params mod_params;
	struct dpa_cls_mcast_group_params group_params;

	if (VIF_EXISTS(&mr_tbl[IPv4], vif->vif_id))
		return -EADDRINUSE;

	v->flags = vif->vif_type;
	v->local = vif->local;
	v->remote = vif->remote;
	v->threshold = vif->threshold;
	v->link = vif->link_id;

	if (!if_indextoname(v->link, ifname))
		return -errno;

	v->tx_fqid = get_shmac_tx(ifname);
	if (!v->tx_fqid)
		return -EINVAL;

	if (vif->vif_id + 1 > mr_tbl[IPv4].maxvif)
		mr_tbl[IPv4].maxvif = vif->vif_id + 1;

	memset(&action, 0, sizeof(action));

	/*
	 * if vif is an input interface, all entries that have this
	 * vif as input were invalidated (action DROP) when vif was deleted
	 */
	ret = __validate_entries(v);
	if (ret < 0)
		return ret;
	/*
	 * if the vif was removed and was member in several groups, then
	 * add it as a member to the groups it belonged before removal.
	 * If the vif was the only member of the group - change the action
	 * of the corresponding route entry, and recreate the group which
	 * contains the removed member.
	 */
	for (i = 0; i < v->last_id; i++) {
		mfc = v->groups[i].mfc;
		memset(&member, 0, sizeof(member));
		if (mfc && (mfc->num_vifs == 0)) {
			memset(&group_params, 0,
				sizeof(struct dpa_cls_mcast_group_params));

			td = mfc->td;
			id = mfc->entry_id;
			member.override_fqid = true;
			member.new_fqid = v->tx_fqid;
			ret = __get_fwd_manip(v, mfc->mfc_mcastgrp[0],
					      &member.hmd);
			if (ret < 0)
				return ret;

			group_params.max_members = mfc->maxvif + 1;
			group_params.fm_pcd = gbl_init->pcd_dev;
			memcpy(&group_params.first_member_params, &member,
				sizeof(member));

			ret = dpa_classif_mcast_create_group(&group_params,
							 &mfc->grpd, NULL);
			if (ret < 0)
				return ret;

			if (ret < 0) {
				__put_fwd_manip(v, mfc->mfc_mcastgrp[0]);
				return ret;
			}

			memset(&mod_params, 0, sizeof(mod_params));
			mod_params.type = DPA_CLS_TBL_MODIFY_ACTION;
			mod_params.action = &action;
			action.enable_statistics = false;
			action.type = DPA_CLS_TBL_ACTION_MCAST;
			action.mcast_params.grpd = mfc->grpd;
			action.mcast_params.hmd = __ttl;
			ret = dpa_classif_table_modify_entry_by_ref(td, id,
								   &mod_params);
			if (ret < 0) {
				__put_fwd_manip(v, mfc->mfc_mcastgrp[0]);
				return ret;
			}
			/* first member has descriptor 0 */
			md = 0;
		} else if (mfc && (mfc->num_vifs > 0)) {
			member.override_fqid = true;
			member.new_fqid = v->tx_fqid;
			ret = __get_fwd_manip(v, mfc->mfc_mcastgrp[0],
					      &member.hmd);
			if (ret < 0)
				return ret;

			ret = dpa_classif_mcast_add_member(mfc->grpd, &member,
							   &md);
			if (ret < 0)
				return ret;
		}
		/* update mfc with the member descriptors and manip descriptor*/
		if (mfc) {
			vifi = vif->vif_id;
			mfc->md[vifi] = md;
			mfc->hmd[vifi] = member.hmd;
			mfc->num_vifs++;
		}
	}
	/*add vif to the vif list used for get operations */
	list_add_tail(&v->vif_node, &mr_tbl[IPv4].vif_list);
	return 0;
}

/* change action to DROP for all entries that have v as input interface */
static inline int __invalidate_entries(struct vif_device *v)
{
	int ret = 0, td, id;
	struct nfapi_mfc_t *mfc;
	struct dpa_cls_tbl_action action;
	struct dpa_cls_tbl_entry_mod_params mod_params;

	if (list_empty(&v->mr_list))
		return ret;
	/*
	 * this vif is input interface for routes in mr_list
	 * if vif is removed, invalidate route entries
	 */
	list_for_each_entry(mfc, &v->mr_list, mr_vif_node) {
		/* modify entry action and set it to drop */
		td = mfc->td;
		id = mfc->entry_id;
		memset(&mod_params, 0, sizeof(mod_params));
		mod_params.type = DPA_CLS_TBL_MODIFY_ACTION;

		mod_params.action = &action;
		action.enable_statistics = false;
		action.type = DPA_CLS_TBL_ACTION_DROP;
		ret = dpa_classif_table_modify_entry_by_ref(td,
					      id, &mod_params);
		if (ret < 0)
			return ret;
	}

	return ret;
}

static int __vif_delete(int vifi)
{
	struct nfapi_mr_table_t *mr_tbl = gbl_nf_ipfwd_data->mr_tbl;
	struct vif_device *v = &mr_tbl[IPv4].vif_table[vifi];
	struct nfapi_mfc_t *mfc;
	int i, td, id;
	struct dpa_cls_tbl_entry_mod_params mod_params;
	struct dpa_cls_tbl_action action;
	int ret = 0;

	if (!VIF_EXISTS(&mr_tbl[IPv4], vifi))
		return -EADDRNOTAVAIL;
	/*
	 * when removing a virtual interface, invalidate all entries that
	 * have this vif as input interface
	 */
	ret = __invalidate_entries(v);
	if (ret < 0)
		return ret;
	/*
	 * search for all the groups that use this vif and remove
	 * the member entry coresponding to the vif.
	 * If the group has only one member, modify table action to be drop
	 *
	 */
	for (i = 0; i < v->last_id; i++) {
		mfc = v->groups[i].mfc;
		if (mfc) {
			if (unlikely(mfc->num_vifs <= 0))
				return -EINVAL;

			if (mfc->num_vifs == 1) {
				td = mfc->td;
				id = mfc->entry_id;
				/* modify action and set the new group descriptor */
				memset(&mod_params, 0, sizeof(mod_params));
				mod_params.type = DPA_CLS_TBL_MODIFY_ACTION;

				mod_params.action = &action;
				action.enable_statistics = false;
				action.type = DPA_CLS_TBL_ACTION_DROP;
				ret = dpa_classif_table_modify_entry_by_ref(td,
							      id, &mod_params);
				if (ret < 0)
					return ret;

				ret = dpa_classif_mcast_free_group(mfc->grpd);
				if (ret < 0)
					return ret;

				mfc->grpd = DPA_OFFLD_DESC_NONE;
			} else {
				ret = dpa_classif_mcast_remove_member(mfc->grpd,
								 mfc->md[vifi]);
				if (ret < 0)
					return ret;
			}
			__put_fwd_manip(v, mfc->mfc_mcastgrp[0]);
			mfc->md[vifi] = DPA_OFFLD_DESC_NONE;
			mfc->hmd[vifi] = DPA_OFFLD_DESC_NONE;
			mfc->num_vifs--;
		}
	}

	if (vifi + 1 == mr_tbl[IPv4].maxvif) {
		int tmp;

		for (tmp = vifi - 1; tmp >= 0; tmp--) {
			if (VIF_EXISTS(&mr_tbl[IPv4], tmp))
				break;
		}
		mr_tbl[IPv4].maxvif = tmp+1;
	}

	list_del(&v->vif_node);
	v->flags = 0;
	v->local = 0;
	v->remote = 0;
	v->threshold = 0;
	v->link = 0;
	v->tx_fqid = 0;

	return 0;
}

static int create_ttl_hhm(int *hmd)
{
	int ret;
	struct dpa_cls_hm_update_params ttl_dec_hm;
	struct dpa_cls_hm_update_resources update_res;

	if (unlikely(!gbl_nf_ipfwd_data->ip4_mc_route_nf_res))
		return -EINVAL;

	*hmd = DPA_OFFLD_DESC_NONE;
	memset(&ttl_dec_hm, 0, sizeof(ttl_dec_hm));
	memset(&update_res, 0, sizeof(struct dpa_cls_hm_update_resources));
	ttl_dec_hm.op_flags = DPA_CLS_HM_UPDATE_IPv4_UPDATE;
	ttl_dec_hm.update.l3.field_flags =
				DPA_CLS_HM_IP_UPDATE_TTL_HOPL_DECREMENT;
	ttl_dec_hm.fm_pcd = gbl_init->pcd_dev;
	update_res.update_node = gbl_nf_ipfwd_data->ip4_mc_route_nf_res->ttl_dec_hm;
	ret = dpa_classif_set_update_hm(&ttl_dec_hm, DPA_OFFLD_DESC_NONE,
					hmd, true,
					&update_res);
	return ret;
}

/* create a multicast group with its members represented by vifs */
static inline int __nf_init_mc_group(
		struct dpa_cls_tbl_enq_action_desc *member,
		struct dpa_cls_mcast_group_params *group_params,
		const uint8_t ttls[], int vif_desc[], int hm_desc[], int *count,
		int *gd, const uint32_t *gaddr)
{
	struct nfapi_mr_table_t *mr_tbl;
	struct dpa_cls_tbl_enq_action_desc *first;
	struct vif_device *v = NULL;
	int vifi, ret, md;
	bool first_member =  true;
	uint32_t fqid;
	int hmd;

	mr_tbl = gbl_nf_ipfwd_data->mr_tbl;

	/*
	 *  each vif with the ttl < 255 represents a multicast member.
	 *  packet will be replicated on each member.
	 */
	for (vifi = 0; vifi < mr_tbl[IPv4].maxvif; vifi++) {
		if (ttls[vifi] && ttls[vifi] < 255) {
			v = &mr_tbl[IPv4].vif_table[vifi];

			memset(member, 0,
				sizeof(struct dpa_cls_tbl_enq_action_desc));
			fqid = mr_tbl[IPv4].vif_table[vifi].tx_fqid;
			/*
			 * create the multicast group associated with an entry
			 * - (src, graddr). A group must have at least
			 * one member
			 */
			if (first_member) {
				/* config fwd manip */
				ret = __get_fwd_manip(v, *gaddr, &hmd);

				if (ret < 0)
					return ret;

				first = &group_params->first_member_params;
				first->override_fqid = true;
				first->hmd = hmd;
				first->new_fqid = fqid;
				ret = dpa_classif_mcast_create_group(
								 group_params,
								 gd, NULL);
				if (ret < 0)
					return ret;

				/* first member has desc 0 */
				vif_desc[vifi] = 0;
				first_member = false;
			} else {/* add members to the group */
				/* config fwd manip */
				ret = __get_fwd_manip(v, *gaddr, &hmd);

				if (ret < 0)
					return ret;

				member->override_fqid = true;
				member->new_fqid = fqid;
				member->hmd = hmd;

				ret = dpa_classif_mcast_add_member(*gd, member,
								   &md);
				if (ret < 0) {
					__put_fwd_manip(v, *gaddr);
					goto out;
				}

				vif_desc[vifi] = md;
			}
			hm_desc[vifi] = hmd;
			(*count)++;
		}
	}

	return 0;
out:
	ret = dpa_classif_mcast_free_group(*gd);

	return ret;
}

static int __nf_add_mfc(struct dpa_offload_lookup_key *dpa_key,
			struct __nf_mc_out *out_params,
			const struct nf_ip4_mcfwd_mfentry *mfc_res,
			struct dpa_cls_tbl_enq_action_desc *member)
{
	struct dpa_cls_mcast_group_params group_params;
	struct dpa_cls_tbl_action action;
	struct nfapi_mr_table_t *mr_tbl = gbl_nf_ipfwd_data->mr_tbl;
	struct vif_device *v = &mr_tbl[IPv4].vif_table[mfc_res->vif_id];
	int i, vifi, ret, new_gd = DPA_OFFLD_INVALID_OBJECT_ID ,td, id;
	bool found = false;

	if (!VIF_EXISTS(&mr_tbl[IPv4], mfc_res->vif_id))
		return -EADDRNOTAVAIL;

	vifi = mfc_res->vif_id;
	/* make sure that the input vif is not selected for output */
	if (mfc_res->ttls[vifi] && mfc_res->ttls[vifi] < 255)
		return -EINVAL;

	/* check if all output vifs exist. If not return error */
	for (vifi = 0; vifi < mr_tbl[IPv4].maxvif; vifi++) {
		if (mfc_res->ttls[vifi] && mfc_res->ttls[vifi] < 255 &&
		     !VIF_EXISTS(&mr_tbl[IPv4], vifi))
			return -EADDRNOTAVAIL;

		/* check that we have at least one vif set in the ttl array */
		if (mfc_res->ttls[vifi] && mfc_res->ttls[vifi] < 255)
			found = true;
	}
	if (!found)
		return -EADDRNOTAVAIL;

	memset(&group_params, 0, sizeof(struct dpa_cls_mcast_group_params));
	group_params.max_members = mr_tbl[IPv4].maxvif + 1;
	out_params->maxvif = group_params.max_members;
	group_params.fm_pcd = gbl_init->pcd_dev;


	ret = __nf_init_mc_group(member, &group_params, mfc_res->ttls,
				out_params->md,
				out_params->hmd,
				&out_params->count,
				&out_params->gd,
				&mfc_res->mcastgrp);

	if (ret < 0)
		return ret;

	/*
	 * add multicast group descriptor to the entry action.
	 * members of the multicast group are represented by vifs with ttl < 255
	 */
	memset(&action, 0, sizeof(struct dpa_cls_tbl_action));
	action.type = DPA_CLS_TBL_ACTION_MCAST;
	action.enable_statistics = 0;
	action.mcast_params.grpd = out_params->gd;
	action.mcast_params.hmd = __ttl;
	td = DPA_OFFLD_DESC_NONE;
	id = -1;

	for (i = 0; i < gbl_nf_ipfwd_data->ip4_mc_route_nf_res->num_td; i++) {
		if (gbl_nf_ipfwd_data->ip4_mc_route_nf_res->nf_cc[i].ifid != v->link)
			continue;

		td = gbl_nf_ipfwd_data->ip4_mc_route_nf_res->nf_cc[i].td;
		ret = dpa_classif_table_insert_entry(td, dpa_key,
						     &action, 0, &id);
		if (ret < 0)
			goto out;


		break;
	}

	if (unlikely(td == DPA_OFFLD_DESC_NONE) || unlikely(id == -1))
		return -EINVAL;

	out_params->td = td;
	out_params->id = id;

	return 0;
out:
	ret = dpa_classif_mcast_free_group(new_gd);
	return ret;

}

/* remove a multicast group from vif group array*/
static inline void __delete_group_vif(struct vif_device *v,
				      struct nfapi_mfc_t *mfc)
{
	int i;

	for (i = 0; i < v->last_id; i++)
		if (v->groups[i].mfc == mfc) {
			v->groups[i].mfc = NULL;
			v->users--;
			/*
			 * if vif is not referenced by any mfc entry,
			 * last_id is 0
			 */
			if (!v->users)
				v->last_id = 0;
			break;
		}
}

static inline int __update_group_vif(struct vif_device *vif_dev,
				   struct nfapi_mfc_t *mfc)
{
	int i;
	bool group_exist = false;

	/* check if the vif contains this group */
	for (i = 0; i < vif_dev->last_id; i++)
		if (vif_dev->groups[i].mfc == mfc) {
			group_exist = true;
			break;
		}
	/* if no group is found, add it on an empty position */
	if (!group_exist) {
		for (i = 0; i < vif_dev->last_id; i++)
			if (!vif_dev->groups[i].mfc)
				break;

		if (vif_dev->last_id >= MAX_GROUPS)
				return -ENOMEM;

		vif_dev->groups[i].mfc = mfc;
		if (i == vif_dev->last_id)
			vif_dev->last_id++;

		vif_dev->users++;
	}

	return 0;
}

/* recreate a multicast replicator group if the number of vifs changes */
static inline int __resize_mfc_group(struct nfapi_mfc_t *mfc,
				     struct dpa_cls_tbl_enq_action_desc *member,
				     const struct nf_ip4_mcfwd_mfentry *mfc_res,
				     struct dpa_offload_lookup_key *dpa_key,
				     int maxvif)
{
	struct nfapi_mr_table_t *mr_tbl;
	int ret, vifi;
	struct dpa_cls_tbl_entry_mod_params mod_params;
	struct dpa_cls_tbl_action action;
	struct dpa_cls_mcast_group_params group_params;
	struct vif_device *v;

	mr_tbl = gbl_nf_ipfwd_data->mr_tbl;
	/*
	 * to be able to delete a group, first change the action of
	 * the entry
	 */
	memset(&mod_params, 0, sizeof(mod_params));
	mod_params.type = DPA_CLS_TBL_MODIFY_ACTION;
	mod_params.action = &action;
	action.enable_statistics = false;
	action.type = DPA_CLS_TBL_ACTION_DROP;
	ret = dpa_classif_table_modify_entry_by_ref(mfc->td,
					mfc->entry_id, &mod_params);
	if (ret < 0)
		return ret;

	ret = dpa_classif_mcast_free_group(mfc->grpd);
	if (ret < 0)
		return ret;

	/*
	 * free the fwd manip for a vif in case that is no longer
	 * referenced. remove also the group from vif group array
	 */
	for (vifi = 0; vifi < mfc->maxvif; vifi++) {
		struct vif_device *vif_dev;

		vif_dev = &mr_tbl[IPv4].vif_table[vifi];
		if (mfc->md[vifi] >= 0)
			__put_fwd_manip(vif_dev, mfc->mfc_mcastgrp[0]);
		__delete_group_vif(vif_dev, mfc);
	}
	memset(mfc->md, DPA_OFFLD_DESC_NONE, sizeof(mfc->md));
	memset(mfc->hmd, DPA_OFFLD_DESC_NONE, sizeof(mfc->hmd));
	mfc->num_vifs = 0;
	/*
	 * Change maximum number of members in the group
	 * according to the max number of vifs.
	 * increment by 1 is necessary because when manipulating a
	 * group, one member will remain (when cleaning the group).
	 * the member will be erased after adding all the new members.
	 * Note that a group cannot be empty when is removed.
	 * E.g : maxvif = 3 (new members 2,3,5), last member 0
	 * 0,2,3,5 will be in the group (so max_members is 3 + 1)
	 * 0 will be then removed to reflect the state with members
	 * 2,3,5
	 */
	mfc->maxvif = maxvif + 1;
	memset(&group_params, 0, sizeof(struct dpa_cls_mcast_group_params));
	group_params.max_members = mfc->maxvif;
	group_params.fm_pcd = gbl_init->pcd_dev;

	ret = __nf_init_mc_group(member, &group_params, mfc_res->ttls,
				mfc->md, mfc->hmd,
				&mfc->num_vifs,
				&mfc->grpd,
				mfc->mfc_mcastgrp);

	if (ret < 0)
		return ret;

	/* update the vifs with the rebuilt groups */
	for (vifi = 0; vifi < mfc->maxvif; vifi++) {
		if (mfc->md[vifi] >= 0) {
			struct vif_device *vif_dev;

			vif_dev = &mr_tbl[IPv4].vif_table[vifi];
			ret = __update_group_vif(vif_dev, mfc);
			if (ret < 0)
				return ret;
		}
	}

	memset(&action, 0, sizeof(struct dpa_cls_tbl_action));
	action.type = DPA_CLS_TBL_ACTION_MCAST;
	action.enable_statistics = 0;
	action.mcast_params.grpd = mfc->grpd;
	action.mcast_params.hmd = __ttl;

	/*
	 * after creating the group update the entry which was set
	 * to drop
	 */
	memset(&mod_params, 0, sizeof(mod_params));
	mod_params.type = DPA_CLS_TBL_MODIFY_ACTION;
	mod_params.action = &action;
	ret = dpa_classif_table_modify_entry_by_ref(mfc->td,
					mfc->entry_id, &mod_params);
	if (ret < 0)
		return ret;
	/*
	 * if input interface has changed remove the mfc entry from
	 * the old ccnode corresponding to old input interface
	 * and add it to the ccnode corresponding to the current
	 * input interface (mfc_res->vif_id)
	 */

	v = &mr_tbl[IPv4].vif_table[mfc_res->vif_id];
	ret = __update_cc_entry(v, mfc, &action, dpa_key);
	return ret;
}

static int __nf_update_mfc(struct nfapi_mfc_t *mfc,
			struct dpa_offload_lookup_key *dpa_key,
			const struct nf_ip4_mcfwd_mfentry *mfc_res,
			struct dpa_cls_tbl_enq_action_desc *member)
{
	struct nfapi_mr_table_t *mr_tbl;
	struct dpa_cls_tbl_action action;
	struct dpa_cls_tbl_entry_mod_params mod_params;
	struct vif_device *v;
	int vifi, ret, md, last_md_idx = -1;
	bool found = false;
	uint32_t fqid;
	int hmd, last_md = DPA_OFFLD_DESC_NONE;

	mr_tbl = gbl_nf_ipfwd_data->mr_tbl;
	if (!VIF_EXISTS(&mr_tbl[IPv4], mfc_res->vif_id))
		return -EADDRNOTAVAIL;

	vifi = mfc_res->vif_id;
	/* make sure that the input vif is not selected for output */
	if (mfc_res->ttls[vifi] && mfc_res->ttls[vifi] < 255)
		return -EINVAL;

	for (vifi = 0; vifi < mr_tbl[IPv4].maxvif; vifi++) {
		/* check if all output vifs exist. If not return error */
		if (mfc_res->ttls[vifi] && mfc_res->ttls[vifi] < 255 &&
		     !VIF_EXISTS(&mr_tbl[IPv4], vifi))
			return -EADDRNOTAVAIL;

		/* check that we have at least one vif set in the ttl array */
		if (mfc_res->ttls[vifi] && mfc_res->ttls[vifi] < 255)
			found = true;
	}
	if (!found)
		return -EADDRNOTAVAIL;

	/*
	 * resize the group: delete the group, create it
	 * with the new max members value  and add the members
	 * obtained from ttls array
	 */
	if ( mfc->maxvif != (mr_tbl[IPv4].maxvif + 1)) {
		ret = __resize_mfc_group(mfc, member, mfc_res, dpa_key,
				   mr_tbl[IPv4].maxvif);
		return ret;
	}

	/* remove members from the group except the first (a group must have
	 * at least one member) */
	for (vifi = 0; vifi < mr_tbl[IPv4].maxvif; vifi++) {
		struct vif_device *vif_dev;

		vif_dev = &mr_tbl[IPv4].vif_table[vifi];
		if (mfc->md[vifi] >= 0) {
			if (mfc->num_vifs == 1) {
				last_md = mfc->md[vifi];
				last_md_idx = vifi;
				mfc->num_vifs--;
				break;
			}

			ret = dpa_classif_mcast_remove_member(mfc->grpd,
							       mfc->md[vifi]);
			if (ret < 0)
				return ret;

			__put_fwd_manip(vif_dev, mfc->mfc_mcastgrp[0]);
			mfc->md[vifi] = DPA_OFFLD_DESC_NONE;
			mfc->hmd[vifi] = DPA_OFFLD_DESC_NONE;
			mfc->num_vifs--;
		}
		__delete_group_vif(vif_dev, mfc);
	}

	/*
	 *  each vif with the ttl < 255 represents a multicast member.
	 *  packet will be replicated on each member.
	 */
	for (vifi = 0; vifi < mr_tbl[IPv4].maxvif; vifi++) {
		if (mfc_res->ttls[vifi] && mfc_res->ttls[vifi] < 255 &&
		     VIF_EXISTS(&mr_tbl[IPv4], vifi)) {
			struct vif_device *vif_dev;

			vif_dev = &mr_tbl[IPv4].vif_table[vifi];
			memset(member, 0,
				sizeof(struct dpa_cls_tbl_enq_action_desc));
			fqid = mr_tbl[IPv4].vif_table[vifi].tx_fqid;
			/* config fwd manip */
			ret = __get_fwd_manip(vif_dev, mfc_res->mcastgrp, &hmd);

			if (ret < 0)
				return ret;

			/* add members to the group */
			member->override_fqid = true;
			member->new_fqid = fqid;
			member->hmd = hmd;
			ret = dpa_classif_mcast_add_member(mfc->grpd,
							   member, &md);
			if (ret < 0) {
				__put_fwd_manip(vif_dev, mfc_res->mcastgrp);
				return ret;
			}

			mfc->md[vifi] = md;
			mfc->hmd[vifi] = hmd;
			mfc->num_vifs++;
			ret = __update_group_vif(vif_dev, mfc);
			if (ret < 0) {
				__put_fwd_manip(vif_dev, mfc_res->mcastgrp);
				return ret;
			}
		}
	}

	if (unlikely(last_md == DPA_OFFLD_DESC_NONE))
		return -EINVAL;

	/*
	 * Remove the last member in group. A group must have at
	 * least one member that cannot be removed. After adding the new members
	 * the last memmber can be removed
	 */
	ret = dpa_classif_mcast_remove_member(mfc->grpd, last_md);
	if (ret < 0)
		return ret;

	__put_fwd_manip(&mr_tbl[IPv4].vif_table[last_md_idx],
			mfc->mfc_mcastgrp[0]);

	if (unlikely(last_md_idx == -1))
		return -EINVAL;

	/* if the member was not overwritten, unset that position */
	if (mfc->md[last_md_idx] == last_md) {
		mfc->md[last_md_idx] = DPA_OFFLD_DESC_NONE;
		mfc->hmd[last_md_idx] = DPA_OFFLD_DESC_NONE;
		/*
		 * vif is no longer a mfc group member.
		 * search the mfc entry in the vif groups array
		 * and remove it.
		 */
		__delete_group_vif(&mr_tbl[IPv4].vif_table[last_md_idx], mfc);
	}

	v = &mr_tbl[IPv4].vif_table[mfc_res->vif_id];
	memset(&action, 0, sizeof(struct dpa_cls_tbl_action));
	action.type = DPA_CLS_TBL_ACTION_MCAST;
	action.enable_statistics = 0;
	action.mcast_params.grpd = mfc->grpd;
	action.mcast_params.hmd = __ttl;
	memset(&mod_params, 0, sizeof(mod_params));
	/*
	 * modify entry action - make sure the action is updated each time
	 * a route is being modified
	 */
	mod_params.type = DPA_CLS_TBL_MODIFY_ACTION;
	mod_params.action = &action;
	ret = dpa_classif_table_modify_entry_by_ref(mfc->td,
					mfc->entry_id, &mod_params);
	if (ret < 0)
		return ret;

	ret = __update_cc_entry(v, mfc, &action, dpa_key);
	return ret;
}

static int __nf_remove_mfc(int id, int gd, int vifi)
{
	int ret = 0, i, td;

	for (i = 0; i < gbl_nf_ipfwd_data->ip4_mc_route_nf_res->num_td; i++) {
		if (gbl_nf_ipfwd_data->ip4_mc_route_nf_res->nf_cc[i].ifid != vifi)
			continue;

		td = gbl_nf_ipfwd_data->ip4_mc_route_nf_res->nf_cc[i].td;
		ret = dpa_classif_table_delete_entry_by_ref(td, id);
		ret |= dpa_classif_mcast_free_group(gd);
		break;
	}

	return ret;
}

int32_t nf_ip4_mcfwd_group_add(nf_ns_id nsid,
		const struct nf_ip4_mcfwd_group *ip4_mcfwd_grp,
		nf_api_control_flags flags,
		struct nf_ip4_mcfwd_group_outargs *ip4_mcfwd_outargs,
		struct nf_api_resp_args  *ip4_mcfwd_respargs)
{
	int ret, id, idx;
	struct dpa_offload_lookup_key dpa_key;
	uint32_t group_key[5];
	struct nfapi_grp_iif_table_t *group_tbl;
	struct nfapi_grp_iif_t *iif_group;

	group_tbl = gbl_nf_ipfwd_data->group_tbl;

	memset(group_key, 0, sizeof(group_key));
	memcpy(group_key, &ip4_mcfwd_grp->group_addr, sizeof(struct in_addr));
	idx = (sizeof(struct in_addr) / sizeof(group_key[0]));
	memcpy(group_key + idx, &ip4_mcfwd_grp->ifid,
		sizeof(ip4_mcfwd_grp->ifid));
	/* build the key for searching it in the ccnode */
	dpa_key.byte = (uint8_t *)group_key;
	dpa_key.mask = NULL;
	dpa_key.size = gbl_nf_ipfwd_data->ip4_mc_iif_grp_nf_res->keysize;

	/* if an application joins a mcast group, search if the group addr
	 * is already present in the interface ccnode. If true, increase the
	 * reference count without adding the group
	 */
	ret = __nf_find_group_addr(&dpa_key, ip4_mcfwd_grp->ifid);

	/*
	 * group address was found in the interface's ccnode.
	 * find the group in the group hash table and increase reference count
	 */
	if (!ret) {
		iif_group = nfapi_group_lookup(&group_tbl[IPv4], group_key,
							sizeof(group_key));
		if (unlikely(!iif_group))
			return -ENOENT;

		iif_group->users++;
		return ret;
	}

	/* insert the group addr  in the group interface ccnode */
	ret = __nf_add_group_addr(&dpa_key, ip4_mcfwd_grp->ifid, &id);

	if (ret < 0)
		return ret;

	/* create and add the group addr  to the group interface table */
	iif_group = nfapi_group_create(&group_tbl[IPv4]);
	if (!iif_group) {
		__nf_remove_group_addr(id, ip4_mcfwd_grp->ifid);
		return -ENOMEM;
	}

	iif_group->entry_id = id;
	iif_group->iif_group = *ip4_mcfwd_grp;
	iif_group->group_tbl = &group_tbl[IPv4];
	iif_group->users = 1;
	iif_group->ifid = ip4_mcfwd_grp->ifid;
	memcpy(iif_group->addr, &ip4_mcfwd_grp->group_addr,
		sizeof(struct in_addr));
	list_add_tail(&iif_group->iif_group_node,
			&group_tbl[IPv4].iif_group_list);

	if (!nfapi_group_add(&group_tbl[IPv4], iif_group)) {
		__nf_remove_group_addr(iif_group->entry_id,
					ip4_mcfwd_grp->ifid);
		list_del(&iif_group->iif_group_node);
		nfapi_group_free(iif_group, &group_tbl[IPv4]);
		return -EINVAL;
	}

	return ret;
}

int32_t nf_ip4_mcfwd_group_delete(nf_ns_id nsid,
		const struct nf_ip4_mcfwd_group *ip4_mcfwd_grp,
		nf_api_control_flags flags,
		struct nf_ip4_mcfwd_group_outargs *ip4_mcfwd_outargs,
		struct nf_api_resp_args  *ip4_mcfwd_respargs)
{
	int ret, idx;
	struct nfapi_grp_iif_table_t *group_tbl;
	struct nfapi_grp_iif_t *iif_group;
	uint32_t group_key[5];

	group_tbl = gbl_nf_ipfwd_data->group_tbl;

	memset(group_key, 0, sizeof(group_key));
	memcpy(group_key, &ip4_mcfwd_grp->group_addr, sizeof(struct in_addr));
	idx = (sizeof(struct in_addr) / sizeof(group_key[0]));
	memcpy(group_key + idx, &ip4_mcfwd_grp->ifid,
		sizeof(ip4_mcfwd_grp->ifid));
	iif_group = nfapi_group_lookup(&group_tbl[IPv4], group_key,
					sizeof(group_key));

	if (!iif_group)
		return -ENOENT;

	/* if an app leaves a multicast group, decrement users counter */
	iif_group->users--;

	/* remove the group if it is no longer referenced */
	if (!iif_group->users) {
		/* remove the group addr from the group interface ccnode */
		ret = __nf_remove_group_addr(iif_group->entry_id,
					    ip4_mcfwd_grp->ifid);

		if (ret < 0)
			return ret;

		list_del(&iif_group->iif_group_node);
		ret = nfapi_group_remove(&group_tbl[IPv4], group_key,
					 sizeof(group_key));
		if (!ret)
			return -EINVAL;
	}

	return 0;
}

int32_t nf_ip4_mcfwd_group_get(nf_ns_id nsid,
		const struct nf_ip4_mcfwd_group_get_inargs *in,
		nf_api_control_flags flags,
		struct nf_ip4_mcfwd_group_get_outargs *out,
		struct nf_api_resp_args *resp)
{
	int idx;
	struct nfapi_grp_iif_table_t *group_tbl;
	struct nfapi_grp_iif_t *iif_group = NULL;
	uint32_t group_key[5];

	group_tbl = gbl_nf_ipfwd_data->group_tbl;

	switch(in->operation) {
	case NF_IP4_MCFWD_GET_FIRST:
		if (list_empty(&group_tbl[IPv4].iif_group_list))
			return -ENOENT;

		iif_group = list_entry(group_tbl[IPv4].iif_group_list.next,
				       struct nfapi_grp_iif_t,
				       iif_group_node);
		break;
	case NF_IP4_MCFWD_GET_NEXT:
		memset(group_key, 0, sizeof(group_key));
		memcpy(group_key, &in->group_addr, sizeof(struct in_addr));
		idx = (sizeof(struct in_addr) / sizeof(group_key[0]));
		memcpy(group_key + idx, &in->ifid,
			sizeof(in->ifid));
		iif_group = nfapi_group_lookup(&group_tbl[IPv4], group_key,
						sizeof(group_key));
		if (unlikely(!iif_group))
			goto out;

		/*
		 * get the next group if the number of entries in the interface
		 * group table is greater than 1
		 */
		if (&group_tbl[IPv4].iif_group_list !=
		    iif_group->iif_group_node.next)
			iif_group = list_entry(iif_group->iif_group_node.next,
					       struct nfapi_grp_iif_t,
					       iif_group_node);
		break;
	case NF_IP4_MCFWD_GET_EXACT:
		memset(group_key, 0, sizeof(group_key));
		memcpy(group_key, &in->group_addr, sizeof(struct in_addr));
		idx = (sizeof(struct in_addr) / sizeof(group_key[0]));
		memcpy(group_key + idx, &in->ifid,
			sizeof(in->ifid));
		iif_group = nfapi_group_lookup(&group_tbl[IPv4], group_key,
						sizeof(group_key));
		if (unlikely(!iif_group))
			goto out;

		break;
	default:
		return -ENOTSUP;
	}

	memcpy(&out->ip4addr_entry, &iif_group->iif_group,
		sizeof(struct nf_ip4_mcfwd_group));
	return 0;
out:
	return -ENOENT;
}

int32_t nf_ip4_mcfwd_vif_add(nf_ns_id nsid,
		const struct nf_ip4_mcfwd_vif_entry *ip4_mcfwd_vif,
		nf_api_control_flags flags,
		struct nf_ip4_mcfwd_vif_outargs *ip4_mcfwd_outargs,
		struct nf_api_resp_args  *ip4_mcfwd_respargs)
{
	int ret;

	if (ip4_mcfwd_vif->vif_type == NF_IP4_MCFWD_VIF_TYPE_TUNNEL ||
	    ip4_mcfwd_vif->vif_type == NF_IP4_MCFWD_VIF_TYPE_REGISTER)
		return -ENOTSUP;

	if (ip4_mcfwd_vif->vif_id >= NF_IP4_MCFWD_MAX_VIFS)
		return -ENFILE;

	ret = __vif_add(ip4_mcfwd_vif);

	return ret;
}

int32_t nf_ip4_mcfwd_vif_delete(nf_ns_id nsid,
	const struct nf_ip4_mcfwd_vif_entry_del *ip4_mcfwd_vif,
	nf_api_control_flags flags,
	struct nf_ip4_mcfwd_vif_outargs *ip4_mcfwd_outargs,
	struct nf_api_resp_args  *ip4_mcfwd_respargs)
{
	int ret;

	if (ip4_mcfwd_vif->vif_id >= NF_IP4_MCFWD_MAX_VIFS)
		return -ENFILE;

	ret = __vif_delete(ip4_mcfwd_vif->vif_id);
	return ret;
}

int32_t nf_ip4_mcfwd_vif_get(nf_ns_id nsid,
	const struct nf_ip4_mcfwd_vif_get_inargs *in,
	nf_api_control_flags flags,
	struct nf_ip4_mcfwd_vif_get_outargs *out,
	struct nf_api_resp_args *resp)
{
	struct nfapi_mr_table_t *mr_tbl;
	struct vif_device *v;

	mr_tbl = gbl_nf_ipfwd_data->mr_tbl;

	if (in->vif_id >= NF_IP4_MCFWD_MAX_VIFS)
		return -ENFILE;

	switch(in->operation) {
	case NF_IP4_MCFWD_GET_FIRST:
		if (list_empty(&mr_tbl[IPv4].vif_list))
			return -ENOENT;

		v = list_entry(mr_tbl[IPv4].vif_list.next,
			       struct vif_device,
			       vif_node);
		break;
	case NF_IP4_MCFWD_GET_NEXT:
		if (!VIF_EXISTS(&mr_tbl[IPv4], in->vif_id))
			goto out;

		v = &mr_tbl[IPv4].vif_table[in->vif_id];
		if (&mr_tbl[IPv4].vif_list != v->vif_node.next)
			v = list_entry(v->vif_node.next,
				       struct vif_device,
				       vif_node);
		break;
	case NF_IP4_MCFWD_GET_EXACT:
		if (!VIF_EXISTS(&mr_tbl[IPv4], in->vif_id))
			goto out;

		v = &mr_tbl[IPv4].vif_table[in->vif_id];

		break;
	default:
		return -ENOTSUP;
	}

	out->ip4_mcfwd_entry.link_id = v->link;
	out->ip4_mcfwd_entry.local = v->local;
	out->ip4_mcfwd_entry.remote = v->remote;
	out->ip4_mcfwd_entry.threshold = v->threshold;
	out->ip4_mcfwd_entry.vif_id =  v - mr_tbl[IPv4].vif_table;
	out->ip4_mcfwd_entry.vif_type = v->flags;
	return 0;
out:
	return -ENOENT;
}


int32_t nf_ip4_mcfwd_mfe_add(nf_ns_id nsid,
	const struct nf_ip4_mcfwd_mfentry *ip4_mcfwd_entry,
	nf_api_control_flags flags,
	struct nf_ip4_mcfwd_mfe_outargs *ip4_mcfwd_outargs,
	struct nf_api_resp_args  *ip4_mcfwd_respargs)
{
	struct nfapi_mr_table_t *mr_tbl;
	int ret, vifi;
	struct dpa_offload_lookup_key dpa_key;
	struct dpa_cls_tbl_enq_action_desc member;
	uint32_t rt_key[8];
	struct nfapi_mfc_t *mfc;
	struct __nf_mc_out out_params;
	struct vif_device *v;

	mr_tbl = gbl_nf_ipfwd_data->mr_tbl;

	/*
	 * ttl decrement header manip is created only once when a route is added
	 */
	if (__ttl == DPA_OFFLD_DESC_NONE) {
		ret = create_ttl_hhm(&__ttl);
		if (ret < 0)
			return ret;
	}

	if (ip4_mcfwd_entry->vif_id >= NF_IP4_MCFWD_MAX_VIFS)
		return -ENFILE;

	memset(rt_key, 0, sizeof(rt_key));
	memcpy(rt_key, &ip4_mcfwd_entry->src_ip, sizeof(struct in_addr));
	memcpy(&rt_key[1], &ip4_mcfwd_entry->mcastgrp, sizeof(struct in_addr));

	dpa_key.byte = (uint8_t *)rt_key;
	dpa_key.mask = NULL;
	dpa_key.size = gbl_nf_ipfwd_data->ip4_mc_route_nf_res->keysize;

	memset(&out_params, DPA_OFFLD_INVALID_OBJECT_ID, sizeof(out_params));
	/* initialize number of multicast members */
	out_params.count = 0;
	mfc = nfapi_mfc_lookup(&mr_tbl[IPv4], rt_key, sizeof(rt_key));
	/* add the route in the coresponding ccnode according to vif_id */
	if (!mfc) {
		ret = __nf_add_mfc(&dpa_key, &out_params, ip4_mcfwd_entry,
				   &member);

		if (ret < 0)
			return ret;

		mfc = nfapi_mfc_create(&mr_tbl[IPv4]);
		if (!mfc) {
			ret = __nf_remove_mfc(out_params.id, out_params.gd,
					      ip4_mcfwd_entry->vif_id);
			if (ret < 0)
				return ret;
			else
				return -ENOMEM;
		}

		mfc->mrt = &mr_tbl[IPv4];
		mfc->entry_id = out_params.id;
		mfc->td = out_params.td;
		mfc->grpd = out_params.gd;
		mfc->num_vifs = out_params.count;
		mfc->maxvif = out_params.maxvif;
		mfc->vif_id = ip4_mcfwd_entry->vif_id;

		memcpy(mfc->md, out_params.md, sizeof(out_params.md));
		memcpy(mfc->hmd, out_params.hmd, sizeof(out_params.hmd));
		memcpy(mfc->mfc_origin, &ip4_mcfwd_entry->src_ip,
			sizeof(struct in_addr));
		memcpy(mfc->mfc_mcastgrp, &ip4_mcfwd_entry->mcastgrp,
			sizeof(struct in_addr));

		list_add_tail(&mfc->mfc_node, &mr_tbl[IPv4].mfc_list);
		/* add multicast route entry in the input vif list */
		v = &mr_tbl[IPv4].vif_table[mfc->vif_id];
		list_add_tail(&mfc->mr_vif_node, &v->mr_list);


		for (vifi = 0; vifi < mr_tbl[IPv4].maxvif; vifi++) {
			if (mfc->md[vifi] >= 0) {
				v = &mr_tbl[IPv4].vif_table[vifi];
				ret = __update_group_vif(v, mfc);
				if (ret < 0)
					return ret;
			}
		}

		if (!nfapi_mfc_add(&mr_tbl[IPv4], mfc)) {
			__nf_remove_mfc(mfc->entry_id, mfc->grpd,
					ip4_mcfwd_entry->vif_id);
			list_del(&mfc->mfc_node);
			nfapi_mfc_free(mfc, &mr_tbl[IPv4]);
			return -EINVAL;
		}
	} else {
		/*
		 * if the input vif has changed, remove the mfc route from its
		 * list and add it to the new input vif list.
		 */
		if (mfc->vif_id != ip4_mcfwd_entry->vif_id) {
			/* del route from old input vif */
			list_del(&mfc->mr_vif_node);
			v = &mr_tbl[IPv4].vif_table[ip4_mcfwd_entry->vif_id];
			/* add route to new input vif */
			list_add_tail(&mfc->mr_vif_node, &v->mr_list);
			/* update the input interface */
			mfc->vif_id = ip4_mcfwd_entry->vif_id;
		}
		/*
		 * the mfc exists. update the multicast group with the new
		 * output interfaces
		 */
		ret = __nf_update_mfc(mfc, &dpa_key, ip4_mcfwd_entry, &member);
		if (ret < 0)
			return ret;
	}
	mfc->mfc_res = *ip4_mcfwd_entry;

	return 0;
}

int32_t nf_ip4_mcfwd_mfe_delete(nf_ns_id nsid,
		const struct nf_ip4_mcfwd_mfentry_del *ip4_mcfwd_entry,
		nf_api_control_flags flags,
		struct nf_ip4_mcfwd_mfe_outargs *ip4_mcfwd_outargs,
		struct nf_api_resp_args  *ip4_mcfwd_respargs)
{
	struct nfapi_mr_table_t *mr_tbl;
	int ret;
	uint32_t rt_key[8];
	struct nfapi_mfc_t *mfc;
	struct vif_device *v;
	int vifi;

	mr_tbl = gbl_nf_ipfwd_data->mr_tbl;

	memset(rt_key, 0, sizeof(rt_key));
	memcpy(rt_key, &ip4_mcfwd_entry->src_ip, sizeof(struct in_addr));
	memcpy(&rt_key[1], &ip4_mcfwd_entry->mcastgrp, sizeof(struct in_addr));

	mfc = nfapi_mfc_lookup(&mr_tbl[IPv4], rt_key, sizeof(rt_key));
	if (!mfc)
		return -ENOENT;

	v = &mr_tbl[IPv4].vif_table[mfc->vif_id];
	ret = __nf_remove_mfc(mfc->entry_id, mfc->grpd, v->link);
	if (ret < 0)
		return ret;

	/*
	 * for each multicast member (attached to the removed mfc entry),
	 * free the associated resources (fwd manips and the mfc entry
	 * subject to removal)
	 */
	for (vifi = 0; vifi < mfc->maxvif; vifi++) {
		struct vif_device *vif_dev;

		vif_dev = &mr_tbl[IPv4].vif_table[vifi];

		if (mfc->md[vifi] >= 0)
			__put_fwd_manip(vif_dev, ip4_mcfwd_entry->mcastgrp);
		__delete_group_vif(vif_dev, mfc);
	}

	/* remove the route from the route_list defined in the routing table */
	list_del(&mfc->mfc_node);
	/* remove the route from the input vif list */
	list_del(&mfc->mr_vif_node);
	ret = nfapi_mfc_remove(&mr_tbl[IPv4],rt_key, sizeof(rt_key));
	if (ret == false)
		return -EINVAL;


	return 0;
}

int32_t  nf_ip4_mcfwd_mfe_get(nf_ns_id nsid,
	const struct nf_ip4_mcfwd_mfe_get_inargs *in,
	nf_api_control_flags flags,
	struct nf_ip4_mcfwd_mfe_get_outargs *out,
	struct nf_api_resp_args *resp)
{
	struct nfapi_mr_table_t *mr_tbl;
	struct nfapi_mfc_t *mfc;
	uint32_t rt_key[8];

	mr_tbl = gbl_nf_ipfwd_data->mr_tbl;

	switch(in->operation) {
	case NF_IP4_MCFWD_GET_FIRST:
		if (list_empty(&mr_tbl[IPv4].mfc_list))
			return -ENOENT;

		mfc = list_entry(mr_tbl[IPv4].mfc_list.next,
				   struct nfapi_mfc_t, mfc_node);
		break;
	case NF_IP4_MCFWD_GET_NEXT:
		memset(rt_key, 0, sizeof(rt_key));
		memcpy(rt_key, &in->ip4_mcfwd_entry.src_ip,
			sizeof(struct in_addr));
		memcpy(&rt_key[1], &in->ip4_mcfwd_entry.mcastgrp,
			sizeof(struct in_addr));
		mfc = nfapi_mfc_lookup(&mr_tbl[IPv4], rt_key, sizeof(rt_key));
		if (!mfc)
			goto out;

		/*
		 * get the next route if the number of entries in route table
		 * is greater than 1
		 */
		if (&mr_tbl[IPv4].mfc_list != mfc->mfc_node.next)
			mfc = list_entry(mfc->mfc_node.next,
					 struct nfapi_mfc_t,
					 mfc_node);
		break;
	case NF_IP4_MCFWD_GET_EXACT:
		memset(rt_key, 0, sizeof(rt_key));
		memcpy(rt_key, &in->ip4_mcfwd_entry.src_ip,
			sizeof(struct in_addr));
		memcpy(&rt_key[1], &in->ip4_mcfwd_entry.mcastgrp,
			sizeof(struct in_addr));
		mfc = nfapi_mfc_lookup(&mr_tbl[IPv4], rt_key, sizeof(rt_key));
		if (!mfc)
			goto out;

		break;
	default:
		return -ENOTSUP;
	}

	memcpy(&out->ip4_mcfwd_entry, &mfc->mfc_res, sizeof(mfc->mfc_res));
	return 0;
out:
	return -ENOENT;
}
