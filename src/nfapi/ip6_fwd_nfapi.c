#include <stdint.h>
#include <errno.h>

#include "fsl_dpa_offload.h"
#include "fsl_dpa_classifier.h"

#include "ipfwd.h"
#include "ip6_fwd_nfapi.h"
#include "fib_nfapi.h"
#include "rule_nfapi.h"

/* IPv6 route key : IP Dest + TC (IP Source always masked)*/
static inline void mk_route_key(uint8_t *rt_key, uint8_t *rt_mask, int keysize,
				const struct nf_ip6_fwd_route_entry *rt_entry,
				struct dpa_offload_lookup_key *dpa_key)
{
	uint8_t *dst;
	uint8_t sz;
	uint16_t tos;

	memset(rt_key, 0, keysize);
	memset(rt_mask, 0, keysize);
	sz = sizeof(rt_entry->dst_addr.b_addr);
	/* jump over source address part - not involved in route */
	dst = rt_key + sz;
	memcpy(dst, rt_entry->dst_addr.b_addr, sz);
	dst += sz;

	tos = rt_entry->tc << 4;
	memcpy(dst, &tos, sizeof(tos));

	dst = rt_mask + sizeof(rt_entry->dst_mask);
	memcpy(dst, rt_entry->dst_mask, sizeof(rt_entry->dst_mask));

	dst += sizeof(rt_entry->dst_mask);

	/* ip ver - 4 bits ; tos - 8 bits; last -4 bits (total 16 bits) */
	if (rt_entry->tc) {
		*dst++ = 0x0F;
		*dst = 0xF0;
	}

	dpa_key->byte = rt_key;
	dpa_key->mask = rt_mask;
	dpa_key->size = keysize;
}

/* IPv6 rule key : IP Source + IP Dest + TC */
static inline void mk_rule_key(uint8_t *rl_key, uint8_t *rl_mask, int keysize,
				const void  *pbr_rule,
				struct dpa_offload_lookup_key *dpa_key,
				bool add_rule)
{
	uint8_t *dst;
	uint8_t sz;
	uint16_t tos;

	memset(rl_key, 0, keysize);
	memset(rl_mask, 0, keysize);
	if (add_rule) {
		struct nf_ip6_fwd_pbr_rule *pbr_rule_prm =
					 (struct nf_ip6_fwd_pbr_rule *)pbr_rule;
		sz = sizeof(pbr_rule_prm->dst_addr.b_addr);
		dst = rl_key;
		memcpy(dst, pbr_rule_prm->src_addr.b_addr, sz);
		dst += sz;
		memcpy(dst, pbr_rule_prm->dst_addr.b_addr, sz);
		dst += sz;

		tos = pbr_rule_prm->tc << 4;
		memcpy(dst, &tos, sizeof(tos));

		dst = rl_mask;
		memcpy(dst, pbr_rule_prm->smask, sizeof(pbr_rule_prm->smask));
		dst += sizeof(pbr_rule_prm->smask);
		memcpy(dst, pbr_rule_prm->dst_mask,
		       sizeof(pbr_rule_prm->dst_mask));
		dst += sizeof(pbr_rule_prm->dst_mask);

		/* ip ver - 4 bits ; tos - 8 bits; last -4 bits(total 16 bits)*/
		if (pbr_rule_prm->tc) {
			*dst++ = 0x0F;
			*dst = 0xF0;
		}
	} else {
		struct nf_ip6_fwd_pbr_rule_del *pbr_rule_prm =
				     (struct nf_ip6_fwd_pbr_rule_del *)pbr_rule;
		sz = sizeof(pbr_rule_prm->dst_addr.b_addr);
		dst = rl_key;
		memcpy(dst, pbr_rule_prm->src_addr.b_addr, sz);
		dst += sz;
		memcpy(dst, pbr_rule_prm->dst_addr.b_addr, sz);
		dst += sz;

		tos = pbr_rule_prm->tc << 4;
		memcpy(dst, &tos, sizeof(tos));

		dst = rl_mask;
		memcpy(dst, pbr_rule_prm->smask, sizeof(pbr_rule_prm->smask));
		dst += sizeof(pbr_rule_prm->smask);
		memcpy(dst, pbr_rule_prm->dst_mask,
		       sizeof(pbr_rule_prm->dst_mask));
		dst += sizeof(pbr_rule_prm->dst_mask);

		/* ip ver - 4 bits ; tos - 8 bits; last -4 bits(total 16 bits)*/
		if (pbr_rule_prm->tc) {
			*dst++ = 0x0F;
			*dst = 0xF0;
		}
	}
	dpa_key->byte = rl_key;
	dpa_key->mask = rl_mask;
	dpa_key->size = keysize;
}

/* Add a route entry to the corresponding cc_route table descriptor */
static inline int __nf_add_route(struct dpa_offload_lookup_key *dpa_key,
				 struct dpa_cls_tbl_action *act,
				 int prio, int *id,
				 struct nfapi_neigh_t *neigh,
				 int table_id)
{
	struct nf_ipfwd_cc *nf_cc;
	int i, j, ret, td, rt_table_no;
	bool entry = false;

	memset(act, 0, sizeof(*act));
	act->type = DPA_CLS_TBL_ACTION_ENQ;
	act->enable_statistics = false;
	act->enq_params.hmd = DPA_OFFLD_INVALID_OBJECT_ID;
	act->enq_params.override_fqid = false;

	for (i = 0; i < gbl_nf_ipfwd_data->ip6fwd_route_nf_res->num_td; i++) {
		nf_cc = &gbl_nf_ipfwd_data->ip6fwd_route_nf_res->nf_cc[i];
		rt_table_no = nf_cc->action.rt_table_no;
		if (table_id == rt_table_no) {
			td = nf_cc->td;
			if (neigh->tx_fqid)
				act->enq_params.override_fqid = true;
			act->enq_params.hmd = neigh->hmd[0];
			act->enq_params.new_fqid = neigh->tx_fqid;
			ret = dpa_classif_table_insert_entry(td, dpa_key,
							     act, prio, id);
			entry = true;
			if (ret < 0)
				goto out;
		}
	}

	if (!entry)
		return -ENOENT;
	else
		return 0;

out:
	for (j = 0; j < i; j++) {
		nf_cc = &gbl_nf_ipfwd_data->ip6fwd_route_nf_res->nf_cc[j];
		td = nf_cc->td;
		rt_table_no = nf_cc->action.rt_table_no;
		if (table_id == rt_table_no)
			dpa_classif_table_delete_entry_by_ref(td, *id);
	}

	return ret;
}

/* Remove a route entry from all route offload tables */
static inline int __nf_remove_route(int id, int table_id)
{
	struct nf_ipfwd_cc *nf_cc;
	int i, td, ret = 0, rt_table_no;
	for (i = 0; i < gbl_nf_ipfwd_data->ip6fwd_route_nf_res->num_td; i++) {
		nf_cc = &gbl_nf_ipfwd_data->ip6fwd_route_nf_res->nf_cc[i];
		td = nf_cc->td;
		rt_table_no = nf_cc->action.rt_table_no;
		if (rt_table_no == table_id)
			ret += dpa_classif_table_delete_entry_by_ref(td, id);
	}
	return ret;
}

/* Set the rule action to the ccroute table corresponding to table_id. */
static inline int set_rule_action(int table_id,
		struct dpa_cls_tbl_action *act)
{
	int i;
	int rt_table_no;
	int act_type;
	uint32_t fqid;
	int td;

	memset(act, 0, sizeof(*act));
	act->enable_statistics = false;
	act->enq_params.hmd = DPA_OFFLD_INVALID_OBJECT_ID;
	for (i = 0; i < gbl_nf_ipfwd_data->ip6fwd_route_nf_res->num_td; i++) {
		rt_table_no = gbl_nf_ipfwd_data->ip6fwd_route_nf_res->nf_cc[i].action.rt_table_no;
		act_type = gbl_nf_ipfwd_data->ip6fwd_route_nf_res->nf_cc[i].action.type;
		td = gbl_nf_ipfwd_data->ip6fwd_route_nf_res->nf_cc[i].td;
		fqid = gbl_nf_ipfwd_data->ip6fwd_route_nf_res->nf_cc[i].action.fq.fqid;
		if (rt_table_no == table_id) {
			if (act_type == DPA_CLS_TBL_ACTION_ENQ) {
				act->type = act_type;
				act->enq_params.override_fqid = true;
				act->enq_params.new_fqid = fqid;
			} else {
				act->type = DPA_CLS_TBL_ACTION_NEXT_TABLE;
				act->next_table_params.next_td = td;
			}
			return 0;
		}
	}

	return -ENOENT;
}

/* Add a rule entry to all relevant rule offload tables.
 * When an input interface is specified in rule arguments,
 * the entry is inserted only in the corresponding port table */
static inline int __nf_add_rule(struct dpa_offload_lookup_key *dpa_key,
		struct dpa_cls_tbl_action *act,
		int prio, int *id, int in_ifid, int table_id)
{
	int i, j, ret, td;
	bool entry = false;

	ret = set_rule_action(table_id, act);

	if (ret < 0)
		return ret;

	for (i = 0; i < gbl_nf_ipfwd_data->ip6fwd_rule_nf_res->num_td; i++) {
		/* if input interface was specified add entry
		   only in the corresponding table */
		if (in_ifid &&
				gbl_nf_ipfwd_data->ip6fwd_rule_nf_res->nf_cc[i].ifid != in_ifid)
			continue;

		entry = true;
		td = gbl_nf_ipfwd_data->ip6fwd_rule_nf_res->nf_cc[i].td;
		ret = dpa_classif_table_insert_entry(td, dpa_key,
				act, prio, id);
		if (ret < 0)
			goto out;
	}
	if (entry)
		return 0;
	else
		return -ENOENT;

out:
	for (j = 0; j < i; j++) {
		if (in_ifid &&
				gbl_nf_ipfwd_data->ip6fwd_rule_nf_res->nf_cc[j].ifid != in_ifid)
			continue;
		td = gbl_nf_ipfwd_data->ip6fwd_rule_nf_res->nf_cc[j].td;
		dpa_classif_table_delete_entry_by_ref(td, *id);
	}
	return ret;
}

/* Remove a rule entry from the relevant rule offload tables.
 * When an input interface is specified in rule arguments,
 * the entry is removed only from the corresponding port rule table */
static inline int __nf_remove_rule(struct dpa_offload_lookup_key *dpa_key,
		int in_ifid)
{
	int i, td, ret = 0;
	for (i = 0; i < gbl_nf_ipfwd_data->ip6fwd_rule_nf_res->num_td; i++) {
		if (in_ifid &&
				gbl_nf_ipfwd_data->ip6fwd_rule_nf_res->nf_cc[i].ifid != in_ifid)
			continue;
		td = gbl_nf_ipfwd_data->ip6fwd_rule_nf_res->nf_cc[i].td;
		ret += dpa_classif_table_delete_entry_by_key(td, dpa_key);
	}
	return ret;
}

int32_t nf_ip6_fwd_route_add(nf_ns_id ns_id,
		const struct nf_ip6_fwd_route_entry *new_rt_entry_data,
		nf_api_control_flags flags,
		struct nf_ip6_fwd_route_outargs *ip6_out_args,
		struct nf_api_resp_args  *ip6_fwd_route_respargs)
{
	int id, ret;
	struct nfapi_fib_hash_table_t *fib_htbl;
	struct nfapi_neigh_table_t *neigh_tbl;
	struct nfapi_neigh_t *neigh;
	const uint32_t *nh_addr;
	struct dpa_offload_lookup_key dpa_key;
	struct dpa_cls_tbl_action def_action;
	uint8_t rt_key[gbl_nf_ipfwd_data->ip6fwd_route_nf_res->keysize],
		rt_mask[gbl_nf_ipfwd_data->ip6fwd_route_nf_res->keysize];
	struct nfapi_rt_id *rt_id;
	struct nfapi_fib_table_t *fib_table;
	uint32_t neigh_key[5];
	int idx;

	neigh_tbl = gbl_nf_ipfwd_data->neigh_tbl;
	fib_htbl = gbl_nf_ipfwd_data->fib_htbl;

	memset(neigh_key, 0, sizeof(neigh_key));
	mk_route_key(rt_key, rt_mask, gbl_nf_ipfwd_data->ip6fwd_route_nf_res->keysize,
			new_rt_entry_data, &dpa_key);

	/* try to bind route to ARP  */
	nh_addr = (new_rt_entry_data->gw_info[0]).gw_ipaddr.w_addr;
	memcpy(neigh_key, nh_addr, sizeof(struct in6_addr));
	idx = (sizeof(struct in6_addr) / sizeof(neigh_key[0]));
	memcpy(neigh_key + idx, &new_rt_entry_data->gw_info[0].out_ifid,
			sizeof(new_rt_entry_data->gw_info[0].out_ifid));
	neigh = nfapi_neigh_lookup(&neigh_tbl[IPv6], neigh_key,
			sizeof(neigh_key));
	/* no ARP entry for this route's nexthop, create the neighbor */
	if (!neigh) {
		neigh = nfapi_neigh_create(&neigh_tbl[IPv6]);
		if (!neigh)
			return -ENOMEM;
		nfapi_neigh_init(&neigh_tbl[IPv6], neigh, neigh_key);
		if (!nfapi_neigh_add(&neigh_tbl[IPv6], neigh)) {
			neigh_free(neigh, &neigh_tbl[IPv6]);
			return -ENOMEM;
		}
	}

	ret = __nf_add_route(&dpa_key, &def_action,
			new_rt_entry_data->priority, &id, neigh,
			new_rt_entry_data->rt_table_id);
	if (ret < 0) {
		nfapi_neigh_remove(&neigh_tbl[IPv6], neigh_key,
				sizeof(neigh_key));
		neigh_free(neigh, &neigh_tbl[IPv6]);
		return ret;
	}
	/* neighbour is used by this route */
	neigh->refcnt++;

	/* create fib_table which will hold the routes */
	fib_table = nfapi_fib_table_lookup(&fib_htbl[IPv6],
			&new_rt_entry_data->rt_table_id,
			sizeof(new_rt_entry_data->rt_table_id));
	if (!fib_table) {
		fib_table = nfapi_fib_table_create(&fib_htbl[IPv6]);
		if (!fib_table)
			return -ENOMEM;

		nfapi_fib_table_init(&fib_htbl[IPv6], fib_table,
				&new_rt_entry_data->rt_table_id, AF_INET6);
		if (!nfapi_fib_table_add(&fib_htbl[IPv6], fib_table)) {
			nfapi_fib_table_free(fib_table, &fib_htbl[IPv6]);
			return -ENOMEM;
		}
	}

	/* add route entry id on the neighbour list and in the fib_table*/
	rt_id = nfapi_rt_create(&neigh_tbl[IPv6]);
	if (!rt_id) {
		__nf_remove_route(id, new_rt_entry_data->rt_table_id);
		return -ENOMEM;
	}
	nfapi_rt_init(&neigh_tbl[IPv6], rt_id);
	rt_id->rt_id = id;
	rt_id->rt_entry6 = *new_rt_entry_data;
	list_add_tail(&rt_id->route_node, &fib_table->route_list);

	if(!nfapi_rt_add(&neigh_tbl[IPv6], neigh, fib_table, rt_id)) {
		__nf_remove_route(id, new_rt_entry_data->rt_table_id);
		list_del(&rt_id->route_node);
		nfapi_rt_free(rt_id, &neigh_tbl[IPv6]);
		return -EINVAL;
	}

	return ret;
}

int32_t nf_ip6_fwd_route_get(nf_ns_id nsid,
		const struct nf_ip6_fwd_route_get_inargs *in,
		nf_api_control_flags flags,
		struct nf_ip6_fwd_route_get_outargs *out,
		struct nf_api_resp_args *resp)
{
	struct nfapi_fib_table_t *fib_table;
	struct nfapi_rt_id *rt_id;
	uint32_t key[9];

	if (!in)
		return -EINVAL;

	/* find the routing table with id  route_table_id */
	fib_table = nfapi_fib_table_lookup(&gbl_nf_ipfwd_data->fib_htbl[IPv6],
			&in->route_table_id,
			sizeof(in->route_table_id));
	if (!fib_table)
		goto out;

	/* if there are no entries in the route table, exit */
	if (!fib_table->entries)
		goto out;

	switch(in->operation) {
		case NF_IP6_FWD_ROUTE_GET_FIRST:
			if (list_empty(&fib_table->route_list))
				return -ENOENT;

			rt_id = list_entry(fib_table->route_list.next,
					struct nfapi_rt_id, route_node);
			break;
		case NF_IP6_FWD_ROUTE_GET_NEXT:
			memset(key, 0, sizeof(key));
			memcpy(&key[4], in->route_in_params.dst_addr.w_addr,
					sizeof(struct in6_addr));
			memcpy(&key[8], &in->route_in_params.tc, sizeof(uint8_t));
			/* get the route with dest addr from the route table */
			rt_id = nfapi_rt_lookup(fib_table, key, sizeof(key));
			if (unlikely(!rt_id))
				goto out;

			/*
			 * get the next route if the number of entries in route table
			 * is greater than 1
			 */
			if (&fib_table->route_list != rt_id->route_node.next)
				rt_id = list_entry(rt_id->route_node.next,
						struct nfapi_rt_id,
						route_node);
			break;
		case NF_IP6_FWD_ROUTE_GET_EXACT:
			memset(key, 0, sizeof(key));
			memcpy(&key[4], in->route_in_params.dst_addr.w_addr,
					sizeof(struct in6_addr));
			memcpy(&key[8], &in->route_in_params.tc, sizeof(uint8_t));
			rt_id = nfapi_rt_lookup(fib_table, key, sizeof(key));
			if (unlikely(!rt_id))
				goto out;
			break;
		default:
			return -ENOTSUP;
	}

	memcpy(&out->route_out_params, &rt_id->rt_entry6,
			sizeof(struct nf_ip6_fwd_route_entry));
	return 0;
out:
	return -ENOENT;
}

int32_t nf_ip6_fwd_route_delete(nf_ns_id ns_id,
		const struct nf_ip6_fwd_route_entry_del *rt_entry_data,
		nf_api_control_flags flags,
		struct nf_ip6_fwd_route_outargs *ip6_out_args,
		struct nf_api_resp_args  *ip6_fwd_route_respargs)
{
	struct nfapi_fib_hash_table_t *fib_htbl;
	struct nfapi_rt_id *curr;
	struct nfapi_fib_table_t *fib_table;
	int ret;
	uint32_t key[9];
	uint32_t neigh_key[5];
	int idx;

	fib_htbl = gbl_nf_ipfwd_data->fib_htbl;

	/* find the route table */
	fib_table = nfapi_fib_table_lookup(&fib_htbl[IPv6],
			&rt_entry_data->rt_table_id,
			sizeof(rt_entry_data->rt_table_id));
	if (!fib_table)
		return -ENOENT;

	memset(key, 0, sizeof(key));
	memcpy(&key[4], rt_entry_data->dst_addr.w_addr,
			sizeof(struct in6_addr));
	memcpy(&key[8], &rt_entry_data->tc, sizeof(uint8_t));

	/* search for the route in the routing table */
	curr = nfapi_rt_lookup(fib_table, key, sizeof(key));

	if (unlikely(!curr))
		return -ENOENT;

	if (unlikely(!curr->neigh))
		return -EINVAL;

	/* remove the route from the route ccnode */
	ret = __nf_remove_route(curr->rt_id, rt_entry_data->rt_table_id);
	if (ret < 0)
		return ret;

	/*
	 * remove the route from the route linked list - used to identify
	 * first or the next element relative to curr
	 */
	list_del(&curr->route_node);
	curr->neigh->refcnt--;
	/* last reference , remove the neighbour */
	if (!curr->neigh->refcnt) {
		memset(neigh_key, 0, sizeof(neigh_key));
		memcpy(neigh_key, curr->neigh->ip_address,
				sizeof(struct in6_addr));
		idx = (sizeof(struct in6_addr) / sizeof(neigh_key[0]));
		memcpy(neigh_key + idx, &curr->neigh->ifid,
				sizeof(curr->neigh->ifid));
		nfapi_neigh_remove(&gbl_nf_ipfwd_data->neigh_tbl[IPv6],
				neigh_key, sizeof(neigh_key));
	}

	/* remove the route from the route table */
	nfapi_rt_remove(fib_table, key, sizeof(key));

	/* remove the fib table if there are no more routes */
	if (!fib_table->entries)
		nfapi_fib_table_remove(&fib_htbl[IPv6],
				&rt_entry_data->rt_table_id,
				sizeof(rt_entry_data->rt_table_id));

	return 0;
}

/* delete route from neigh route list */
static struct nfapi_rt_id *__neigh_del_rt(struct nfapi_neigh_table_t *nt,
		struct nfapi_neigh_t *n,
		struct nfapi_rt_id *rt_id)
{
	struct nfapi_rt_id *curr, *prev;
	if (!nt || !n)
		return NULL;

	for (curr = n->rt_list_head, prev = NULL; curr; curr = curr->next) {
		if (curr == rt_id) {
			if (curr == n->rt_list_head)
				n->rt_list_head = curr->next;
			else
				prev->next = curr->next;
			if (curr == n->rt_list_tail)
				n->rt_list_tail = prev;
			break;
		}
		prev = curr;
	}
	return curr;
}

static int __modify_route(struct nfapi_neigh_t *neigh,
		int rt_id, int rt_table_no)
{
	struct nf_ipfwd_cc *nf_cc;
	struct dpa_cls_tbl_action act;
	struct dpa_cls_tbl_entry_mod_params mod_params;
	int i, ret = 0, td, table_id;
	bool entry = false;

	memset(&act, 0, sizeof(struct dpa_cls_tbl_action));
	memset(&mod_params, 0, sizeof(struct dpa_cls_tbl_entry_mod_params));

	act.enq_params.override_fqid = false;
	act.enq_params.hmd = neigh->hmd[0];
	act.type = DPA_CLS_TBL_ACTION_ENQ;
	if (neigh->tx_fqid)
		act.enq_params.override_fqid = true;
	act.enq_params.new_fqid = neigh->tx_fqid;

	mod_params.type = DPA_CLS_TBL_MODIFY_ACTION;
	mod_params.action = &act;

	for (i = 0; i < gbl_nf_ipfwd_data->ip6fwd_route_nf_res->num_td; i++) {
		nf_cc = & gbl_nf_ipfwd_data->ip6fwd_route_nf_res->nf_cc[i];
		table_id = nf_cc->action.rt_table_no;
		if (table_id == rt_table_no) {
			td = nf_cc->td;
			ret += dpa_classif_table_modify_entry_by_ref(td, rt_id,
								   &mod_params);
			entry = true;
		}
	}

	if (!entry)
		return -ENOENT;
	else
		return ret;
}

int32_t nf_ip6_fwd_route_modify(nf_ns_id ns_id,
		const struct nf_ip6_fwd_route_entry_mod *rt_entry_data,
		nf_api_control_flags flags,
		struct nf_ip6_fwd_route_outargs *ip6_out_args,
		struct nf_api_resp_args  *ip6_fwd_route_respargs)
{
	const uint32_t *nh_addr;
	struct nfapi_neigh_table_t *neigh_tbl;
	struct nfapi_neigh_t *neigh;
	struct nfapi_rt_id *curr;
	struct nfapi_fib_table_t *fib_table;
	uint32_t key[9];
	uint32_t neigh_key[5];
	int idx, ret;

	neigh_tbl = gbl_nf_ipfwd_data->neigh_tbl;

	memset(neigh_key, 0, sizeof(neigh_key));

	/* find the route table */
	fib_table = nfapi_fib_table_lookup(&gbl_nf_ipfwd_data->fib_htbl[IPv6],
					&rt_entry_data->rt_table_id,
					sizeof(rt_entry_data->rt_table_id));
	if (!fib_table)
		return -ENOENT;

	memset(key, 0, sizeof(key));
	memcpy(&key[4], rt_entry_data->dst_addr.w_addr,
		sizeof(struct in6_addr));
	memcpy(&key[8], &rt_entry_data->tc, sizeof(uint8_t));

	/* search for the route in the routing table */
	curr = nfapi_rt_lookup(fib_table, key, sizeof(key));

	if (!curr)
		return -ENOENT;

	nh_addr = (rt_entry_data->gw_info[0]).gw_ipaddr.w_addr;
	/* check if the gw of the route has changed and should be updated */
	if (memcmp(curr->neigh->ip_address, nh_addr, sizeof(struct in6_addr))
	    || curr->neigh->ifid != rt_entry_data->gw_info[0].out_ifid) {
		memcpy(neigh_key, nh_addr, sizeof(struct in6_addr));
		idx = (sizeof(struct in6_addr) / sizeof(neigh_key[0]));
		memcpy(neigh_key + idx, &rt_entry_data->gw_info[0].out_ifid,
			sizeof(rt_entry_data->gw_info[0].out_ifid));
		neigh = nfapi_neigh_lookup(&neigh_tbl[IPv6], nh_addr,
					   sizeof(neigh_key));
		/* no ARP entry for this route's nexthop, create the neighbor */
		if (!neigh) {
			neigh = nfapi_neigh_create(&neigh_tbl[IPv6]);
			if (!neigh)
				return -ENOMEM;

			nfapi_neigh_init(&neigh_tbl[IPv6], neigh, neigh_key);
			if (!nfapi_neigh_add(&neigh_tbl[IPv6], neigh)) {
				neigh_free(neigh, &neigh_tbl[IPv6]);
				return -ENOMEM;
			}
		}

		/* delete the route from the old neigh route list */
		if (!__neigh_del_rt(&neigh_tbl[IPv6], curr->neigh, curr))
			return -EINVAL;

		/* neigh is no longer referenced by the route */
		curr->neigh->refcnt--;
		/* last reference , remove the neighbour */
		if (!curr->neigh->refcnt) {
			memset(neigh_key, 0, sizeof(neigh_key));
			memcpy(neigh_key, curr->neigh->ip_address,
				sizeof(struct in6_addr));
			idx = (sizeof(struct in6_addr) / sizeof(neigh_key[0]));
			memcpy(neigh_key + idx, &curr->neigh->ifid,
			       sizeof(curr->neigh->ifid));
			nfapi_neigh_remove(&neigh_tbl[IPv6], neigh_key,
					   sizeof(neigh_key));
		}

		/* add the route to the new neigh route list */
		if (!neigh->rt_list_head)
			neigh->rt_list_head = curr;
		if (neigh->rt_list_tail)
			neigh->rt_list_tail->next = curr;
		neigh->rt_list_tail = curr;
		curr->neigh = neigh;
		ret = __modify_route(curr->neigh, curr->rt_id,
				     curr->rt_entry6.rt_table_id);
		if (ret)
			return ret;

		neigh->refcnt++;
	}

	/* update route entry for the current route with the new values */
	memcpy(&curr->rt_entry6, rt_entry_data,
		sizeof(struct nf_ip6_fwd_route_entry));

	return 0;
}

int32_t nf_ip6_fwd_pbr_rule_add(nf_ns_id ns_id,
		const struct nf_ip6_fwd_pbr_rule *new_pbr_rule,
		nf_api_control_flags flags,
		struct nf_ip6_fwd_rule_outargs *ip6_out_args,
		struct nf_api_resp_args  *ip6_fwd_pbr_respargs)
{

	struct dpa_offload_lookup_key dpa_key;
	struct dpa_cls_tbl_action def_action;
	uint8_t rl_key[gbl_nf_ipfwd_data->ip6fwd_rule_nf_res->keysize],
		rl_mask[gbl_nf_ipfwd_data->ip6fwd_rule_nf_res->keysize];
	struct nfapi_rule_table_t *rule_tbl;
	struct nfapi_rule_t *rule;
	uint32_t priority;
	int id, ret;

	rule_tbl = gbl_nf_ipfwd_data->rule_tbl;

	mk_rule_key(rl_key, rl_mask, gbl_nf_ipfwd_data->ip6fwd_rule_nf_res->keysize,
		    new_pbr_rule, &dpa_key, true);
	/* insert the rule in the rule ccnode */
	ret = __nf_add_rule(&dpa_key, &def_action, new_pbr_rule->priority, &id,
			    new_pbr_rule->in_ifid, new_pbr_rule->rt_table_no);

	if (ret < 0)
		return ret;

	/* create and add a rule to the rule hash table */
	rule = nfapi_rule_create(&rule_tbl[IPv6]);
	if (!rule) {
		__nf_remove_rule(&dpa_key, new_pbr_rule->in_ifid);
		return -ENOMEM;
	}
	priority = new_pbr_rule->priority;
	rule->rule_entry6 =  *new_pbr_rule;
	nfapi_rule_init(&rule_tbl[IPv6], rule, &priority);

	if (!nfapi_rule_add(&rule_tbl[IPv6], rule)) {
		__nf_remove_rule(&dpa_key, new_pbr_rule->in_ifid);
		nfapi_rule_free(rule, &rule_tbl[IPv6]);
		return -ENOMEM;
	}

	list_add_tail(&rule->rule_node, &rule_tbl[IPv6].rule_list);

	return 0;
}

int32_t nf_ip6_fwd_pbr_rule_delete(nf_ns_id ns_id,
		const struct nf_ip6_fwd_pbr_rule_del *pbr_rule,
		nf_api_control_flags flags,
		struct nf_ip6_fwd_rule_outargs *ip6_out_args,
		struct nf_api_resp_args  *ip6_fwd_pbr_respargs)
{
	struct dpa_offload_lookup_key dpa_key;
	uint8_t rl_key[gbl_nf_ipfwd_data->ip6fwd_rule_nf_res->keysize],
		rl_mask[gbl_nf_ipfwd_data->ip6fwd_rule_nf_res->keysize];
	struct nfapi_rule_table_t *rule_tbl;
	struct nfapi_rule_t * rule;
	uint32_t priority;
	int ret;

	rule_tbl = gbl_nf_ipfwd_data->rule_tbl;
	priority = pbr_rule->priority;

	rule = nfapi_rule_lookup(&rule_tbl[IPv6],
				 &priority,
				 sizeof(priority));
	if (!rule)
		return -ENOENT;

	mk_rule_key(rl_key, rl_mask, gbl_nf_ipfwd_data->ip6fwd_rule_nf_res->keysize,
		   pbr_rule, &dpa_key, false);
	/* remove the rule form the rule cccnode */
	ret = __nf_remove_rule(&dpa_key, pbr_rule->in_ifid);
	if (ret < 0)
		return ret;

	list_del(&rule->rule_node);

	/* remove the rule from the rule hash table */
	nfapi_rule_remove(&rule_tbl[IPv6], &priority, sizeof(priority));

	return 0;
}

int32_t nf_ip6_fwd_pbr_get(nf_ns_id nsid,
		      const struct nf_ip6_fwd_pbr_get_inargs *in,
		      nf_api_control_flags flags,
		      struct nf_ip6_fwd_pbr_get_outargs *out,
		      struct nf_api_resp_args *resp)
{
	struct nfapi_rule_table_t *rule_tbl;
	struct nfapi_rule_t *rule = NULL;

	rule_tbl = gbl_nf_ipfwd_data->rule_tbl;

	if (!in)
		return -EINVAL;

	switch(in->operation) {
	case NF_IP6_FWD_PBR_GET_FIRST:
		if (list_empty(&rule_tbl[IPv6].rule_list))
			return -ENOENT;

		rule = list_entry(rule_tbl[IPv6].rule_list.next,
				   struct nfapi_rule_t, rule_node);
		break;
	case NF_IP6_FWD_PBR_GET_NEXT:
		/* find the rule with given priority */
		rule = nfapi_rule_lookup(&rule_tbl[IPv6],
					&in->priority,
					sizeof(in->priority));


		if (!rule)
			goto out;
		/*
		 * get the next rule if the number of entries in rule table
		 * is greater than 1
		 */
		if (&rule_tbl[IPv6].rule_list != rule->rule_node.next)
			rule = list_entry(rule->rule_node.next,
					  struct nfapi_rule_t,
					  rule_node);
		break;
	case NF_IP6_FWD_PBR_GET_EXACT:
		/* find the rule with given priority */
		rule = nfapi_rule_lookup(&rule_tbl[IPv6],
					&in->priority,
					sizeof(in->priority));


		if (!rule)
			goto out;
		break;
	default:
		return -ENOTSUP;
	}

	memcpy(&out->pbr_rule_params, &rule->rule_entry6,
		sizeof(struct nf_ip6_fwd_pbr_rule));
	return 0;
out:
	return -ENOENT;
}


