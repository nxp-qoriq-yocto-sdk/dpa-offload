#ifndef __IPMR_NFAPI
#define __IPMR_NFAPI

#include <unistd.h>
#include <net/if.h>

#include <compat.h>
#include "fsl_dpa_classifier.h"

#include "ip4_mcfwd_nfapi.h"
#include "ip6_mcfwd_nfapi.h"


#define GROUP_POOL_SIZE_2EXP		(10)
#define GROUP_TABLE_BUCKETS_2EXP	(10)
#define GROUP_TABLE_MAX_ENTRIES_2EXP	(10)

#define MFC_POOL_SIZE_2EXP		(10)
#define MFC_TABLE_BUCKETS_2EXP		(10)
#define MFC_TABLE_MAX_ENTRIES_2EXP	(10)

#define MANIP_POOL_SIZE_2EXP		(10)
#define MANIP_TABLE_BUCKETS_2EXP	(10)
#define MANIP_TABLE_MAX_ENTRIES_2EXP	(10)

/* Maximum number of entries in the interface group table */
#define GROUP_TABLE_MAX_ENTRIES		(1 << GROUP_TABLE_MAX_ENTRIES_2EXP)

/* Number of buckets in the group table */
#define GROUP_TABLE_BUCKETS		(1 << GROUP_TABLE_BUCKETS_2EXP)
#define GROUP_HASH_MASK			(GROUP_TABLE_MAX_ENTRIES - 1)

/* Maximum number of groups defined in the memcache pool */
#define GROUP_POOL_SIZE			(1 << GROUP_POOL_SIZE_2EXP)

/* Maximum number of entries in the multicast routing table */
#define MFC_TABLE_MAX_ENTRIES		(1 << MFC_TABLE_MAX_ENTRIES_2EXP)

/* Number of buckets in the multicast routing table */
#define MFC_TABLE_BUCKETS		(1 << MFC_TABLE_BUCKETS_2EXP)
#define MFC_HASH_MASK			(MFC_TABLE_MAX_ENTRIES - 1)

/* Maximum number of multicast routes defined in the memcache pool */
#define MFC_POOL_SIZE			(1 << MFC_POOL_SIZE_2EXP)

/* Maximum number of entries in the manip fwd  table */
#define MANIP_TABLE_MAX_ENTRIES		(1 << MANIP_TABLE_MAX_ENTRIES_2EXP)

/* Number of buckets in the manip fwd  table table */
#define MANIP_TABLE_BUCKETS		(1 << MANIP_TABLE_BUCKETS_2EXP)
#define MANIP_HASH_MASK			(MANIP_TABLE_MAX_ENTRIES - 1)

/* Maximum number of manip elements defined in the memcache pool */
#define MANIP_POOL_SIZE			(1 << MANIP_POOL_SIZE_2EXP)


/* maximum number of multicast groups a vif device could belong to */
#define MAX_GROUPS			1024
/* multicast group entry */
struct nfapi_grp_iif_t {
	/* next group in a group table  bucket */
	struct nfapi_grp_iif_t *next;
	/* id in the classifier table */
	int entry_id;
	/* input interface*/
	uint32_t ifid;
	/* reference count */
	int users;
	uint32_t addr[NF_IPV6_ADDRU32_LEN];
	struct nfapi_grp_iif_table_t *group_tbl;

	struct list_head iif_group_node;
	union {
		struct nf_ip4_mcfwd_group iif_group;
		struct nf_ip6_mcfwd_group iif_group6;
	};
};

/* group info specific for a vif device */
struct __groups {
	struct nfapi_mfc_t *mfc;
};

struct vif_device {
	uint32_t tx_fqid;
	/* node in the vif_list */
	struct list_head vif_node;
	/* multicast entries that use this vif as source interface */
	struct list_head mr_list;
	unsigned char	threshold;
	unsigned short	flags;
	uint32_t local, remote;
	int link;
	/* number of groups a vif device could belong to */
	struct __groups groups[MAX_GROUPS];
	int users;
	int last_id;
};

struct nfapi_grp_iif_bucket_t {
	uint32_t id;
	struct nfapi_grp_iif_t *head;
};

/* multicast group entries table */
struct nfapi_grp_iif_table_t {
	struct list_head iif_group_list;
	uint32_t entries;
	int addr_len;
	struct mem_cache_t *free_entries;
	struct nfapi_grp_iif_bucket_t buckets[GROUP_TABLE_BUCKETS];
};

/* multicast route entry */
struct nfapi_mfc_t {
	/* next route entry  in a route table  bucket */
	struct nfapi_mfc_t *next;
	struct list_head mfc_node;
	/* multicast route node in a vif device */
	struct list_head mr_vif_node;
	uint32_t mfc_origin[NF_IPV6_ADDRU32_LEN];
	uint32_t mfc_mcastgrp[NF_IPV6_ADDRU32_LEN];
	/* id in the classifier table */
	int entry_id;
	struct nfapi_mr_table_t *mrt;
	/* member descriptors */
	int md[NF_IP4_MCFWD_MAX_VIFS];
	/* header manip member descriptors */
	int hmd[NF_IP4_MCFWD_MAX_VIFS];
	/* group descriptor corresponding to an entry */
	int grpd;
	/* input interface */
	int vif_id;
	/* table descriptor corresponding to a route entry */
	int td;
	/* first member(vif index) in a group */
	int first_vif;
	/* number of group members */
	int num_vifs;
	/* maximum number of members in a group */
	int maxvif;
	union {
		struct nf_ip4_mcfwd_route  mfc_res;
		struct nf_ip6_mcfwd_route mfc_res6;
	};
};

struct nfapi_mfc_bucket_t {
	uint32_t id;
	struct nfapi_mfc_t *head;
};

/* multicast routing table */
struct nfapi_mr_table_t {
	/* multicast route list */
	struct list_head mfc_list;
	/* max number of virtual interfaces */
	int maxvif;
	/* Ipv4 or Ipv6 addr len */
	int addr_len;
	/* virtual interfaces list*/
	struct list_head vif_list;
	uint32_t entries;
	struct vif_device vif_table[NF_IP4_MCFWD_MAX_VIFS];
	struct mem_cache_t *free_entries;
	struct nfapi_mfc_bucket_t buckets[MFC_TABLE_BUCKETS];
};

struct nfapi_fwd_manip_t {
	/* next manip entry  in a manip table  bucket */
	struct nfapi_fwd_manip_t *next;
	/* output interface */
	int link;
	/* header manip descriptor */
	int hmd;
	/* reference count */
	int users;
	/* destination group address*/
	uint32_t mcastgrp[NF_IPV6_ADDRU32_LEN];
	struct nfapi_fwd_manip_table_t *manip_table;
};

struct nfapi_fwd_manip_bucket_t {
	uint32_t id;
	struct nfapi_fwd_manip_t *head;
};

struct nfapi_fwd_manip_table_t {
	/* Ipv4 or Ipv6 addr len */
	int addr_len;
	uint32_t entries;
	struct mem_cache_t *free_entries;
	struct nfapi_fwd_manip_bucket_t buckets[MANIP_TABLE_BUCKETS];
};

int get_shmac_tx(char *ifname);

int set_action(int iif,  struct dpa_cls_tbl_action *act);

int nfapi_group_table_init(struct nfapi_grp_iif_table_t *gt);

void nfapi_group_free(struct nfapi_grp_iif_t *group,
		      struct nfapi_grp_iif_table_t *gt);

struct nfapi_grp_iif_t *nfapi_group_create(struct nfapi_grp_iif_table_t *gt);

bool nfapi_group_add(struct nfapi_grp_iif_table_t *gt,
		     struct nfapi_grp_iif_t *new_g);

void nfapi_group_free(struct nfapi_grp_iif_t *group,
		      struct nfapi_grp_iif_table_t *gt);

struct nfapi_grp_iif_t *nfapi_group_lookup(struct nfapi_grp_iif_table_t *grt,
					const uint32_t *key,
					uint32_t keylen);

bool nfapi_group_remove(struct nfapi_grp_iif_table_t *gt,
			uint32_t *key,
			uint32_t keylen);

int nfapi_mrt_init(struct nfapi_mr_table_t *mt);

struct nfapi_mfc_t *nfapi_mfc_create(struct nfapi_mr_table_t *mt);

bool nfapi_mfc_add(struct nfapi_mr_table_t *mt,
		    struct nfapi_mfc_t *new_res);

void nfapi_mfc_free(struct nfapi_mfc_t *mfc,
		      struct nfapi_mr_table_t *mt);

struct nfapi_mfc_t *nfapi_mfc_lookup(struct nfapi_mr_table_t *mt,
				     const uint32_t *key,
				     uint32_t keylen);

bool nfapi_mfc_remove(struct nfapi_mr_table_t *mt,
			uint32_t *key,
			uint32_t keylen);

int nfapi_manip_init(struct nfapi_fwd_manip_table_t *mt);

struct nfapi_fwd_manip_t *nfapi_manip_create(
					struct nfapi_fwd_manip_table_t *mt);

bool nfapi_manip_add(struct nfapi_fwd_manip_table_t *mt,
		    struct nfapi_fwd_manip_t *new_res);

void nfapi_manip_free(struct nfapi_fwd_manip_t *mfc,
		      struct nfapi_fwd_manip_table_t *mt);

struct nfapi_fwd_manip_t *nfapi_manip_lookup(struct nfapi_fwd_manip_table_t *mt,
				       const uint32_t *key,
				       uint32_t keylen);

bool nfapi_manip_remove(struct nfapi_fwd_manip_table_t *mt,
			uint32_t *key,
			uint32_t keylen);

#endif
