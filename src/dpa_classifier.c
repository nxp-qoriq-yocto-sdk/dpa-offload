/* Copyright (c) 2011-2013 Freescale Semiconductor, Inc.
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
 * DPA Classifier user space library implementation
 */

#include <of.h>
#include <error.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "fsl_dpa_classifier.h"
#include "dpa_classifier_ioctl.h"


#define DPA_CLS_DEVICEFILENAME		"/dev/dpa_classifier"

#ifdef DPA_CLASSIFIER_DEBUG
#define dpa_cls_dbg(message) printf message
#else
#define dpa_cls_dbg(message)
#endif /* defined DPA_CLASSIFIER_DEBUG */

#define CHECK_CLASSIFIER_DEV_FD() \
	if (dpa_cls_devfd < 0) { \
		error(0, ENODEV, "ERROR %s, %s (%d): DPA Classifier library " \
			"is not initialized", __FILE__, __func__, __LINE__); \
		return -ENODEV; \
	}


/* The device data structure is necessary so that the dpa_classifier library
 * can translate the "fmlib" handles into FM driver handles. */
struct t_Device {
	uintptr_t	id;
	int		fd;
	void		*h_UserPriv;
	uint32_t	owners;
};


static inline void *dev_get_id(void *device);

static inline void *dev_get_fd(void *device);

static int dpa_cls_devfd = -1;


int dpa_classif_lib_init(void)
{
	if (dpa_cls_devfd >= 0) {
		error(0, EEXIST,
			"ERROR %s, %s (%d): DPA Classifier library is already "
			"initialized", __FILE__, __func__, __LINE__);
		return -EEXIST;
	}

	dpa_cls_devfd = open(DPA_CLS_DEVICEFILENAME, O_RDWR);

	if (dpa_cls_devfd < 0) {
		error(0, errno, "ERROR %s, %s (%d): Could not open "
			DPA_CLS_DEVICEFILENAME, __FILE__, __func__, __LINE__);
		return -errno;
	}

	return 0;
}

void dpa_classif_lib_exit(void)
{
	if (dpa_cls_devfd < 0)
		return;

	close(dpa_cls_devfd);
	dpa_cls_devfd = -1;
}

int dpa_classif_table_create(const struct dpa_cls_tbl_params *params, int *td)
{
	struct ioc_dpa_cls_tbl_params table_params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__, DPA_CLS_IOC_TBL_CREATE));

	CHECK_CLASSIFIER_DEV_FD();

	memset(&table_params, 0, sizeof(struct ioc_dpa_cls_tbl_params));
	table_params.td = DPA_OFFLD_DESC_NONE;
	memcpy(&table_params.table_params, params,
			sizeof(struct dpa_cls_tbl_params));
	/* Translate Cc node handle and FM PCD handle to FMD type of handles: */
	table_params.table_params.cc_node = dev_get_id(params->cc_node);

	if (params->distribution && params->classification) {
		table_params.table_params.distribution	=
					dev_get_id(params->distribution);
		table_params.table_params.classification =
					dev_get_id(params->classification);
	}

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_TBL_CREATE, &table_params) < 0)
		return -errno;

	if ((td) && (table_params.td != DPA_OFFLD_DESC_NONE))
		*td = table_params.td;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_free(int td)
{
	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__, DPA_CLS_IOC_TBL_FREE));

	CHECK_CLASSIFIER_DEV_FD();

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_TBL_FREE, td) < 0)
		return -errno;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_modify_miss_action(int	td,
		const struct dpa_cls_tbl_action	*miss_action)
{
	struct ioc_dpa_cls_tbl_miss_action params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__,
		DPA_CLS_IOC_TBL_MODIFY_MISS_ACTION));

	CHECK_CLASSIFIER_DEV_FD();

	if (td < 0) {
		error(0, EINVAL, "Invalid input parameter");
		return -EINVAL;
	}

	memset(&params, 0, sizeof(struct ioc_dpa_cls_tbl_miss_action));
	params.td = td;
	memcpy(&params.miss_action, miss_action,
			sizeof(struct dpa_cls_tbl_action));

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_TBL_MODIFY_MISS_ACTION,
			&params) < 0)
		return -errno;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_insert_entry(int				td,
			const struct dpa_offload_lookup_key	*key,
			const struct dpa_cls_tbl_action		*action,
			int					priority,
			int					*entry_id)
{
	struct ioc_dpa_cls_tbl_entry_params params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__,
		DPA_CLS_IOC_TBL_INSERT_ENTRY));

	if ((td < 0) || (!key) || (!action)) {
		error(0, EINVAL, "ERROR %s, %s (%d): Invalid input parameter",
			__FILE__, __func__, __LINE__);
		return -EINVAL;
	}

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_tbl_entry_params));
	params.td	= td;
	params.priority	= priority;

	memcpy(&params.key, key, sizeof(struct dpa_offload_lookup_key));
	memcpy(&params.action, action, sizeof(struct dpa_cls_tbl_action));
	if (ioctl(dpa_cls_devfd,
			DPA_CLS_IOC_TBL_INSERT_ENTRY, &params) < 0)
		return -errno;

	if (entry_id)
		*entry_id = params.entry_id;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_modify_entry_by_key(int			td,
		const struct dpa_offload_lookup_key		*key,
		const struct dpa_cls_tbl_entry_mod_params	*mod_params)
{
	struct ioc_dpa_cls_tbl_entry_mod_by_key params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__,
		DPA_CLS_IOC_TBL_MODIFY_ENTRY_BY_KEY));

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_tbl_entry_mod_by_key));
	params.td = td;

	memcpy(&params.key, key, sizeof(struct dpa_offload_lookup_key));
	memcpy(&params.mod_params, mod_params,
			sizeof(struct dpa_cls_tbl_entry_mod_params));

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_TBL_MODIFY_ENTRY_BY_KEY,
			&params) < 0)
		return -errno;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_modify_entry_by_ref(int			td,
		int						entry_id,
		const struct dpa_cls_tbl_entry_mod_params	*mod_params)
{
	struct ioc_dpa_cls_tbl_entry_mod_by_ref params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__,
		DPA_CLS_IOC_TBL_MODIFY_ENTRY_BY_REF));

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0,
			sizeof(struct ioc_dpa_cls_tbl_entry_mod_by_ref));
	params.td	= td;
	params.entry_id	= entry_id;
	memcpy(&params.mod_params, mod_params,
			sizeof(struct dpa_cls_tbl_entry_mod_params));

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_TBL_MODIFY_ENTRY_BY_REF,
			&params) < 0)
		return -errno;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_delete_entry_by_key(int				td,
				const struct dpa_offload_lookup_key	*key)
{
	struct ioc_dpa_cls_tbl_entry_by_key params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__,
		DPA_CLS_IOC_TBL_DELETE_ENTRY_BY_KEY));

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_tbl_entry_by_key));
	params.td = td;
	memcpy(&params.key, key, sizeof(struct dpa_offload_lookup_key));

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_TBL_DELETE_ENTRY_BY_KEY,
			&params) < 0)
		return -errno;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_delete_entry_by_ref(int td, int entry_id)
{
	struct ioc_dpa_cls_tbl_entry_by_ref params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__,
		DPA_CLS_IOC_TBL_DELETE_ENTRY_BY_REF));

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_tbl_entry_by_ref));
	params.td	= td;
	params.entry_id	= entry_id;

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_TBL_DELETE_ENTRY_BY_REF,
			&params) < 0)
		return -errno;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_lookup_by_key(int					td,
				const struct dpa_offload_lookup_key	*key,
				struct dpa_cls_tbl_action		*action)
{
	struct ioc_dpa_cls_tbl_lookup_by_key params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__,
		DPA_CLS_IOC_TBL_LOOKUP_BY_KEY));

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_tbl_lookup_by_key));
	params.td = td;
	memcpy(&params.key, key, sizeof(struct dpa_offload_lookup_key));

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_TBL_LOOKUP_BY_KEY, &params) < 0)
		return -errno;
	else
		memcpy(action, &params.action,
			sizeof(struct dpa_cls_tbl_action));

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_lookup_by_ref(int				td,
				    int				entry_id,
				    struct dpa_cls_tbl_action	*action)
{
	struct ioc_dpa_cls_tbl_lookup_by_ref params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__,
		DPA_CLS_IOC_TBL_LOOKUP_BY_REF));

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_tbl_lookup_by_ref));
	params.td	= td;
	params.entry_id	= entry_id;

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_TBL_LOOKUP_BY_REF, &params) < 0)
		return -errno;
	else
		memcpy(action, &params.action,
			sizeof(struct dpa_cls_tbl_action));

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_flush(int td)
{
	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__, DPA_CLS_IOC_TBL_FLUSH));

	CHECK_CLASSIFIER_DEV_FD();

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_TBL_FLUSH, td) < 0)
		return -errno;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_get_entry_stats_by_key(int			td,
				const struct dpa_offload_lookup_key	*key,
				struct dpa_cls_tbl_entry_stats		*stats)
{
	struct ioc_dpa_cls_tbl_entry_stats_by_key params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__,
		DPA_CLS_IOC_TBL_GET_STATS_BY_KEY));

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_tbl_entry_stats_by_key));
	params.td	= td;
	memcpy(&params.key, key, sizeof(struct dpa_offload_lookup_key));

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_TBL_GET_STATS_BY_KEY,
			&params) < 0)
		return -errno;
	else
		memcpy(stats, &params.stats,
			sizeof(struct dpa_cls_tbl_entry_stats));

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_get_entry_stats_by_ref(int		td,
				int				entry_id,
				struct dpa_cls_tbl_entry_stats	*stats)
{
	struct ioc_dpa_cls_tbl_entry_stats_by_ref params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__,
		DPA_CLS_IOC_TBL_GET_STATS_BY_REF));

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_tbl_entry_stats_by_ref));
	params.td	= td;
	params.entry_id	= entry_id;

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_TBL_GET_STATS_BY_REF, &params) < 0)
		return -errno;
	else
		memcpy(stats, &params.stats,
			sizeof(struct dpa_cls_tbl_entry_stats));

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_get_miss_stats(int			td,
				struct dpa_cls_tbl_entry_stats	*stats)
{
	struct ioc_dpa_cls_tbl_miss_stats params;

	dpa_cls_dbg((
		"DEBUG: dpa_classifier_lib %s (%d): --> Executing ioctl=0x%x\n",
		__func__, __LINE__, DPA_CLS_IOC_TBL_GET_MISS_STATS));

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_tbl_miss_stats));
	params.td	= td;

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_TBL_GET_MISS_STATS, &params) < 0)
		return -errno;
	else
		memcpy(stats, &params.stats,
			sizeof(struct dpa_cls_tbl_entry_stats));

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_table_get_params(int td, struct dpa_cls_tbl_params *params)
{
	struct ioc_dpa_cls_tbl_params table_params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__,
		DPA_CLS_IOC_TBL_GET_PARAMS));

	CHECK_CLASSIFIER_DEV_FD();

	memset(&table_params, 0,
			sizeof(struct ioc_dpa_cls_tbl_params));
	table_params.td = td;

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_TBL_GET_PARAMS, &table_params) < 0)
		return -errno;
	else
		memcpy(params, &table_params.table_params,
				sizeof(struct dpa_cls_tbl_params));

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_set_remove_hm(const struct dpa_cls_hm_remove_params
		*remove_params, int next_hmd, int *hmd, bool chain_head,
		const struct dpa_cls_hm_remove_resources *res)
{
	struct ioc_dpa_cls_hm_remove_params params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__, DPA_CLS_IOC_SET_REMOVE_HM));

	*hmd = DPA_OFFLD_DESC_NONE;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0,
		sizeof(struct ioc_dpa_cls_hm_remove_params));
	params.hmd = DPA_OFFLD_DESC_NONE;
	params.next_hmd = next_hmd;
	params.chain_head = chain_head;
	memcpy(&params.rm_params, remove_params,
		sizeof(struct dpa_cls_hm_remove_params));

	if ((res) && (res->remove_node))
		params.res.remove_node = dev_get_id(res->remove_node);
	else
		params.rm_params.fm_pcd = dev_get_fd(params.rm_params.fm_pcd);

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_SET_REMOVE_HM, &params) < 0)
		return -errno;

	if (params.hmd != DPA_OFFLD_DESC_NONE)
		*hmd = params.hmd;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_modify_remove_hm(int hmd,
	const struct dpa_cls_hm_remove_params *new_remove_params,
	int modify_flags)
{
	struct ioc_dpa_cls_hm_remove_params params;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_hm_remove_params));
	memcpy(&params.rm_params, new_remove_params,
		sizeof(struct dpa_cls_hm_remove_params));
	params.hmd = hmd;
	params.modify_flags = modify_flags;

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_MODIFY_REMOVE_HM, &params) < 0)
		return -errno;

	return 0;

}

int dpa_classif_set_insert_hm(const struct dpa_cls_hm_insert_params
		*insert_params, int next_hmd, int *hmd, bool chain_head,
		const struct dpa_cls_hm_insert_resources *res)
{
	struct ioc_dpa_cls_hm_insert_params params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__, DPA_CLS_IOC_SET_INSERT_HM));

	*hmd = DPA_OFFLD_DESC_NONE;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0,
		sizeof(struct ioc_dpa_cls_hm_insert_params));
	params.hmd = DPA_OFFLD_DESC_NONE;
	params.next_hmd = next_hmd;
	params.chain_head = chain_head;
	memcpy(&params.ins_params, insert_params,
		sizeof(struct dpa_cls_hm_insert_params));

	if ((res) && (res->insert_node))
		params.res.insert_node = dev_get_id(res->insert_node);
	else
		params.ins_params.fm_pcd = dev_get_fd(params.ins_params.fm_pcd);

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_SET_INSERT_HM, &params) < 0)
		return -errno;

	if (params.hmd != DPA_OFFLD_DESC_NONE)
		*hmd = params.hmd;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_modify_insert_hm(int hmd,
	const struct dpa_cls_hm_insert_params *new_insert_params,
	int modify_flags)
{
	struct ioc_dpa_cls_hm_insert_params params;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_hm_insert_params));
	memcpy(&params.ins_params, new_insert_params,
		sizeof(struct dpa_cls_hm_insert_params));
	params.hmd = hmd;
	params.modify_flags = modify_flags;

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_MODIFY_INSERT_HM, &params) < 0)
		return -errno;

	return 0;

}

int dpa_classif_set_vlan_hm(const struct dpa_cls_hm_vlan_params
		*vlan_params, int next_hmd, int *hmd, bool chain_head,
		const struct dpa_cls_hm_vlan_resources	*res)
{
	struct ioc_dpa_cls_hm_vlan_params params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__, DPA_CLS_IOC_SET_VLAN_HM));

	*hmd = DPA_OFFLD_DESC_NONE;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0,
		sizeof(struct ioc_dpa_cls_hm_vlan_params));
	params.hmd = DPA_OFFLD_DESC_NONE;
	params.next_hmd = next_hmd;
	params.chain_head = chain_head;
	memcpy(&params.vlan_params, vlan_params,
			sizeof(struct dpa_cls_hm_vlan_params));

	if ((res) && (res->vlan_node))
		params.res.vlan_node = dev_get_id(res->vlan_node);
	else
		params.vlan_params.fm_pcd = dev_get_fd(
						params.vlan_params.fm_pcd);

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_SET_VLAN_HM, &params) < 0)
		return -errno;

	if (params.hmd != DPA_OFFLD_DESC_NONE)
		*hmd = params.hmd;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_modify_vlan_hm(int hmd,
	const struct dpa_cls_hm_vlan_params *new_vlan_params, int modify_flags)
{
	struct ioc_dpa_cls_hm_vlan_params params;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_hm_vlan_params));
	memcpy(&params.vlan_params, new_vlan_params,
		sizeof(struct dpa_cls_hm_vlan_params));
	params.hmd = hmd;
	params.modify_flags = modify_flags;

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_MODIFY_VLAN_HM, &params) < 0)
		return -errno;

	return 0;
}

int dpa_classif_set_nat_hm(const struct dpa_cls_hm_nat_params	*nat_params,
			int					next_hmd,
			int					*hmd,
			bool					chain_head,
			const struct dpa_cls_hm_nat_resources	*res)
{
	struct ioc_dpa_cls_hm_nat_params params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__, DPA_CLS_IOC_SET_NAT_HM));

	*hmd = DPA_OFFLD_DESC_NONE;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_hm_nat_params));
	params.hmd = DPA_OFFLD_DESC_NONE;
	params.next_hmd = next_hmd;
	params.chain_head = chain_head;
	memcpy(&params.nat_params, nat_params,
		sizeof(struct dpa_cls_hm_nat_params));

	if (res) {
		if (res->l3_update_node)
			params.res.l3_update_node =
						dev_get_id(res->l3_update_node);
		if (res->l4_update_node)
			params.res.l4_update_node =
						dev_get_id(res->l4_update_node);
	} else
		params.nat_params.fm_pcd = dev_get_fd(params.nat_params.fm_pcd);

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_SET_NAT_HM, &params) < 0)
		return -errno;

	if (params.hmd != DPA_OFFLD_DESC_NONE)
		*hmd = params.hmd;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_modify_nat_hm(int hmd,
	const struct dpa_cls_hm_nat_params *new_nat_params, int modify_flags)
{
	struct ioc_dpa_cls_hm_nat_params params;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_hm_nat_params));
	memcpy(&params.nat_params, new_nat_params,
		sizeof(struct dpa_cls_hm_nat_params));
	params.hmd = hmd;
	params.modify_flags = modify_flags;

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_MODIFY_NAT_HM, &params) < 0)
		return -errno;

	return 0;
}

int dpa_classif_set_update_hm(const struct dpa_cls_hm_update_params
		*update_params, int next_hmd, int *hmd, bool chain_head,
		const struct dpa_cls_hm_update_resources *res)
{
	struct ioc_dpa_cls_hm_update_params params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__, DPA_CLS_IOC_SET_UPDATE_HM));

	*hmd = DPA_OFFLD_DESC_NONE;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_hm_update_params));
	params.hmd = DPA_OFFLD_DESC_NONE;
	params.next_hmd = next_hmd;
	params.chain_head = chain_head;
	memcpy(&params.update_params, update_params,
		sizeof(struct dpa_cls_hm_update_params));

	if (res) {
		if (res->update_node)
			params.res.update_node = dev_get_id(res->update_node);
		if (res->ip_frag_node)
			params.res.ip_frag_node = dev_get_id(res->ip_frag_node);
	} else
		params.update_params.fm_pcd =
					dev_get_fd(params.update_params.fm_pcd);

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_SET_UPDATE_HM, &params) < 0)
		return -errno;

	if (params.hmd != DPA_OFFLD_DESC_NONE)
		*hmd = params.hmd;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_modify_update_hm(int hmd,
	const struct dpa_cls_hm_update_params *new_update_params,
	int modify_flags)
{
	struct ioc_dpa_cls_hm_update_params params;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_hm_update_params));
	memcpy(&params.update_params, new_update_params,
		sizeof(struct dpa_cls_hm_update_params));
	params.hmd = hmd;
	params.modify_flags = modify_flags;

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_MODIFY_UPDATE_HM, &params) < 0)
		return -errno;

	return 0;
}

int dpa_classif_set_fwd_hm(const struct dpa_cls_hm_fwd_params	*fwd_params,
			int					next_hmd,
			int					*hmd,
			bool					chain_head,
			const struct dpa_cls_hm_fwd_resources	*res)
{
	struct ioc_dpa_cls_hm_fwd_params params;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__, DPA_CLS_IOC_SET_FWD_HM));

	*hmd = DPA_OFFLD_DESC_NONE;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_hm_fwd_params));
	params.hmd = DPA_OFFLD_DESC_NONE;
	params.next_hmd = next_hmd;
	params.chain_head = chain_head;
	memcpy(&params.fwd_params, fwd_params,
		sizeof(struct dpa_cls_hm_fwd_params));

	if (res) {
		if (res->fwd_node)
			params.res.fwd_node = dev_get_id(res->fwd_node);
		if (res->pppoe_node)
			params.res.pppoe_node = dev_get_id(res->pppoe_node);
		if (res->ip_frag_node)
			params.res.ip_frag_node = dev_get_id(res->ip_frag_node);
	} else
		params.fwd_params.fm_pcd = dev_get_fd(params.fwd_params.fm_pcd);

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_SET_FWD_HM, &params) < 0)
		return -errno;

	if (params.hmd != DPA_OFFLD_DESC_NONE)
		*hmd = params.hmd;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_modify_fwd_hm(int hmd,
	const struct dpa_cls_hm_fwd_params *new_fwd_params, int modify_flags)
{
	struct ioc_dpa_cls_hm_fwd_params params;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_hm_fwd_params));
	memcpy(&params.fwd_params, new_fwd_params,
		sizeof(struct dpa_cls_hm_fwd_params));
	params.hmd = hmd;
	params.modify_flags = modify_flags;

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_MODIFY_FWD_HM, &params) < 0)
		return -errno;

	return 0;
}

int dpa_classif_set_mpls_hm(const struct dpa_cls_hm_mpls_params	*mpls_params,
			int					next_hmd,
			int					*hmd,
			bool					chain_head,
			const struct dpa_cls_hm_mpls_resources	*res)
{
	struct ioc_dpa_cls_hm_mpls_params params;

	*hmd = DPA_OFFLD_DESC_NONE;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_hm_mpls_params));
	params.hmd = DPA_OFFLD_DESC_NONE;
	params.next_hmd = next_hmd;
	params.chain_head = chain_head;
	memcpy(&params.mpls_params, mpls_params,
		sizeof(struct dpa_cls_hm_mpls_params));

	if ((res) && (res->ins_rm_node))
		params.res.ins_rm_node = dev_get_id(res->ins_rm_node);
	else
		params.mpls_params.fm_pcd =
					  dev_get_fd(params.mpls_params.fm_pcd);

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_SET_MPLS_HM, &params) < 0)
		return -errno;

	if (params.hmd != DPA_OFFLD_DESC_NONE)
		*hmd = params.hmd;

	return 0;
}

int dpa_classif_modify_mpls_hm(int hmd,
	const struct dpa_cls_hm_mpls_params *new_mpls_params, int modify_flags)
{
	struct ioc_dpa_cls_hm_mpls_params params;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_hm_mpls_params));
	memcpy(&params.mpls_params, new_mpls_params,
		sizeof(struct dpa_cls_hm_mpls_params));
	params.hmd = hmd;
	params.modify_flags = modify_flags;

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_MODIFY_MPLS_HM, &params) < 0)
		return -errno;

	return 0;
}

int dpa_classif_free_hm(int hmd)
{
	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): --> Executing "
		"ioctl=0x%x\n", __func__, __LINE__, DPA_CLS_IOC_FREE_HM));

	CHECK_CLASSIFIER_DEV_FD();

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_FREE_HM, hmd) < 0)
		return -errno;

	dpa_cls_dbg(("DEBUG: dpa_classifier_lib %s (%d): <-- Done\n", __func__,
		__LINE__));

	return 0;
}

int dpa_classif_mcast_create_group(
		const struct dpa_cls_mcast_group_params *group_params,
		int *grpd,
		const struct dpa_cls_mcast_group_resources *res)
{
	struct ioc_dpa_cls_mcast_group_params params;
	void *distribution, *classification;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_mcast_group_params));
	memcpy(&params.mcast_grp_params, group_params,
		sizeof(struct dpa_cls_mcast_group_params));
	params.grpd = DPA_OFFLD_DESC_NONE;
	if (res && (res->group_node))
		params.res.group_node = dev_get_id(res->group_node);
	else
		params.mcast_grp_params.fm_pcd = dev_get_fd(params.
						       mcast_grp_params.fm_pcd);

	distribution = params.mcast_grp_params.distribution;
	classification = params.mcast_grp_params.classification;
	if (distribution && classification) {
		params.mcast_grp_params.distribution = dev_get_id(distribution);
		params.mcast_grp_params.classification =
						     dev_get_id(classification);
	}

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_MCAST_CREATE_GROUP, &params) < 0)
		return -errno;

	if (params.grpd != DPA_OFFLD_DESC_NONE)
		*grpd = params.grpd;

	return 0;
}

int dpa_classif_mcast_add_member(int grpd,
		const struct dpa_cls_tbl_enq_action_desc *member_params,
		int *membrd)
{
	struct ioc_dpa_cls_mcast_member_params params;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_mcast_member_params));
	memcpy(&params.member_params, member_params,
		sizeof(struct dpa_cls_tbl_enq_action_desc));
	params.grpd = grpd;
	params.md = DPA_OFFLD_DESC_NONE;

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_MCAST_ADD_MEMBER, &params) < 0)
		return -errno;

	if (params.md != DPA_OFFLD_DESC_NONE)
		*membrd = params.md;

	return 0;
}

int dpa_classif_mcast_remove_member(int grpd, int membrd)
{
	struct ioc_dpa_cls_mcast_remove_params params;

	CHECK_CLASSIFIER_DEV_FD();

	memset(&params, 0, sizeof(struct ioc_dpa_cls_mcast_remove_params));
	params.grpd = grpd;
	params.md = membrd;

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_MCAST_REMOVE_MEMBER, &params) < 0)
		return -errno;

	return 0;
}

int dpa_classif_mcast_free_group(int grpd)
{
	CHECK_CLASSIFIER_DEV_FD();

	if (ioctl(dpa_cls_devfd, DPA_CLS_IOC_MCAST_FREE_GROUP, &grpd) < 0)
		return -errno;

	return 0;
}

static inline void *dev_get_id(void *device)
{
	struct t_Device *dev = (struct t_Device *)device;

	if (!dev) {
		error(0, ENODEV, "ERROR %s, %s (%d): Failed to translate a "
				"NULL device Id", __FILE__, __func__, __LINE__);
		return NULL;
	}

	return (void *)dev->id;
}

static inline void *dev_get_fd(void *device)
{
	struct t_Device *dev = (struct t_Device *)device;

	if (!dev) {
		error(0, ENODEV, "ERROR %s, %s (%d): Failed to translate a "
				"NULL device", __FILE__, __func__, __LINE__);
		return NULL;
	}

	return (void *)dev->fd;
}
