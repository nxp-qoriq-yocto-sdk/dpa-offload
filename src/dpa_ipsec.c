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
 * DPA IPsec user space library implementation
 */

#include <of.h>
#include <error.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "fsl_dpa_ipsec.h"
#include "dpa_ipsec_ioctl.h"

#define DPA_IPSEC_DEV_FILE_NAME	  "/dev/dpa_ipsec"

/*
 * The device data structure is necessary so that the dpa_ipsec library
 * can translate the "fmlib" handles into FM driver handles.
 */
struct t_Device {
	uintptr_t	id;
	int		fd;
	void		*h_UserPriv;
	uint32_t	owners;
} t_Device;

static int dpa_ipsec_devfd = -1;

int dpa_ipsec_lib_init(void)
{
	if (dpa_ipsec_devfd >= 0) {
		error(0, EEXIST, "DPA IPSec library is already initialized\n");
		return -EEXIST;
	}

	dpa_ipsec_devfd = open(DPA_IPSEC_DEV_FILE_NAME, O_RDWR);

	if (dpa_ipsec_devfd < 0) {
		error(0, errno, "Could not open /dev/dpa_ipsec\n");
		return -errno;
	}

	return 0;
}

void dpa_ipsec_lib_exit(void)
{
	if (dpa_ipsec_devfd < 0)
		return;
	close(dpa_ipsec_devfd);
	dpa_ipsec_devfd = -1;
}

int dpa_ipsec_init(const struct dpa_ipsec_params *params, int *dpa_ipsec_id)
{
	struct ioc_dpa_ipsec_params prm;

	if ((!params) || (!dpa_ipsec_id)) {
		error(0, EINVAL, "Invalid input parameters\n");
		return -EINVAL;
	}

	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -ENODEV;
	}

	memset(&prm, 0, sizeof(prm));
	memcpy(&prm.dpa_ipsec_params, params, sizeof(*params));
	prm.dpa_ipsec_params.fm_pcd =
				(void *)((struct t_Device *)params->fm_pcd)->fd;

	if (ioctl(dpa_ipsec_devfd, DPA_IPSEC_IOC_INIT, &prm) < 0) {
		error(0, errno,
		      "Could not initialize the DPA IPSec instance\n");
		return -errno;
	}

	*dpa_ipsec_id = prm.dpa_ipsec_id;

	return 0;
}

int dpa_ipsec_free(int dpa_ipsec_id)
{
	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -ENODEV;
	}

	if (ioctl(dpa_ipsec_devfd, DPA_IPSEC_IOC_FREE, &dpa_ipsec_id) < 0) {
		error(0, errno, "Could not free the DPA IPSec instance\n");
		return -errno;
	}
	return 0;
}

int dpa_ipsec_create_sa(int dpa_ipsec_id, struct dpa_ipsec_sa_params *sa_params,
			int *sa_id)
{
	struct ioc_dpa_ipsec_sa_params sa_prm;

	if (!sa_params || !sa_id) {
		error(0, EINVAL, "Invalid input parameters\n");
		return -EINVAL;
	}

	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -ENODEV;
	}

	sa_prm.sa_id = DPA_OFFLD_DESC_NONE;
	sa_prm.dpa_ipsec_id = dpa_ipsec_id;
	memcpy(&sa_prm.sa_params, sa_params, sizeof(*sa_params));

	if (ioctl(dpa_ipsec_devfd, DPA_IPSEC_IOC_CREATE_SA, &sa_prm) < 0) {
		error(0, errno, "Could not create SA\n");
		return -errno;
	}

	if (sa_prm.sa_id >= 0)
		*sa_id = sa_prm.sa_id;
	return 0;
}

int dpa_ipsec_remove_sa(int sa_id)
{
	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -ENODEV;
	}

	if (ioctl(dpa_ipsec_devfd, DPA_IPSEC_IOC_REMOVE_SA, &sa_id) < 0) {
		error(0, errno, "Could not remove this SA\n");
		return -errno;
	}

	return 0;
}

int dpa_ipsec_sa_add_policy(int sa_id,
			    struct dpa_ipsec_policy_params *policy_params)
{
	struct ioc_dpa_ipsec_add_rem_policy pol_params;

	if (!policy_params) {
		error(0, EINVAL, "Invalid input parameter\n");
		return -EINVAL;
	}

	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -ENODEV;
	}

	pol_params.sa_id = sa_id;
	memcpy(&pol_params.pol_params, policy_params, sizeof(*policy_params));

	if (ioctl(dpa_ipsec_devfd, DPA_IPSEC_IOC_ADD_POLICY, &pol_params) < 0) {
		error(0, errno, "Could not add policy for this SA\n");
		return -errno;
	}

	return 0;
}

int dpa_ipsec_sa_remove_policy(int sa_id,
			       struct dpa_ipsec_policy_params *policy_params)
{
	struct ioc_dpa_ipsec_add_rem_policy pol_params;

	if (!policy_params) {
		error(0, EINVAL, "Invalid input parameter\n");
		return -EINVAL;
	}

	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -ENODEV;
	}

	pol_params.sa_id = sa_id;
	memcpy(&pol_params.pol_params, policy_params, sizeof(*policy_params));

	if (ioctl(dpa_ipsec_devfd, DPA_IPSEC_IOC_REMOVE_POLICY,
		  &pol_params) < 0) {
		error(0, errno, "Could not remove policy for this SA\n");
		return -errno;
	}

	return 0;
}

int dpa_ipsec_sa_rekeying(int sa_id,
			  struct dpa_ipsec_sa_params *sa_params,
			  dpa_ipsec_rekey_event_cb rekey_event_cb,
			  bool auto_rmv_old_sa, int *new_sa_id)
{
	struct ioc_dpa_ipsec_rekey_prm sa_rekey;

	/* unused(rekey_event_cb); */

	if (!sa_params || !new_sa_id) {
		error(0, EINVAL, "Invalid input parameter\n");
		return -EINVAL;
	}

	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -EAGAIN;
	}

	sa_rekey.sa_id = sa_id;
	sa_rekey.new_sa_id = DPA_OFFLD_DESC_NONE;
	sa_rekey.auto_rmv_old_sa = auto_rmv_old_sa;

	memcpy(&sa_rekey.sa_params, sa_params, sizeof(*sa_params));

	if (ioctl(dpa_ipsec_devfd, DPA_IPSEC_IOC_SA_REKEYING, &sa_rekey) < 0) {
		error(0, errno, "Could not rekey this SA\n");
		return -errno;
	}

	if (sa_rekey.new_sa_id >= 0)
		*new_sa_id = sa_rekey.new_sa_id;

	return 0;
}

int dpa_ipsec_flush_all_sa(int dpa_ipsec_id)
{
	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -EAGAIN;
	}

	if (ioctl(dpa_ipsec_devfd,
		  DPA_IPSEC_IOC_FLUSH_ALL_SA, &dpa_ipsec_id) < 0) {
		error(0, errno,
		      "Could not free all SAs of the DPA IPSec instance\n");
		return -errno;
	}
	return 0;
}

int dpa_ipsec_sa_get_policies(int sa_id,
			      struct dpa_ipsec_policy_params *policy_params,
			      int *num_pol)
{
	struct ioc_dpa_ipsec_get_policies ioc_prm;

	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -EAGAIN;
	}

	if (!num_pol) {
		error(0, EINVAL, "Invalid num of policies handle\n");
		return -EINVAL;
	}

	ioc_prm.sa_id = sa_id;
	ioc_prm.policy_params = policy_params;
	ioc_prm.num_pol = *num_pol;

	if (ioctl(dpa_ipsec_devfd,
		  DPA_IPSEC_IOC_GET_SA_POLICIES, &ioc_prm) < 0) {
		error(0, errno, "Could not get policies for SA %d\n", sa_id);
		return -errno;
	}

	*num_pol = ioc_prm.num_pol;

	return 0;
}

int dpa_ipsec_sa_flush_policies(int sa_id)
{
	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -EAGAIN;
	}

	if (ioctl(dpa_ipsec_devfd,
		  DPA_IPSEC_IOC_FLUSH_SA_POLICIES, &sa_id) < 0) {
		error(0, errno, "Could not flush policies for SA %d\n", sa_id);
		return -errno;
	}
	return 0;
}

int dpa_ipsec_disable_sa(int sa_id)
{
	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -EAGAIN;
	}

	if (ioctl(dpa_ipsec_devfd, DPA_IPSEC_IOC_DISABLE_SA, &sa_id) < 0) {
		error(0, errno, "Could not disable SA %d\n", sa_id);
		return -errno;
	}

	return 0;
}

int dpa_ipsec_sa_get_stats(int sa_id, struct dpa_ipsec_sa_stats *sa_stats)
{
	struct ioc_dpa_ipsec_sa_get_stats ioc_prm;

	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -EAGAIN;
	}

	if (!sa_stats) {
		error(0, EINVAL, "Invalid SA stats handle\n");
		return -EINVAL;
	}

	ioc_prm.sa_id = sa_id;

	if (ioctl(dpa_ipsec_devfd, DPA_IPSEC_IOC_GET_SA_STATS, &ioc_prm) < 0) {
		error(0, errno, "Could not get statistics for SA %d\n", sa_id);
		return -errno;
	}

	*sa_stats = ioc_prm.sa_stats;

	return 0;
}

int dpa_ipsec_get_stats(int dpa_ipsec_id, struct dpa_ipsec_stats *stats)
{
	struct ioc_dpa_ipsec_instance_stats ioc_prm;

	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -EAGAIN;
	}

	if (!stats) {
		error(0, EINVAL, "Invalid IPSec stats handle\n");
		return -EINVAL;
	}

	ioc_prm.instance_id = dpa_ipsec_id;

	if (ioctl(dpa_ipsec_devfd, DPA_IPSEC_IOC_GET_STATS, &ioc_prm) < 0) {
		error(0, errno, "Could not get IPSec global statistics.\n");
		return -errno;
	}

	memcpy(stats, &ioc_prm.stats, sizeof(*stats));

	return 0;
}

int dpa_ipsec_sa_modify(int sa_id,
			struct dpa_ipsec_sa_modify_prm *modify_prm)
{
	struct ioc_dpa_ipsec_sa_modify_prm ioc_prm;

	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -EAGAIN;
	}

	if (!modify_prm) {
		error(0, EINVAL, "Invalid SA modify handle\n");
		return -EINVAL;
	}

	ioc_prm.sa_id = sa_id;
	memcpy(&ioc_prm.modify_prm, modify_prm, sizeof(*modify_prm));

	if (ioctl(dpa_ipsec_devfd, DPA_IPSEC_IOC_SA_MODIFY, &ioc_prm) < 0) {
		error(0, errno, "Could not modify SA %d\n", sa_id);
		return -errno;
	}

	return 0;
}

int dpa_ipsec_sa_request_seq_number(int sa_id)
{
	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -EAGAIN;
	}

	if (ioctl(dpa_ipsec_devfd, DPA_IPSEC_IOC_SA_REQUEST_SEQ_NUMBER,
		  &sa_id) < 0) {
		error(0, errno, "Could not make a SEQ request SA %d\n", sa_id);
		return -errno;
	}

	return 0;
}

int dpa_ipsec_sa_get_seq_number(int sa_id, uint64_t *seq)
{
	struct ioc_dpa_ipsec_sa_get_seq_num ioc_prm;

	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -EAGAIN;
	}

	if (!seq) {
		error(0, EINVAL, "Invalid SA modify handle\n");
		return -EINVAL;
	}

	ioc_prm.sa_id = sa_id;
	ioc_prm.seq = 0;

	if (ioctl(dpa_ipsec_devfd, DPA_IPSEC_IOC_SA_GET_SEQ_NUMBER,
		  &ioc_prm) < 0) {
		error(0, errno, "Could not get SEQ NUM for SA %d\n", sa_id);
		return -errno;
	}

	*seq = ioc_prm.seq;

	return 0;
}

int dpa_ipsec_sa_get_out_path(int sa_id, uint32_t *fqid)
{
	struct ioc_dpa_ipsec_sa_get_out_path ioc_prm;

	if (dpa_ipsec_devfd < 0) {
		error(0, ENODEV, "DPA IPSec library is not initialized\n");
		return -ENODEV;
	}

	if (!fqid) {
		error(0, EINVAL, "Invalid fqid handle\n");
		return -EINVAL;
	}

	ioc_prm.sa_id = sa_id;

	if (ioctl(dpa_ipsec_devfd, DPA_IPSEC_IOC_SA_GET_OUT_PATH,
		  &ioc_prm) < 0) {
		error(0, errno, "Could not get out_path for SA %d\n", sa_id);
		return -errno;
	}

	*fqid = ioc_prm.fqid;

	return 0;
}
