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
 * @file    neigh_cmn__nfapi.h
 * @brief   This header file contains the macros which are
 *          common for ARP and ND.
 * @addtogroup  ARP
 * @{
 */

#ifndef __NF_NEIGH_CMN_H
#define __NF_NEIGH_CMN_H
#include "nfinfra_nfapi.h"

/**< Size of ethernet MAC address */
#define NF_ETHR_HWADDR_SIZE 6

/*! States for ARP and Neighbor records. */

/**< The neighbor record information is incomplete */
#define NF_NUD_STATE_INCOMPLETE BIT(0)
/**< The neighbor in the record is  reachable */
#define NF_NUD_STATE_REACHABLE  BIT(1)
/**< The neighbor record information needs  to be re-validated */
#define NF_NUD_STATE_STALE      BIT(2)
/**< Delay the revalidation of the  neighbor*/
#define NF_NUD_STATE_DELAY      BIT(3)
/**< Revalidating the neighbor information  in the record*/
#define NF_NUD_STATE_PROBE      BIT(4)
/**< The neighbor resolution has  failed */
#define NF_NUD_STATE_FAILED     BIT(5)
/**< Represents NO ARP state */
#define NF_NUD_STATE_NOARP      BIT(6)
/**< Represents a permanent neighbor  record*/
#define NF_NUD_STATE_PERMANENT  BIT(7)
/**< Represents a NONE state*/
#define NF_NUD_STATE_NONE       BIT(8)

#endif /* ifndef __NF_NEIGH_CMN_H */
/*! @} */

