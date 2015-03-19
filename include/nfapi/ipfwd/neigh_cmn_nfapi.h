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

/*!< Size of ethernet MAC address */
#define NF_ETHR_HWADDR_SIZE 6

/*! States for ARP and Neighbor records. */

/*!< The neighbor record information is incomplete */
#define NF_NUD_STATE_INCOMPLETE BIT(0)
/*!< The neighbor in the record is  reachable */
#define NF_NUD_STATE_REACHABLE  BIT(1)
/*!< The neighbor record information needs  to be re-validated */
#define NF_NUD_STATE_STALE      BIT(2)
/*!< Delay the revalidation of the  neighbor*/
#define NF_NUD_STATE_DELAY      BIT(3)
/*!< Revalidating the neighbor information  in the record*/
#define NF_NUD_STATE_PROBE      BIT(4)
/*!< The neighbor resolution has  failed */
#define NF_NUD_STATE_FAILED     BIT(5)
/*!< Represents NO ARP state */
#define NF_NUD_STATE_NOARP      BIT(6)
/*!< Represents a permanent neighbor  record*/
#define NF_NUD_STATE_PERMANENT  BIT(7)
/*!< Represents a NONE state*/
#define NF_NUD_STATE_NONE       BIT(8)

#endif /* ifndef __NF_NEIGH_CMN_H */
/*! @} */

