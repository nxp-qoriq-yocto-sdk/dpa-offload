/* Copyright (c) 2013 Freescale Semiconductor, Inc.
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
 * PF_KEY to DPA IPsec algos mapping table
 */
#include <linux/ipsec.h>
#include <linux/pfkeyv2.h>
#include <stdbool.h>
#include "fsl_dpa_ipsec.h"

struct dpa_alg_suite {
	int aalg;
	const char *aalg_s;
	int ealg;
	const char *ealg_s;
	int dpa_alg;
} dpa_algs[23] = {
	{
	  .aalg = SADB_AALG_SHA1HMAC,
	  .aalg_s = "hmac(sha1)",
	  .ealg = SADB_EALG_3DESCBC,
	  .ealg_s = "cbc(des3_ede)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_96_SHA_160
	},
	{
	  .aalg = SADB_AALG_MD5HMAC,
	  .aalg_s = "hmac(md5)",
	  .ealg = SADB_EALG_3DESCBC,
	  .ealg_s = "cbc(des3_ede)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_96_MD5_128
	},
	{
	  .aalg = SADB_X_AALG_SHA2_256HMAC,
	  .aalg_s = "hmac(sha256)",
	  .ealg = SADB_EALG_3DESCBC,
	  .ealg_s = "cbc(des3_ede)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_256_128
	},
	{
	  .aalg = SADB_X_AALG_SHA2_384HMAC,
	  .aalg_s = "hmac(sha384)",
	  .ealg = SADB_EALG_3DESCBC,
	  .ealg_s = "cbc(des3_ede)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_384_192
	},
	{
	  .aalg = SADB_X_AALG_SHA2_512HMAC,
	  .aalg_s = "hmac(sha512)",
	  .ealg = SADB_EALG_3DESCBC,
	  .ealg_s = "cbc(des3_ede)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_512_256
	},
	{
	  .aalg = SADB_AALG_MD5HMAC,
	  .aalg_s = "hmac(md5)",
	  .ealg = SADB_EALG_NULL,
	  .ealg_s = "ecb(cipher_null)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_96_MD5_128
	},
	{
	  .aalg = SADB_AALG_SHA1HMAC,
	  .aalg_s = "hmac(sha1)",
	  .ealg = SADB_EALG_NULL,
	  .ealg_s = "ecb(cipher_null)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_96_SHA_160
	},
	{
	  .aalg = SADB_X_AALG_SHA2_256HMAC,
	  .aalg_s = "hmac(sha256)",
	  .ealg = SADB_EALG_NULL,
	  .ealg_s = "ecb(cipher_null)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_SHA_256_128
	},
	{
	  .aalg = SADB_X_AALG_SHA2_384HMAC,
	  .aalg_s = "hmac(sha384)",
	  .ealg = SADB_EALG_NULL,
	  .ealg_s = "ecb(cipher_null)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_SHA_384_192
	},
	{
	  .aalg = SADB_X_AALG_SHA2_512HMAC,
	  .aalg_s = "hmac(sha512)",
	  .ealg = SADB_EALG_NULL,
	  .ealg_s = "ecb(cipher_null)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_NULL_ENC_HMAC_SHA_512_256
	},
	{
	  .aalg = SADB_X_AALG_AES_XCBC_MAC,
	  .aalg_s = "xcbc(aes)",
	  .ealg = SADB_EALG_NULL,
	  .ealg_s = "ecb(cipher_null)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_NULL_ENC_AES_XCBC_MAC_96
	},
	{
	  .aalg = SADB_AALG_MD5HMAC,
	  .aalg_s = "hmac(md5)",
	  .ealg = SADB_X_EALG_AESCBC,
	  .ealg_s = "cbc(aes)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_96_MD5_128
	},
	{
	  .aalg = SADB_AALG_SHA1HMAC,
	  .aalg_s = "hmac(sha1)",
	  .ealg = SADB_X_EALG_AESCBC,
	  .ealg_s = "cbc(aes)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_96_SHA_160
	},
	{
	  .aalg = SADB_X_AALG_AES_XCBC_MAC,
	  .aalg_s = "xcbc(aes)",
	  .ealg = SADB_X_EALG_AESCBC,
	  .ealg_s = "cbc(aes)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_AES_CBC_AES_XCBC_MAC_96
	},
	{
	  .aalg = SADB_X_AALG_SHA2_256HMAC,
	  .aalg_s = "hmac(sha256)",
	  .ealg = SADB_X_EALG_AESCBC,
	  .ealg_s = "cbc(aes)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_256_128
	},
	{
	  .aalg = SADB_X_AALG_SHA2_384HMAC,
	  .aalg_s = "hmac(sha384)",
	  .ealg = SADB_X_EALG_AESCBC,
	  .ealg_s = "cbc(aes)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_384_192
	},
	{
	  .aalg = SADB_X_AALG_SHA2_512HMAC,
	  .aalg_s = "hmac(sha512)",
	  .ealg = SADB_X_EALG_AESCBC,
	  .ealg_s = "cbc(aes)",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_512_256
	},
	{
	  .aalg = SADB_AALG_MD5HMAC,
	  .aalg_s = "hmac(md5)",
	  .ealg = SADB_X_EALG_AESCTR,
	  .ealg_s = "rfc3686(ctr(aes))",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_96_MD5_128
	},
	{
	  .aalg = SADB_AALG_SHA1HMAC,
	  .aalg_s = "hmac(sha1)",
	  .ealg = SADB_X_EALG_AESCTR,
	  .ealg_s = "rfc3686(ctr(aes))",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_96_SHA_160
	},
	{
	  .aalg = SADB_X_AALG_AES_XCBC_MAC,
	  .aalg_s = "xcbc(aes)",
	  .ealg = SADB_X_EALG_AESCTR,
	  .ealg_s = "rfc3686(ctr(aes))",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_AES_CTR_AES_XCBC_MAC_96
	},
	{
	  .aalg = SADB_X_AALG_SHA2_256HMAC,
	  .aalg_s = "hmac(sha256)",
	  .ealg = SADB_X_EALG_AESCTR,
	  .ealg_s = "rfc3686(ctr(aes))",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_256_128
	},
	{
	  .aalg = SADB_X_AALG_SHA2_384HMAC,
	  .aalg_s = "hmac(sha384)",
	  .ealg = SADB_X_EALG_AESCTR,
	  .ealg_s = "rfc3686(ctr(aes))",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_384_192
	},
	{
	  .aalg = SADB_X_AALG_SHA2_512HMAC,
	  .aalg_s = "hmac(sha512)",
	  .ealg = SADB_X_EALG_AESCTR,
	  .ealg_s = "rfc3686(ctr(aes))",
	  .dpa_alg = DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_512_256
	},
};
