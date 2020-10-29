/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <string.h>
#include <inttypes.h>

#include <osmocom/core/utils.h>
#include <osmocom/crypt/auth.h>

#include "logging.h"
#include "rand.h"

#define hexb(buf) osmo_hexdump_nospc((void*)buf, sizeof(buf))
#define hex(buf,sz) osmo_hexdump_nospc((void*)buf, sz)

/* compute given number of vectors using either aud2g or aud2g or a combination
 * of both.  Handles re-synchronization if rand_auts and auts are set */
int auc_compute_vectors(struct osmo_auth_vector *vec, unsigned int num_vec,
			struct osmo_sub_auth_data *aud2g,
			struct osmo_sub_auth_data *aud3g,
			const uint8_t *rand_auts, const uint8_t *auts)
{
	unsigned int i;
	uint8_t rand[16];
	struct osmo_auth_vector vtmp;
	int rc;

	/* no need to iterate the log categories all the time */
	int dbg = log_check_level(DAUC, LOGL_DEBUG);
#define DBGP(args ...) if (dbg) DEBUGP(DAUC, ##args)
#define DBGVB(member) DBGP("vector [%u]: " #member " = %s\n", \
			   i, hexb(vec[i].member))
#define DBGVV(fmt, member) DBGP("vector [%u]: " #member " = " fmt "\n", \
			        i, vec[i].member)

	if (aud2g && (aud2g->algo == OSMO_AUTH_ALG_NONE
		      || aud2g->type == OSMO_AUTH_TYPE_NONE))
		aud2g = NULL;
	if (aud3g && (aud3g->algo == OSMO_AUTH_ALG_NONE
		      || aud3g->type == OSMO_AUTH_TYPE_NONE))
		aud3g = NULL;

	if (!aud2g && !aud3g) {
		LOGP(DAUC, LOGL_ERROR, "auc_compute_vectors() called"
		     " with neither 2G nor 3G auth data available\n");
		return -1;
	}

	if (aud2g && aud2g->type != OSMO_AUTH_TYPE_GSM) {
		LOGP(DAUC, LOGL_ERROR, "auc_compute_vectors() called"
		     " with non-2G auth data passed for aud2g arg\n");
		return -1;
	}

	if (aud3g && aud3g->type != OSMO_AUTH_TYPE_UMTS) {
		LOGP(DAUC, LOGL_ERROR, "auc_compute_vectors() called"
		     " with non-3G auth data passed for aud3g arg\n");
		return -1;
	}

	if ((rand_auts != NULL) != (auts != NULL)) {
		LOGP(DAUC, LOGL_ERROR, "auc_compute_vectors() with only one"
		     " of AUTS and AUTS_RAND given, need both or neither\n");
		return -1;
	}

	if (auts && !aud3g) {
		LOGP(DAUC, LOGL_ERROR, "auc_compute_vectors() with AUTS called"
		     " but no 3G auth data passed\n");
		return -1;
	}

	DBGP("Computing %d auth vector%s: %s%s\n",
	     num_vec, num_vec == 1 ? "" : "s",
	     aud3g? (aud2g? "3G + separate 2G"
		     : "3G only (2G derived from 3G keys)")
	     : "2G only",
	     auts? ", with AUTS resync" : "");
	if (aud3g) {
		DBGP("3G: k = %s\n", hexb(aud3g->u.umts.k));
		DBGP("3G: %s = %s\n",
		     aud3g->u.umts.opc_is_op? "OP" : "opc",
		     hexb(aud3g->u.umts.opc));
		DBGP("3G: for sqn ind %u, previous sqn was %" PRIu64 "\n",
		     aud3g->u.umts.ind, aud3g->u.umts.sqn);
	}
	if (aud2g)
		DBGP("2G: ki = %s\n", hexb(aud2g->u.gsm.ki));

	for (i = 0; i < num_vec; i++) {
		rc = rand_get(rand, sizeof(rand));
		if (rc != sizeof(rand)) {
			LOGP(DAUC, LOGL_ERROR, "Unable to read %zu random "
			     "bytes: rc=%d\n", sizeof(rand), rc);
			goto out;
		}
		DBGP("vector [%u]: rand = %s\n", i, hexb(rand));

		if (aud3g) {
			/* 3G or 3G + 2G case */

			/* Do AUTS only for the first vector or we would use
			 * the same SQN for each following key. */
			if ((i == 0) && auts) {
				DBGP("vector [%u]: resync: auts = %s\n",
				     i, hex(auts, 14));
				DBGP("vector [%u]: resync: rand_auts = %s\n",
				     i, hex(rand_auts, 16));

				rc = osmo_auth_gen_vec_auts(vec+i, aud3g, auts,
							    rand_auts, rand);
			} else {
				rc = osmo_auth_gen_vec(vec+i, aud3g, rand);
			}
			if (rc < 0) {
				LOGP(DAUC, LOGL_ERROR, "Error in 3G vector "
				     "generation: [%u]: rc = %d\n", i, rc);
				goto out;
			}
			DBGP("vector [%u]: sqn = %" PRIu64 "\n",
			     i, aud3g->u.umts.sqn);

			DBGVB(autn);
			DBGVB(ck);
			DBGVB(ik);
			DBGVB(res);
			DBGVV("%u", res_len);

			if (!aud2g) {
				/* use the 2G tokens from 3G keys */
				DBGVB(kc);
				DBGVB(sres);
				DBGVV("0x%x", auth_types);
				continue;
			}
			/* calculate 2G separately */

			DBGP("vector [%u]: deriving 2G from 3G\n", i);

			rc = osmo_auth_gen_vec(&vtmp, aud2g, rand);
			if (rc < 0) {
				LOGP(DAUC, LOGL_ERROR, "Error in 2G vector"
				     "generation: [%u]: rc = %d\n", i, rc);
				goto out;
			}
			memcpy(&vec[i].kc, vtmp.kc, sizeof(vec[i].kc));
			memcpy(&vec[i].sres, vtmp.sres, sizeof(vec[i].sres));
			vec[i].auth_types |= OSMO_AUTH_TYPE_GSM;
		} else {
			/* 2G only case */
			rc = osmo_auth_gen_vec(vec+i, aud2g, rand);
			if (rc < 0) {
				LOGP(DAUC, LOGL_ERROR, "Error in 2G vector "
				     "generation: [%u]: rc = %d\n", i, rc);
				goto out;
			}
		}

		DBGVB(kc);
		DBGVB(sres);
		DBGVV("0x%x", auth_types);
	}
out:
	return i;
#undef DBGVV
#undef DBGVB
#undef DBGP
}
