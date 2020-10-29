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

#include <sqlite3.h>

#include "logging.h"
#include "db.h"
#include "auc.h"
#include "rand.h"

#define LOGAUC(imsi, level, fmt, args ...)	LOGP(DAUC, level, "%s: " fmt, imsi, ## args)

/* update the SQN for a given subscriber ID */
int db_update_sqn(struct db_context *dbc, uint64_t id,
		      uint64_t new_sqn)
{
	sqlite3_stmt *stmt = dbc->stmt[AUC_UPD_SQN];
	int rc;

	/* bind new SQN and subscriber ID */
	rc = sqlite3_bind_int64(stmt, 1, new_sqn);
	if (rc != SQLITE_OK) {
		LOGP(DAUC, LOGL_ERROR, "Error binding SQN: %d\n", rc);
		return -1;
	}

	rc = sqlite3_bind_int64(stmt, 2, id);
	if (rc != SQLITE_OK) {
		LOGP(DAUC, LOGL_ERROR, "Error binding Subscrber ID: %d\n", rc);
		return -1;
	}

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGP(DAUC, LOGL_ERROR, "Error updating SQN: %d\n", rc);
		return -2;
	}

	/* remove bindings and reset statement to be re-executed */
	rc = sqlite3_clear_bindings(stmt);
	if (rc != SQLITE_OK) {
		LOGP(DAUC, LOGL_ERROR, "Error clerearing bindings: %d\n", rc);
	}
	rc = sqlite3_reset(stmt);
	if (rc != SQLITE_OK) {
		LOGP(DAUC, LOGL_ERROR, "Error in sqlite3_reset: %d\n", rc);
	}

	return 0;
}

/* obtain the authentication data for a given imsi
 * returns -1 in case of error, 0 for unknown IMSI, 1 for success */
int db_get_auth_data(struct db_context *dbc, const char *imsi,
		     struct osmo_sub_auth_data *aud2g,
		     struct osmo_sub_auth_data *aud3g,
		     uint64_t *subscr_id)
{
	sqlite3_stmt *stmt = dbc->stmt[AUC_BY_IMSI];
	int ret = 0;
	int rc;

	memset(aud2g, 0, sizeof(*aud2g));
	memset(aud3g, 0, sizeof(*aud3g));

	/* bind the IMSI value */
	rc = sqlite3_bind_text(stmt, 1, imsi, -1,
				SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		LOGAUC(imsi, LOGL_ERROR, "Error binding IMSI: %d\n", rc);
		ret = -1;
		goto out;
	}

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE) {
		LOGAUC(imsi, LOGL_INFO, "Unknown\n");
		ret = 0;
		goto out;
	} else if (rc != SQLITE_ROW) {
		LOGAUC(imsi, LOGL_ERROR, "Error executing SQL: %d\n", rc);
		ret = -1;
		goto out;
	}

	/* as an optimization, we retrieve the subscriber ID, to ensure we can
	 * update the SQN later without having to go back via a JOIN with the
	 * subscriber table. */
	if (subscr_id)
		*subscr_id = sqlite3_column_int64(stmt, 0);

	/* obtain result values using sqlite3_column_*() */
	if (sqlite3_column_type(stmt, 1) == SQLITE_INTEGER) {
		/* we do have some 2G authentication data */
		const uint8_t *ki;

		aud2g->algo = sqlite3_column_int(stmt, 1);
		ki = sqlite3_column_text(stmt, 2);
#if 0
		if (sqlite3_column_bytes(stmt, 2) != sizeof(aud2g->u.gsm.ki)) {
			LOGAUC(imsi, LOGL_ERROR, "Error reading Ki: %d\n", rc);
			goto end_2g;
		}
#endif
		osmo_hexparse((void*)ki, (void*)&aud2g->u.gsm.ki, sizeof(aud2g->u.gsm.ki));
		aud2g->type = OSMO_AUTH_TYPE_GSM;
	} else
		LOGAUC(imsi, LOGL_DEBUG, "No 2G Auth Data\n");
//end_2g:
	if (sqlite3_column_type(stmt, 3) == SQLITE_INTEGER) {
		/* we do have some 3G authentication data */
		const uint8_t *k, *op, *opc;

		aud3g->algo = sqlite3_column_int(stmt, 3);
		k = sqlite3_column_text(stmt, 4);
		if (!k) {
			LOGAUC(imsi, LOGL_ERROR, "Error reading K: %d\n", rc);
			goto out;
		}
		osmo_hexparse((void*)k, (void*)&aud3g->u.umts.k, sizeof(aud3g->u.umts.k));
		/* UMTS Subscribers can have either OP or OPC */
		op = sqlite3_column_text(stmt, 5);
		if (!op) {
			opc = sqlite3_column_text(stmt, 6);
			if (!opc) {
				LOGAUC(imsi, LOGL_ERROR, "Error reading OPC: %d\n", rc);
				goto out;
			}
			osmo_hexparse((void*)opc, (void*)&aud3g->u.umts.opc,
					sizeof(aud3g->u.umts.opc));
			aud3g->u.umts.opc_is_op = 0;
		} else {
			osmo_hexparse((void*)op, (void*)&aud3g->u.umts.opc,
					sizeof(aud3g->u.umts.opc));
			aud3g->u.umts.opc_is_op = 1;
		}
		aud3g->u.umts.sqn = sqlite3_column_int64(stmt, 7);
		aud3g->u.umts.ind_bitlen = sqlite3_column_int(stmt, 8);
		/* FIXME: amf? */
		aud3g->type = OSMO_AUTH_TYPE_UMTS;
	} else
		LOGAUC(imsi, LOGL_DEBUG, "No 3G Auth Data\n");

	if (aud2g->type == 0 && aud3g->type == 0)
		ret = -1;
	else
		ret = 1;

out:
	/* remove bindings and reset statement to be re-executed */
	rc = sqlite3_clear_bindings(stmt);
	if (rc != SQLITE_OK) {
		LOGAUC(imsi, LOGL_ERROR, "Error in sqlite3_clear_bindings(): %d\n", rc);
	}
	rc = sqlite3_reset(stmt);
	if (rc != SQLITE_OK) {
		LOGAUC(imsi, LOGL_ERROR, "Error in sqlite3_reset(): %d\n", rc);
	}

	return ret;
}

/* return -1 in case of error, 0 for unknown imsi, positive for number
 * of vectors generated */
int db_get_auc(struct db_context *dbc, const char *imsi,
	       unsigned int auc_3g_ind, struct osmo_auth_vector *vec,
	       unsigned int num_vec, const uint8_t *rand_auts,
	       const uint8_t *auts)
{
	struct osmo_sub_auth_data aud2g, aud3g;
	uint64_t subscr_id;
	int ret = 0;
	int rc;

	rc = db_get_auth_data(dbc, imsi, &aud2g, &aud3g, &subscr_id);
	if (rc <= 0)
		return rc;

	aud3g.u.umts.ind = auc_3g_ind;
	if (aud3g.type == OSMO_AUTH_TYPE_UMTS
	    && aud3g.u.umts.ind >= (1U << aud3g.u.umts.ind_bitlen)) {
		LOGAUC(imsi, LOGL_NOTICE, "3G auth: SQN's IND bitlen %u is"
		       " too small to hold an index of %u. Truncating. This"
		       " may cause numerous additional AUTS resyncing.\n",
		       aud3g.u.umts.ind_bitlen, aud3g.u.umts.ind);
		aud3g.u.umts.ind &= (1U << aud3g.u.umts.ind_bitlen) - 1;
	}

	LOGAUC(imsi, LOGL_DEBUG, "Calling to generate %u vectors\n", num_vec);
	rc = auc_compute_vectors(vec, num_vec, &aud2g, &aud3g, rand_auts, auts);
	if (rc < 0) {
		num_vec = 0;
		ret = -1;
	} else {
		num_vec = rc;
		ret = num_vec;
	}
	LOGAUC(imsi, LOGL_INFO, "Generated %u vectors\n", num_vec);

	/* Update SQN in database, as needed */
	if (aud3g.algo) {
		LOGAUC(imsi, LOGL_DEBUG, "Updating SQN=%" PRIu64 " in DB\n",
		       aud3g.u.umts.sqn);
		rc = db_update_sqn(dbc, subscr_id, aud3g.u.umts.sqn);
		/* don't tell caller we generated any triplets in case of
		 * update error */
		if (rc < 0) {
			LOGAUC(imsi, LOGL_ERROR, "Error updating SQN: %d\n", rc);
			num_vec = 0;
			ret = -1;
		}
	}

	return ret;
}
