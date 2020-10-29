#pragma once

#include <stdbool.h>
#include <sqlite3.h>

enum stmt_idx {
	SEL_BY_IMSI		= 0,
	UPD_VLR_BY_ID		= 1,
	UPD_SGSN_BY_ID		= 2,
	AUC_BY_IMSI		= 3,
	AUC_UPD_SQN		= 4,
	UPD_PURGE_CS_BY_IMSI	= 5,
	UPD_PURGE_PS_BY_IMSI	= 6,
	SET_NAM_PS_BY_IMSI	= 7,
	UNSET_NAM_PS_BY_IMSI	= 8,
	_NUM_STMT
};

struct db_context {
	char *fname;
	sqlite3 *db;
	sqlite3_stmt *stmt[_NUM_STMT];
};

bool db_remove_reset(sqlite3_stmt *stmt);
bool db_bind_imsi(sqlite3_stmt *stmt, const char *imsi);
void db_close(struct db_context *dbc);
struct db_context *db_open(void *ctx, const char *fname);

#include <osmocom/crypt/auth.h>

/* obtain the authentication data for a given imsi */
int db_get_auth_data(struct db_context *dbc, const char *imsi,
		     struct osmo_sub_auth_data *aud2g,
		     struct osmo_sub_auth_data *aud3g,
		     uint64_t *suscr_id);

int db_update_sqn(struct db_context *dbc, uint64_t id,
		      uint64_t new_sqn);

int db_get_auc(struct db_context *dbc, const char *imsi,
	       unsigned int auc_3g_ind, struct osmo_auth_vector *vec,
	       unsigned int num_vec, const uint8_t *rand_auts,
	       const uint8_t *auts);

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>

/* TODO: Get this from somewhere? */
#define GT_MAX_DIGITS	15

struct hlr_subscriber {
	struct llist_head list;

	uint64_t	id;
	char		imsi[GSM23003_IMSI_MAX_DIGITS+1];
	char		msisdn[GT_MAX_DIGITS+1];
	/* imeisv? */
	char		vlr_number[GT_MAX_DIGITS+1];
	char		sgsn_number[GT_MAX_DIGITS+1];
	char		sgsn_address[GT_MAX_DIGITS+1];
	/* ggsn number + address */
	/* gmlc number */
	/* smsc number */
	uint32_t	periodic_lu_timer;
	uint32_t	periodic_rau_tau_timer;
	bool		nam_cs;
	bool		nam_ps;
	uint32_t	lmsi;
	bool		ms_purged_cs;
	bool		ms_purged_ps;
};

int db_subscr_get(struct db_context *dbc, const char *imsi,
		  struct hlr_subscriber *subscr);
int db_subscr_ps(struct db_context *dbc, const char *imsi, bool enable);
int db_subscr_lu(struct db_context *dbc,
		 const struct hlr_subscriber *subscr,
		 const char *vlr_or_sgsn_number,
		 bool lu_is_ps);

int db_subscr_purge(struct db_context *dbc,
		const char *imsi, bool is_ps);
