#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/application.h>

#include "db.h"
#include "hlr.h"
#include "rand.h"
#include "logging.h"

static struct hlr *g_hlr;

static int test(const char *imsi, struct db_context *dbc)
{
	struct osmo_auth_vector vec[3];
	int rc, i;

	/* initialize all vectors with a known token pattern */
	memset(vec, 0x55, sizeof(vec));
	for (i = 0; i < ARRAY_SIZE(vec); i++)
		vec[i].res_len = 0;

	rc = db_get_auc(dbc, imsi, 0, vec, ARRAY_SIZE(vec), NULL, NULL);
	if (rc <= 0) {
		LOGP(DMAIN, LOGL_ERROR, "Cannot obtain auth tuples for '%s'\n", imsi);
		return rc;
	}
	LOGP(DMAIN, LOGL_INFO, "Obtained %u tuples for subscriber IMSI %s\n",
		rc, imsi);

	for (i = 0; i < rc; i++) {
		struct osmo_auth_vector *v = vec + i;
		LOGP(DMAIN, LOGL_DEBUG, "Tuple %u, auth_types=0x%x\n", i, v->auth_types);
		LOGP(DMAIN, LOGL_DEBUG, "RAND=%s\n", osmo_hexdump_nospc(v->rand, sizeof(v->rand)));
		LOGP(DMAIN, LOGL_DEBUG, "AUTN=%s\n", osmo_hexdump_nospc(v->autn, sizeof(v->autn)));
		LOGP(DMAIN, LOGL_DEBUG, "CK=%s\n", osmo_hexdump_nospc(v->ck, sizeof(v->ck)));
		LOGP(DMAIN, LOGL_DEBUG, "IK=%s\n", osmo_hexdump_nospc(v->ik, sizeof(v->ik)));
		LOGP(DMAIN, LOGL_DEBUG, "RES=%s\n", osmo_hexdump_nospc(v->res, v->res_len));
		LOGP(DMAIN, LOGL_DEBUG, "Kc=%s\n", osmo_hexdump_nospc(v->kc, sizeof(v->kc)));
		LOGP(DMAIN, LOGL_DEBUG, "SRES=%s\n", osmo_hexdump_nospc(v->sres, sizeof(v->sres)));
	}

	return rc;
}

int main(int argc, char **argv)
{
	int rc;

	g_hlr = talloc_zero(NULL, struct hlr);

	rc = osmo_init_logging(&hlr_log_info);
	if (rc < 0) {
		fprintf(stderr, "Error initializing logging\n");
		exit(1);
	}
	LOGP(DMAIN, LOGL_NOTICE, "hlr starting\n");

	rc = rand_init();
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Error initializing random source\n");
		exit(1);
	}

	g_hlr->dbc = db_open(NULL, "hlr.db");
	if (!g_hlr->dbc) {
		LOGP(DMAIN, LOGL_ERROR, "Error opening database\n");
		exit(1);
	}

	/* non-existing subscriber */
	rc = test("901990123456789", g_hlr->dbc);
	/* 2G only AUC data (COMP128v1 / MILENAGE) */
	rc = test("901990000000001", g_hlr->dbc);
	/* 2G + 3G AUC data (COMP128v1 / MILENAGE) */
	rc = test("901990000000002", g_hlr->dbc);
	/* 3G AUC data (MILENAGE) */
	rc = test("901990000000003", g_hlr->dbc);

	LOGP(DMAIN, LOGL_NOTICE, "Exiting\n");

	db_close(g_hlr->dbc);

	log_fini();

	exit(0);
}
