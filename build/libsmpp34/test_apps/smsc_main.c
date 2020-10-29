#include <string.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>

#include <smpp34.h>

#include "smpp_smsc.h"

#define DSMPP 1

int handle_smpp_submit(struct osmo_esme *esme, struct submit_sm_t *submit,
			struct submit_sm_resp_t *submit_r)
{
	return 0;
}

static const struct log_info_cat log_info_cat[] = {
	[DSMPP] = {
		.name = "DSMPP",
		.description = "Short Message Peer-to-Peer",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static const struct log_info log_info = {
	.cat = log_info_cat,
	.num_cat = ARRAY_SIZE(log_info_cat),
};

int main(int argc, char **argv)
{
	struct smsc *smsc = talloc_zero(NULL, struct smsc);
	int rc;

	osmo_init_logging(&log_info);

	strcpy(smsc->system_id, "OpenBSC");
	rc = smpp_smsc_init(smsc, 6080);
	if (rc < 0)
		exit(1);

	while (1) {
		osmo_select_main(0);
	}
}
