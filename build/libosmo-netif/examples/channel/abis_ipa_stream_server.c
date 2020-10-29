#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

#include <osmocom/netif/channel.h>
#include <osmocom/netif/channel/abis_ipa_server.h>

static void *tall_example;

#define DEXAMPLE 0

struct log_info_cat example_cat[] = {
	[DEXAMPLE] = {
		.name = "DEXAMPLE",
		.description = "example",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

const struct log_info example_log_info = {
	.filter_fn = NULL,
	.cat = example_cat,
	.num_cat = ARRAY_SIZE(example_cat),
};

void sighandler(int foo)
{
	LOGP(DEXAMPLE, LOGL_NOTICE, "closing test.\n");
	exit(EXIT_SUCCESS);
}

static void signal_msg_cb(struct msgb *msg, int type)
{
	LOGP(DEXAMPLE, LOGL_NOTICE, "received signal message\n");
}

static struct osmo_chan *chan;

int main(void)
{
	tall_example = talloc_named_const(NULL, 1, "example");

	osmo_init_logging(&example_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);

	/* initialize channel infrastructure. */
	osmo_chan_init(tall_example);

	/* create channel. */
	chan = osmo_chan_create(OSMO_CHAN_ABIS_IPA_SRV, OSMO_SUBCHAN_STREAM);
	if (chan == NULL) {
		LOGP(DEXAMPLE, LOGL_ERROR, "Cannot create A-bis IPA server\n");
		exit(EXIT_FAILURE);
	}

	/* set specific parameters (depends on channel type). */
	osmo_abis_ipa_srv_set_cb_signalmsg(chan, signal_msg_cb);
	osmo_abis_ipa_unit_add(chan, 1801, 0);

	/* open channel. */
	if (osmo_chan_open(chan) < 0) {
		LOGP(DEXAMPLE, LOGL_ERROR, "Cannot create A-bis IPA server\n");
		exit(EXIT_FAILURE);
	}

	LOGP(DEXAMPLE, LOGL_NOTICE, "Entering main loop\n");

	while(1) {
		osmo_select_main(0);
	}
}
