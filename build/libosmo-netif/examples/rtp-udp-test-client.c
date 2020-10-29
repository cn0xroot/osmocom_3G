#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/select.h>

#include <osmocom/netif/rtp.h>
#include <osmocom/netif/datagram.h>

#define DRTP_TEST 0

struct log_info_cat rtp_test_cat[] = {
	[DRTP_TEST] = {
		.name = "DRTP_TEST",
		.description = "RTP client test",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

const struct log_info rtp_test_log_info = {
	.filter_fn = NULL,
	.cat = rtp_test_cat,
	.num_cat = ARRAY_SIZE(rtp_test_cat),
};

static struct osmo_dgram *conn;
static struct osmo_rtp_handle *rtp;

static int read_cb(struct osmo_dgram *conn)
{
	struct msgb *msg;
	struct rtp_hdr *rtph;

	LOGP(DLINP, LOGL_DEBUG, "received message\n");

	msg = msgb_alloc(RTP_MSGB_SIZE, "RTP/test");
	if (msg == NULL) {
		LOGP(DRTP_TEST, LOGL_ERROR, "cannot allocate message\n");
		return -1;
	}
	if (osmo_dgram_recv(conn, msg) < 0) {
		msgb_free(msg);
		LOGP(DRTP_TEST, LOGL_ERROR, "cannot receive message\n");
		return -1;
	}

	rtph = osmo_rtp_get_hdr(msg);
	if (rtph == NULL) {
		msgb_free(msg);
		LOGP(DRTP_TEST, LOGL_ERROR, "cannot parse RTP message\n");
		return -1;
	}

	LOGP(DLINP, LOGL_DEBUG, "received message with payload type: %d\n",
		rtph->payload_type);

	msgb_free(msg);
	return 0;
}

void sighandler(int foo)
{
	LOGP(DLINP, LOGL_NOTICE, "closing RTP.\n");
	osmo_dgram_close(conn);
	osmo_dgram_destroy(conn);
	osmo_rtp_handle_free(rtp);
	exit(EXIT_SUCCESS);
}

static void *tall_test;

int main(int argc, char *argv[])
{
	int i;
	char dummy_data[RTP_PT_GSM_FULL_PAYLOAD_LEN] = "payload test";

	signal(SIGINT, sighandler);

	tall_test = talloc_named_const(NULL, 1, "rtp_test");

	osmo_init_logging(&rtp_test_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);

	/*
	 * initialize RTP stuff.
	 */
	rtp = osmo_rtp_handle_create(tall_test);
	if (rtp == NULL) {
		LOGP(DLINP, LOGL_ERROR, "creating RTP handler\n");
		exit(EXIT_FAILURE);
	}
	osmo_rtp_handle_tx_set_sequence(rtp, random());
	osmo_rtp_handle_tx_set_ssrc(rtp, random());
	osmo_rtp_handle_tx_set_timestamp(rtp, time(NULL));

	/*
	 * initialize datagram socket.
	 */

	conn = osmo_dgram_create(tall_test);
	if (conn == NULL) {
		fprintf(stderr, "cannot create client\n");
		exit(EXIT_FAILURE);
	}
	osmo_dgram_set_local_addr(conn, "127.0.0.1");
	osmo_dgram_set_local_port(conn, 20001);
	osmo_dgram_set_remote_addr(conn, "127.0.0.1");
	osmo_dgram_set_remote_port(conn, 20000);
	osmo_dgram_set_read_cb(conn, read_cb);

	if (osmo_dgram_open(conn) < 0) {
		fprintf(stderr, "cannot open client\n");
		exit(EXIT_FAILURE);
	}

	for(i=0; i<10; i++) {
		struct msgb *msg;

		msg = osmo_rtp_build(rtp, RTP_PT_GSM_FULL,
				     RTP_PT_GSM_FULL_PAYLOAD_LEN,
				     dummy_data, RTP_PT_GSM_FULL_DURATION);
		if (msg == NULL) {
			LOGP(DLINP, LOGL_ERROR, "OOM\n");
			continue;
		}
		osmo_dgram_send(conn, msg);
	}

	LOGP(DLINP, LOGL_NOTICE, "Entering main loop\n");

	while(1) {
		osmo_select_main(0);
	}
}
