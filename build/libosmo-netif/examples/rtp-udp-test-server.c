#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

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
		.description = "RPT-server test",
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

int read_cb(struct osmo_dgram *conn)
{
	struct msgb *msg;
	char dummy_data[RTP_PT_GSM_FULL_PAYLOAD_LEN] = "payload test";
	struct rtp_hdr *rtph;

	LOGP(DRTP_TEST, LOGL_DEBUG, "received message from datagram\n");

	msg = msgb_alloc(RTP_MSGB_SIZE, "RTP/test");
	if (msg == NULL) {
		LOGP(DRTP_TEST, LOGL_ERROR, "cannot allocate message\n");
		return -1;
	}
	if (osmo_dgram_recv(conn, msg) < 0) {
		LOGP(DRTP_TEST, LOGL_ERROR, "cannot receive message\n");
		return -1;
	}
	rtph = osmo_rtp_get_hdr(msg);
	if (rtph == NULL) {
		msgb_free(msg);
		LOGP(DRTP_TEST, LOGL_ERROR, "cannot parse RTP message\n");
		return -1;
	}
	LOGP(DLINP, LOGL_DEBUG, "received message with RTP payload type: %d\n",
		rtph->payload_type);

	/*
	 * ... now build gsm_data_frame, set callref and msg_type based
	 * on the rtp payload type (map RTP_PT_GSM_FULL to GSM_THCF_FRAME).
	 * Then, pass it to the RSL layer.
	 */

	msg = msgb_alloc(1200, "RTP/test");
	if (msg == NULL) {
		LOGP(DRTP_TEST, LOGL_ERROR, "cannot allocate message\n");
		return -1;
	}

	/* build reply. */
	msg = osmo_rtp_build(rtp, RTP_PT_GSM_FULL,
			     RTP_PT_GSM_FULL_PAYLOAD_LEN,
			     dummy_data, RTP_PT_GSM_FULL_DURATION);
	if (msg == NULL) {
		LOGP(DLINP, LOGL_ERROR, "OOM\n");
		return -1;
	}
	osmo_dgram_send(conn, msg);

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
	signal(SIGINT, sighandler);

	tall_test = talloc_named_const(NULL, 1, "udp_rtp_test");

	osmo_init_logging(&rtp_test_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);

	/*
	 * initialize RTP handler.
	 */
	rtp = osmo_rtp_handle_create(tall_test);
	if (rtp == NULL) {
		LOGP(DRTP_TEST, LOGL_ERROR, "Error init RTP handler\n");
		exit(EXIT_FAILURE);
	}
	osmo_rtp_handle_tx_set_sequence(rtp, random());
	osmo_rtp_handle_tx_set_ssrc(rtp, random());
	osmo_rtp_handle_tx_set_timestamp(rtp, time(NULL));

	/*
	 * initialize datagram server.
	 */

	conn = osmo_dgram_create(tall_test);
	if (conn == NULL) {
		LOGP(DRTP_TEST, LOGL_ERROR, "cannot create UDP socket\n");
		exit(EXIT_FAILURE);
	}
	osmo_dgram_set_local_addr(conn, "127.0.0.1");
	osmo_dgram_set_local_port(conn, 20000);
	osmo_dgram_set_remote_addr(conn, "127.0.0.1");
	osmo_dgram_set_remote_port(conn, 20001);
	osmo_dgram_set_read_cb(conn, read_cb);

	if (osmo_dgram_open(conn) < 0) {
		fprintf(stderr, "cannot open client\n");
		exit(EXIT_FAILURE);
	}

	LOGP(DRTP_TEST, LOGL_NOTICE, "Entering main loop\n");

	while(1) {
		osmo_select_main(0);
	}
}
