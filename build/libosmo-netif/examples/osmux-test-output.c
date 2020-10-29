#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/select.h>

#include <osmocom/netif/rtp.h>
#include <osmocom/netif/osmux.h>
#include <osmocom/netif/datagram.h>

#define DOSMUX_TEST 0

struct log_info_cat osmux_test_cat[] = {
	[DOSMUX_TEST] = {
		.name = "DOSMUX_TEST",
		.description = "osmux test output",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

const struct log_info osmux_test_log_info = {
	.filter_fn = NULL,
	.cat = osmux_test_cat,
	.num_cat = ARRAY_SIZE(osmux_test_cat),
};

static struct osmo_dgram *conn;
static struct osmo_rtp_handle *rtp;

/*
 * This is the output handle for osmux, it stores last RTP sequence and
 * timestamp that has been used. There should be one per circuit ID.
 */
static struct osmux_out_handle h_output;

static int fd;

static void amr_open(void)
{
	fd = open("/tmp/output.amr", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror("open");
		exit(1);
	}
	write(fd, "#!AMR\n", strlen("#!AMR\n"));
}

static void amr_close(void)
{
	close(fd);
}

static void amr_write(struct msgb *msg)
{
	struct rtp_hdr *rtph;
	void *amr;
	unsigned int len;

	rtph = osmo_rtp_get_hdr(msg);
	amr = osmo_rtp_get_payload(rtph, msg, &len);

	write(fd, (uint8_t *)amr + 1, len - 1);
}

static void tx_cb(struct msgb *msg, void *data)
{
	char buf[4096];

	osmo_rtp_snprintf(buf, sizeof(buf), msg);
	LOGP(DOSMUX_TEST, LOGL_DEBUG, "sending: %s\n", buf);
	osmo_dgram_send(conn, msg);

	amr_write(msg);
}

int read_cb(struct osmo_dgram *conn)
{
	struct msgb *msg;
        struct osmux_hdr *osmuxh;
	struct llist_head list;

	LOGP(DOSMUX_TEST, LOGL_DEBUG, "received message from datagram\n");

	msg = msgb_alloc(RTP_MSGB_SIZE, "OSMUX/test");
	if (msg == NULL) {
		LOGP(DOSMUX_TEST, LOGL_ERROR, "cannot allocate message\n");
		return -1;
	}
	if (osmo_dgram_recv(conn, msg) < 0) {
		LOGP(DOSMUX_TEST, LOGL_ERROR, "cannot receive message\n");
		return -1;
	}

	char buf[1024];
	osmux_snprintf(buf, sizeof(buf), msg);
	LOGP(DOSMUX_TEST, LOGL_DEBUG, "received OSMUX message (len=%d) %s\n",
		msg->len, buf);

	while((osmuxh = osmux_xfrm_output_pull(msg)) != NULL) {
		osmux_xfrm_output(osmuxh, &h_output, &list);
		osmux_tx_sched(&list, tx_cb, NULL);
	}

	return 0;
}

void sighandler(int foo)
{
	LOGP(DOSMUX_TEST, LOGL_NOTICE, "closing OSMUX.\n");
	osmo_dgram_close(conn);
	osmo_dgram_destroy(conn);
	osmo_rtp_handle_free(rtp);
	amr_close();
	exit(EXIT_SUCCESS);
}

static void *tall_test;

/*
 * This is the output handle for osmux, it stores last RTP sequence and
 * timestamp that has been used. There should be one per circuit ID.
 */
int main(int argc, char *argv[])
{
	amr_open();

	signal(SIGINT, sighandler);

	tall_test = talloc_named_const(NULL, 1, "osmux_test");

	osmo_init_logging(&osmux_test_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);

	/*
	 * initialize RTP handler.
	 */
	rtp = osmo_rtp_handle_create(tall_test);
	if (rtp == NULL) {
		LOGP(DOSMUX_TEST, LOGL_ERROR, "Error init OSMUX handler\n");
		exit(EXIT_FAILURE);
	}
	osmo_rtp_handle_tx_set_sequence(rtp, random());
	osmo_rtp_handle_tx_set_ssrc(rtp, random());
	osmo_rtp_handle_tx_set_timestamp(rtp, time(NULL));

	/*
	 * initialize OSMUX handlers.
	 */
	osmux_xfrm_output_init(&h_output, random());

	/*
	 * initialize datagram server.
	 */

	conn = osmo_dgram_create(tall_test);
	if (conn == NULL) {
		LOGP(DOSMUX_TEST, LOGL_ERROR, "cannot create UDP socket\n");
		exit(EXIT_FAILURE);
	}
	osmo_dgram_set_local_addr(conn, "127.0.0.1");
	osmo_dgram_set_local_port(conn, 20001);
	osmo_dgram_set_remote_addr(conn, "127.0.0.1");
	osmo_dgram_set_remote_port(conn, 20002);
	osmo_dgram_set_read_cb(conn, read_cb);

	if (osmo_dgram_open(conn) < 0) {
		fprintf(stderr, "cannot open client\n");
		exit(EXIT_FAILURE);
	}

	LOGP(DOSMUX_TEST, LOGL_NOTICE, "Entering main loop\n");

	while(1) {
		osmo_select_main(0);
	}
}
