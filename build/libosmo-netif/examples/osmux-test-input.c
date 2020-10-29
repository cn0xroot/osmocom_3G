#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>

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
		.description = "osmux test input",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

const struct log_info osmux_test_log_info = {
	.filter_fn = NULL,
	.cat = osmux_test_cat,
	.num_cat = ARRAY_SIZE(osmux_test_cat),
};

static int fd;

static void amr_open(void)
{
	fd = open("/tmp/input.amr", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
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

	/* as described by rfc4867, see page 35 */
	rtph = osmo_rtp_get_hdr(msg);
	amr = osmo_rtp_get_payload(rtph, msg, &len);

	write(fd, (uint8_t *)amr + 1, len - 1);
}

static struct osmo_dgram *conn;
static struct osmo_rtp_handle *rtp;

static void osmux_deliver(struct msgb *batch_msg, void *data)
{
	char buf[1024];

	osmux_snprintf(buf, sizeof(buf), batch_msg);
	LOGP(DOSMUX_TEST, LOGL_DEBUG, "sending batch (len=%d): %s\n",
		batch_msg->len, buf);
	osmo_dgram_send(conn, batch_msg);
}

/*
 * This is the input handle for osmux. It stores the last osmux sequence that
 * has been used and the deliver function that sends the osmux batch.
 */
struct osmux_in_handle h_input = {
	.osmux_seq	= 0, /* sequence number to start OSmux message from */
	.batch_factor	= 4, /* batch up to 4 RTP messages */
	.deliver	= osmux_deliver,
};

#define MAX_CONCURRENT_CALLS	8

static int ccid[MAX_CONCURRENT_CALLS] = { -1, -1, -1, -1, -1, -1, -1, -1 };

static int get_ccid(uint32_t ssrc)
{
       int i, found = 0;

       for (i=0; i<MAX_CONCURRENT_CALLS; i++) {
	       if (ccid[i] == ssrc) {
		       found = 1;
		       break;
	       }
       }

       return found ? i : -1;
}

static void register_ccid(uint32_t ssrc)
{
       int i, found = 0;

       for (i=0; i<MAX_CONCURRENT_CALLS; i++) {
	       if (ccid[i] == ssrc)
		       continue;
	       if (ccid[i] < 0) {
		       found = 1;
		       break;
	       }
       }

       if (found) {
	       ccid[i] = ssrc;
	       LOGP(DOSMUX_TEST, LOGL_DEBUG, "mapping ssrc=%u to ccid=%d\n",
		       ntohl(ssrc), i);
       } else {
	       LOGP(DOSMUX_TEST, LOGL_ERROR, "cannot map ssrc to ccid!\n");
       }
}

int read_cb(struct osmo_dgram *conn)
{
	struct msgb *msg;
	struct rtp_hdr *rtph;
	int ret, ccid;

	msg = msgb_alloc(RTP_MSGB_SIZE, "OSMUX/test");
	if (msg == NULL) {
		LOGP(DOSMUX_TEST, LOGL_ERROR, "cannot allocate message\n");
		return -1;
	}
	if (osmo_dgram_recv(conn, msg) < 0) {
		LOGP(DOSMUX_TEST, LOGL_ERROR, "cannot receive message\n");
		return -1;
	}
	rtph = osmo_rtp_get_hdr(msg);
	if (rtph == NULL) {
		msgb_free(msg);
		LOGP(DOSMUX_TEST, LOGL_ERROR, "cannot parse RTP message\n");
		return -1;
	}
	LOGP(DOSMUX_TEST, LOGL_DEBUG, "received message with RTP payload type: %d\n",
		rtph->payload_type);

	if (rtph->payload_type == RTP_PT_AMR)
		amr_write(msg);

	char buf[1024];

	osmo_rtp_snprintf(buf, sizeof(buf), msg);
	LOGP(DOSMUX_TEST, LOGL_DEBUG, "received RTP (len=%d): %s\n", msg->len, buf);

	ccid = get_ccid(rtph->ssrc);
	if (ccid < 0)
		register_ccid(rtph->ssrc);

	while ((ret = osmux_xfrm_input(&h_input, msg, ccid)) > 0) {
		/* batch full, deliver it */
		osmux_xfrm_input_deliver(&h_input);
	}
	if (ret == -1)
		printf("something is wrong\n");

	return 0;
}

void sighandler(int foo)
{
	LOGP(DOSMUX_TEST, LOGL_NOTICE, "closing test.\n");
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
		LOGP(DOSMUX_TEST, LOGL_ERROR, "Error init RTP handler\n");
		exit(EXIT_FAILURE);
	}
	osmo_rtp_handle_tx_set_sequence(rtp, random());
	osmo_rtp_handle_tx_set_ssrc(rtp, random());
	osmo_rtp_handle_tx_set_timestamp(rtp, time(NULL));

	/*
	 * initialize OSMUX handlers.
	 */
	osmux_xfrm_input_init(&h_input);

	/*
	 * initialize datagram server.
	 */

	conn = osmo_dgram_create(tall_test);
	if (conn == NULL) {
		LOGP(DOSMUX_TEST, LOGL_ERROR, "cannot create UDP socket\n");
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

	LOGP(DOSMUX_TEST, LOGL_NOTICE, "Entering main loop\n");

	while(1) {
		osmo_select_main(0);
	}
}
