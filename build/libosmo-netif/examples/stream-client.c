/* stream client example. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

#include <osmocom/netif/stream.h>

#define DSTREAMTEST 0

struct log_info_cat osmo_stream_cli_test_cat[] = {
	[DSTREAMTEST] = {
		.name = "DSTREAMTEST",
		.description = "STREAMCLIENT-mode test",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

const struct log_info osmo_stream_cli_test_log_info = {
	.filter_fn = NULL,
	.cat = osmo_stream_cli_test_cat,
	.num_cat = ARRAY_SIZE(osmo_stream_cli_test_cat),
};

static struct osmo_stream_cli *conn;

void sighandler(int foo)
{
	LOGP(DSTREAMTEST, LOGL_NOTICE, "closing stream.\n");
	exit(EXIT_SUCCESS);
}

static int connect_cb(struct osmo_stream_cli *conn)
{
	LOGP(DSTREAMTEST, LOGL_NOTICE, "connected\n");
	return 0;
}

static int read_cb(struct osmo_stream_cli *conn)
{
	struct msgb *msg;

	LOGP(DSTREAMTEST, LOGL_NOTICE, "received message from stream\n");

	msg = msgb_alloc(1024, "STREAMCLIENT/test");
	if (msg == NULL) {
		LOGP(DSTREAMTEST, LOGL_ERROR, "cannot allocate message\n");
		return 0;
	}
	if (osmo_stream_cli_recv(conn, msg) < 0) {
		LOGP(DSTREAMTEST, LOGL_ERROR, "cannot receive message\n");
		return 0;
	}
	msgb_free(msg);
	return 0;
}

static void *tall_test;

static int kbd_cb(struct osmo_fd *fd, unsigned int what)
{
	char buf[1024];
	struct msgb *msg;
	uint8_t *ptr;
	int ret;

	ret = read(STDIN_FILENO, buf, sizeof(buf));
	LOGP(DSTREAMTEST, LOGL_NOTICE, "read %d byte from keyboard\n", ret);
	if (ret < 0)
		return ret;

	msg = msgb_alloc(1024, "STREAMCLIENT/test");
	if (msg == NULL) {
		LOGP(DSTREAMTEST, LOGL_ERROR, "cannot allocate message\n");
		return 0;
	}
	ptr = msgb_put(msg, ret);
	memcpy(ptr, buf, ret);

	osmo_stream_cli_send(conn, msg);

	LOGP(DSTREAMTEST, LOGL_NOTICE, "message of %d bytes sent\n", msg->len);

	return 0;
}

int main(void)
{
	struct osmo_fd *kbd_ofd;
	int rc;

	tall_test = talloc_named_const(NULL, 1, "osmo_stream_cli_test");

	osmo_init_logging(&osmo_stream_cli_test_log_info);
	log_set_log_level(osmo_stderr_target, 1);

	/*
	 * initialize stream cli.
	 */

	conn = osmo_stream_cli_create(tall_test);
	if (conn == NULL) {
		fprintf(stderr, "cannot create cli\n");
		exit(EXIT_FAILURE);
	}
	osmo_stream_cli_set_addr(conn, "127.0.0.1");
	osmo_stream_cli_set_port(conn, 10000);
	osmo_stream_cli_set_connect_cb(conn, connect_cb);
	osmo_stream_cli_set_read_cb(conn, read_cb);

	if (osmo_stream_cli_open(conn) < 0) {
		fprintf(stderr, "cannot open cli\n");
		exit(EXIT_FAILURE);
	}

	kbd_ofd = talloc_zero(tall_test, struct osmo_fd);
	if (!kbd_ofd) {
		LOGP(DSTREAMTEST, LOGL_ERROR, "OOM\n");
		exit(EXIT_FAILURE);
	}
	kbd_ofd->fd = STDIN_FILENO;
	kbd_ofd->when = BSC_FD_READ;
	kbd_ofd->data = conn;
	kbd_ofd->cb = kbd_cb;
	rc = osmo_fd_register(kbd_ofd);
	if (rc < 0) {
		LOGP(DSTREAMTEST, LOGL_ERROR, "FD Register\n");
		exit(EXIT_FAILURE);
	}

	LOGP(DSTREAMTEST, LOGL_NOTICE, "Entering main loop\n");

	while(1) {
		osmo_select_main(0);
	}
}
