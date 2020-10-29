/* IPA stream client example. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

#include <osmocom/netif/stream.h>
#include <osmocom/netif/ipa.h>

static LLIST_HEAD(msg_sent_list);

struct msg_sent {
	struct llist_head	head;
	struct msgb		*msg;
	int			num;
	struct timeval		tv;
};

#define DIPATEST 0

struct log_info_cat osmo_stream_client_test_cat[] = {
	[DIPATEST] = {
		.name = "DIPATEST",
		.description = "STREAMCLIENT-mode test",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
};

const struct log_info osmo_stream_client_test_log_info = {
	.filter_fn = NULL,
	.cat = osmo_stream_client_test_cat,
	.num_cat = ARRAY_SIZE(osmo_stream_client_test_cat),
};

static struct osmo_stream_cli *conn;

void sighandler(int foo)
{
	LOGP(DIPATEST, LOGL_NOTICE, "closing stream.\n");
	exit(EXIT_SUCCESS);
}

static int connect_cb(struct osmo_stream_cli *conn)
{
	int *__num_msgs = osmo_stream_cli_get_data(conn);
	int num_msgs = *__num_msgs, i;

	LOGP(DIPATEST, LOGL_NOTICE, "connected\n");

	for (i=0; i<num_msgs; i++) {
		struct msgb *msg;
		struct msg_sent *msg_sent;
		char *ptr;
		int x;

		msg = osmo_ipa_msg_alloc(0);
		if (msg == NULL) {
			LOGP(DLINP, LOGL_ERROR, "cannot alloc msg\n");
			return -1;
		}
		ptr = (char *)msgb_put(msg, sizeof(int));
		x = htonl(i);
		memcpy(ptr, &x, sizeof(int));

		msg_sent = talloc_zero(NULL, struct msg_sent);
		if (msg_sent == NULL) {
			LOGP(DLINP, LOGL_ERROR, "can't alloc struct\n");
			return -1;
		}
		msg_sent->msg = msg;
		gettimeofday(&msg_sent->tv, NULL);
		msg_sent->num = i;
		llist_add(&msg_sent->head, &msg_sent_list);

		osmo_ipa_msg_push_header(msg, IPAC_PROTO_OSMO);

		osmo_stream_cli_send(conn, msg);

		LOGP(DIPATEST, LOGL_DEBUG, "enqueueing msg %d of "
			"%d bytes to be sent\n", i, msg->len);
	}
	return 0;
}

static int read_cb(struct osmo_stream_cli *conn)
{
	struct msgb *msg;

	LOGP(DIPATEST, LOGL_DEBUG, "received message from stream\n");

	msg = osmo_ipa_msg_alloc(0);
	if (msg == NULL) {
		LOGP(DIPATEST, LOGL_ERROR, "cannot allocate message\n");
		return 0;
	}
	if (osmo_stream_cli_recv(conn, msg) <= 0) {
		LOGP(DIPATEST, LOGL_ERROR, "cannot receive message\n");
		return 0;
	}
	if (osmo_ipa_process_msg(msg) < 0) {
		LOGP(DIPATEST, LOGL_ERROR, "bad IPA message\n");
		return 0;
	}

	int num;
	struct msg_sent *cur, *tmp, *found = NULL;

	num = ntohl(*((int *)(msg->data + sizeof(struct ipa_head))));
	LOGP(DLINP, LOGL_DEBUG, "received msg number %d\n", num);

	llist_for_each_entry_safe(cur, tmp, &msg_sent_list, head) {
		if (cur->num == num) {
			llist_del(&cur->head);
			found = cur;
			break;
		}
	}
	if (found) {
		struct timeval tv, diff;

		gettimeofday(&tv, NULL);
		timersub(&tv, &found->tv, &diff);

		LOGP(DLINP, LOGL_NOTICE, "message %d replied "
			"in %lu.%.6lu\n", num, diff.tv_sec, diff.tv_usec);
		talloc_free(found);
	} else {
		LOGP(DLINP, LOGL_ERROR,
			"message %d not found!\n", num);
	}
	return 0;
}

static void *tall_test;

int main(int argc, char *argv[])
{
	int num_msgs;

	signal(SIGINT, sighandler);

	if (argc != 2) {
		printf("Usage: %s [num_msgs]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	num_msgs = atoi(argv[1]);

	tall_test = talloc_named_const(NULL, 1, "osmo_stream_client_test");

	osmo_init_logging(&osmo_stream_client_test_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_NOTICE);

	/*
	 * initialize stream client.
	 */

	conn = osmo_stream_cli_create(tall_test);
	if (conn == NULL) {
		fprintf(stderr, "cannot create client\n");
		exit(EXIT_FAILURE);
	}
	osmo_stream_cli_set_addr(conn, "127.0.0.1");
	osmo_stream_cli_set_port(conn, 10000);
	osmo_stream_cli_set_connect_cb(conn, connect_cb);
	osmo_stream_cli_set_read_cb(conn, read_cb);
	osmo_stream_cli_set_data(conn, &num_msgs);

	if (osmo_stream_cli_open(conn) < 0) {
		fprintf(stderr, "cannot open client\n");
		exit(EXIT_FAILURE);
	}

	int on = 1, ret;
	struct osmo_fd *ofd = osmo_stream_cli_get_ofd(conn);

	ret = setsockopt(ofd->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (ret < 0) {
		LOGP(DIPATEST, LOGL_ERROR, "cannot disable Nagle\n");
		exit(EXIT_FAILURE);
	}

	LOGP(DIPATEST, LOGL_NOTICE, "Entering main loop\n");

	while(1) {
		osmo_select_main(0);
	}
}
