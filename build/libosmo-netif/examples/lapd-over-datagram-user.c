/* LAPD over datagram user-mode example. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/select.h>

#include <osmocom/abis/lapd.h>

#include <osmocom/netif/datagram.h>

static LLIST_HEAD(msg_sent_list);

struct msg_sent {
	struct llist_head	head;
	struct msgb		*msg;
	int			num;
	struct timeval		tv;
};

#define DLAPDTEST 0

struct log_info_cat lapd_test_cat[] = {
	[DLAPDTEST] = {
		.name = "DLAPDTEST",
		.description = "LAPD-mode test",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

const struct log_info lapd_test_log_info = {
	.filter_fn = NULL,
	.cat = lapd_test_cat,
	.num_cat = ARRAY_SIZE(lapd_test_cat),
};

static struct osmo_dgram *conn;
static struct lapd_instance *lapd;
static int sapi = 63, tei = 0;

void sighandler(int foo)
{
	lapd_sap_stop(lapd, tei, sapi);
	lapd_instance_free(lapd);
	LOGP(DLINP, LOGL_NOTICE, "closing LAPD.\n");
	exit(EXIT_SUCCESS);
}

static int read_cb(struct osmo_dgram *conn)
{
	int error;
	struct msgb *msg;

	msg = msgb_alloc(1200, "LAPD/test");
	if (msg == NULL) {
		LOGP(DLAPDTEST, LOGL_ERROR, "cannot allocate message\n");
		return -1;
	}
	if (osmo_dgram_recv(conn, msg) < 0) {
		msgb_free(msg);
		LOGP(DLAPDTEST, LOGL_ERROR, "cannot receive message\n");
		return -1;
	}
	if (lapd_receive(lapd, msg, &error) < 0) {
		msgb_free(msg);
		LOGP(DLINP, LOGL_ERROR, "lapd_receive returned error!\n");
		return -1;
	}
	return 0;
}

static void *tall_test;

void lapd_tx_cb(struct msgb *msg, void *cbdata)
{
	LOGP(DLINP, LOGL_DEBUG, "sending message over datagram\n");
	osmo_dgram_send(conn, msg);
}

void lapd_rx_cb(struct osmo_dlsap_prim *dp, uint8_t tei, uint8_t sapi,
		void *rx_cbdata)
{
	struct msgb *msg = dp->oph.msg;
	int *__msgs = rx_cbdata;
	int num_msgs = *__msgs;

	switch (dp->oph.primitive) {
	case PRIM_DL_EST:
		DEBUGP(DLAPDTEST, "DL_EST: sapi(%d) tei(%d)\n", sapi, tei);

		int i;
		for (i=0; i<num_msgs; i++) {
			struct msgb *msg;
			struct msg_sent *msg_sent;
			char *ptr;
			int x;

			msg = msgb_alloc(1024, "LAPD/test");
			if (msg == NULL) {
				LOGP(DLINP, LOGL_ERROR, "cannot alloc msg\n");
				return;
			}
		        ptr = (char *)msgb_put(msg, sizeof(int));

			x = htonl(i);
		        memcpy(ptr, &x, sizeof(int));

			msg_sent = talloc_zero(NULL, struct msg_sent);
			if (msg_sent == NULL) {
				LOGP(DLINP, LOGL_ERROR, "can't alloc struct\n");
				return;
			}
			msg_sent->msg = msg;
			gettimeofday(&msg_sent->tv, NULL);
			msg_sent->num = i;
			llist_add(&msg_sent->head, &msg_sent_list);

		        lapd_transmit(lapd, tei, sapi, msg);

		        LOGP(DLAPDTEST, LOGL_DEBUG, "enqueueing msg %d of "
				"%d bytes to be sent over LAPD\n", i, msg->len);
		}
		break;
	case PRIM_DL_REL:
		DEBUGP(DLAPDTEST, "DL_REL: sapi(%d) tei(%d)\n", sapi, tei);
		break;
	case PRIM_DL_DATA:
	case PRIM_DL_UNIT_DATA:
		if (dp->oph.operation == PRIM_OP_INDICATION) {
			msg->l2h = msg->l3h;
			DEBUGP(DLAPDTEST, "RX: %s sapi=%d tei=%d\n",
				osmo_hexdump(msgb_l2(msg), msgb_l2len(msg)),
				sapi, tei);

			int num;
			struct msg_sent *cur, *tmp, *found = NULL;

			num = ntohl(*((int *)msg->data));
			LOGP(DLINP, LOGL_DEBUG,
				"received msg number %d\n", num);

			llist_for_each_entry_safe(cur, tmp,
						&msg_sent_list, head) {
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
					"in %lu.%.6lu\n",
					num, diff.tv_sec, diff.tv_usec);
				talloc_free(found);
			} else {
				LOGP(DLINP, LOGL_ERROR,
					"message %d not found!\n", num);
			}
		}
		break;
	case PRIM_MDL_ERROR:
		DEBUGP(DLMI, "MDL_EERROR: cause(%d)\n", dp->u.error_ind.cause);
		break;
	default:
		printf("ERROR: unknown prim\n");
		break;
	}
}

int main(int argc, char *argv[])
{
	int num_msgs;

	signal(SIGINT, sighandler);

	if (argc != 2) {
		printf("Usage: %s [num_msgs]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	num_msgs = atoi(argv[1]);

	tall_test = talloc_named_const(NULL, 1, "lapd_test");

	osmo_init_logging(&lapd_test_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_NOTICE);
	/*
	 * initialize LAPD stuff.
	 */

	lapd = lapd_instance_alloc(0, lapd_tx_cb, NULL, lapd_rx_cb, &num_msgs,
				   &lapd_profile_sat);
	if (lapd == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate instance\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * initialize datagram socket.
	 */

	conn = osmo_dgram_create(tall_test);
	if (conn == NULL) {
		fprintf(stderr, "cannot create client\n");
		exit(EXIT_FAILURE);
	}
	osmo_dgram_set_local_addr(conn, "127.0.0.1");
	osmo_dgram_set_local_port(conn, 10000);
	osmo_dgram_set_remote_addr(conn, "127.0.0.1");
	osmo_dgram_set_remote_port(conn, 10001);
	osmo_dgram_set_read_cb(conn, read_cb);

	if (osmo_dgram_open(conn) < 0) {
		fprintf(stderr, "cannot open client\n");
		exit(EXIT_FAILURE);
	}

	if (lapd_sap_start(lapd, tei, sapi) < 0) {
		LOGP(DLINP, LOGL_ERROR, "cannot start user-side LAPD\n");
		exit(EXIT_FAILURE);
	}

	LOGP(DLINP, LOGL_NOTICE, "Entering main loop\n");

	while(1) {
		osmo_select_main(0);
	}
}
