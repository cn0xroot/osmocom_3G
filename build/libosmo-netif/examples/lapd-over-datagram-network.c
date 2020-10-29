/* LAPD over datagram network-mode example. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/select.h>

#include <osmocom/abis/lapd.h>

#include <osmocom/netif/datagram.h>

static void *tall_test;

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
static int tei = 0;

void sighandler(int foo)
{
	lapd_instance_free(lapd);
	LOGP(DLAPDTEST, LOGL_NOTICE, "closing LAPD.\n");
	exit(EXIT_SUCCESS);
}

int read_cb(struct osmo_dgram *conn)
{
	int error;
	struct msgb *msg;

	LOGP(DLAPDTEST, LOGL_DEBUG, "received message from datagram\n");

	msg = msgb_alloc(1200, "LAPD/test");
	if (msg == NULL) {
		LOGP(DLAPDTEST, LOGL_ERROR, "cannot allocate message\n");
		return -1;
	}
	if (osmo_dgram_recv(conn, msg) < 0) {
		LOGP(DLAPDTEST, LOGL_ERROR, "cannot receive message\n");
		return -1;
	}
	if (lapd_receive(lapd, msg, &error) < 0) {
		LOGP(DLAPDTEST, LOGL_ERROR, "lapd_receive returned error!\n");
		return -1;
	}

	return 0;
}

void lapd_tx_cb(struct msgb *msg, void *cbdata)
{
	struct osmo_dgram *conn = cbdata;

	LOGP(DLAPDTEST, LOGL_DEBUG, "sending message over datagram\n");
	osmo_dgram_send(conn, msg);
}

void lapd_rx_cb(struct osmo_dlsap_prim *dp, uint8_t tei, uint8_t sapi,
		void *rx_cbdata)
{
	struct msgb *msg = dp->oph.msg;

	switch (dp->oph.primitive) {
	case PRIM_DL_EST:
		DEBUGP(DLAPDTEST, "DL_EST: sapi(%d) tei(%d)\n", sapi, tei);
		break;
	case PRIM_DL_REL:
		DEBUGP(DLAPDTEST, "DL_REL: sapi(%d) tei(%d)\n", sapi, tei);
		break;
	case PRIM_DL_DATA:
	case PRIM_DL_UNIT_DATA:
		if (dp->oph.operation == PRIM_OP_INDICATION) {
			struct msgb *nmsg;
			char *ptr;
			int x;

			msg->l2h = msg->l3h;

			DEBUGP(DLAPDTEST, "RX: %s sapi=%d tei=%d\n",
				osmo_hexdump(msgb_l2(msg), msgb_l2len(msg)),
				sapi, tei);

			LOGP(DLAPDTEST, LOGL_DEBUG, "forwarding message\n");

                        nmsg = msgb_alloc(1024, "LAPD/test");
                        if (nmsg == NULL) {
                                LOGP(DLAPDTEST, LOGL_ERROR, "cannot alloc msg\n");
                                return;
                        }
                        ptr = (char *)msgb_put(nmsg, sizeof(int));

                        x = *((int *)msg->data);
                        memcpy(ptr, &x, sizeof(int));

			/* send the message back to client over LAPD */
			lapd_transmit(lapd, tei, sapi, msg);
			return;
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
	struct lapd_tei *teip;

	tall_test = talloc_named_const(NULL, 1, "lapd_test");

	osmo_init_logging(&lapd_test_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_NOTICE);

	/*
	 * initialize datagram server.
	 */

	conn = osmo_dgram_create(tall_test);
	if (conn == NULL) {
		fprintf(stderr, "cannot create client\n");
		exit(EXIT_FAILURE);
	}
	osmo_dgram_set_local_addr(conn, "127.0.0.1");
	osmo_dgram_set_local_port(conn, 10001);
	osmo_dgram_set_remote_addr(conn, "127.0.0.1");
	osmo_dgram_set_remote_port(conn, 10000);
	osmo_dgram_set_read_cb(conn, read_cb);

	lapd = lapd_instance_alloc(1, lapd_tx_cb, conn, lapd_rx_cb, conn,
				   &lapd_profile_sat);
	if (lapd == NULL) {
		LOGP(DLAPDTEST, LOGL_ERROR, "cannot allocate instance\n");
		exit(EXIT_FAILURE);
	}

	teip = lapd_tei_alloc(lapd, tei);
	if (teip == NULL) {
		LOGP(DLAPDTEST, LOGL_ERROR, "cannot assign TEI\n");
		exit(EXIT_FAILURE);
	}

	if (osmo_dgram_open(conn) < 0) {
		fprintf(stderr, "cannot open client\n");
		exit(EXIT_FAILURE);
	}

	LOGP(DLAPDTEST, LOGL_NOTICE, "Entering main loop\n");

	while(1) {
		osmo_select_main(0);
	}
}
