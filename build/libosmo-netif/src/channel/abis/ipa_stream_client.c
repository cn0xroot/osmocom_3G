#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <errno.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>

#include <osmocom/gsm/tlv.h>

#include <osmocom/netif/channel.h>
#include <osmocom/netif/stream.h>
#include <osmocom/netif/ipa.h>
#include <osmocom/netif/ipa_unit.h>

#define CHAN_SIGN_OML	0
#define CHAN_SIGN_RSL	1

/* default IPA cli ports. */
#define IPA_TCP_PORT_OML	3002
#define IPA_TCP_PORT_RSL	3003

static void *abis_ipa_cli_tall;

struct chan_abis_ipa_cli {
	struct osmo_ipa_unit *unit;

	struct osmo_stream_cli *oml;
	struct osmo_stream_cli *rsl;

	void (*signal_msg)(struct msgb *msg, int type);
};

static int oml_read_cb(struct osmo_stream_cli *conn);
static int rsl_read_cb(struct osmo_stream_cli *conn);

static int chan_abis_ipa_cli_create(struct osmo_chan *chan)
{
	struct chan_abis_ipa_cli *c = (struct chan_abis_ipa_cli *)chan->data;

	c->unit = osmo_ipa_unit_alloc(0);
	if (c->unit == NULL)
		goto err;

	c->oml = osmo_stream_cli_create(abis_ipa_cli_tall);
	if (c->oml == NULL)
		goto err_oml;

	/* default address and port for OML. */
	osmo_stream_cli_set_addr(c->oml, "0.0.0.0");
	osmo_stream_cli_set_port(c->oml, IPA_TCP_PORT_OML);
	osmo_stream_cli_set_read_cb(c->oml, oml_read_cb);
	osmo_stream_cli_set_data(c->oml, chan);

	c->rsl = osmo_stream_cli_create(abis_ipa_cli_tall);
	if (c->rsl == NULL)
		goto err_rsl;

	/* default address and port for RSL. */
	osmo_stream_cli_set_addr(c->rsl, "0.0.0.0");
	osmo_stream_cli_set_port(c->rsl, IPA_TCP_PORT_RSL);
	osmo_stream_cli_set_read_cb(c->rsl, rsl_read_cb);
	osmo_stream_cli_set_data(c->rsl, chan);

	return 0;
err_rsl:
	osmo_stream_cli_destroy(c->oml);
err_oml:
	osmo_ipa_unit_free(c->unit);
err:
	return -1;
}

static void chan_abis_ipa_cli_destroy(struct osmo_chan *chan)
{
	struct chan_abis_ipa_cli *c = (struct chan_abis_ipa_cli *)chan->data;

	osmo_ipa_unit_free(c->unit);
	talloc_free(c->rsl);
	talloc_free(c->oml);
}

static int chan_abis_ipa_cli_open(struct osmo_chan *chan)
{
	struct chan_abis_ipa_cli *c = (struct chan_abis_ipa_cli *)chan->data;
	struct osmo_fd *ofd;
	int ret, on = 1;

	if (osmo_stream_cli_open(c->oml) < 0)
		goto err;

	ofd = osmo_stream_cli_get_ofd(c->oml);
	ret = setsockopt(ofd->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (ret < 0)
		goto err_oml;

	if (osmo_stream_cli_open(c->rsl) < 0)
		goto err_oml;

	ofd = osmo_stream_cli_get_ofd(c->rsl);
	ret = setsockopt(ofd->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (ret < 0)
		goto err_rsl;

	return 0;

err_rsl:
	osmo_stream_cli_close(c->rsl);
err_oml:
	osmo_stream_cli_close(c->oml);
err:
	return -1;
}

static void chan_abis_ipa_cli_close(struct osmo_chan *chan)
{
	struct chan_abis_ipa_cli *c = (struct chan_abis_ipa_cli *)chan->data;

	osmo_stream_cli_close(c->oml);
	osmo_stream_cli_close(c->rsl);
}

static int chan_abis_ipa_cli_enqueue(struct osmo_chan *c, struct msgb *msg)
{
	osmo_stream_cli_send(msg->dst, msg);
	return 0;
}

void osmo_abis_ipa_cli_set_oml_addr(struct osmo_chan *c, const char *addr)
{
	struct chan_abis_ipa_cli *s = (struct chan_abis_ipa_cli *)&c->data;

	osmo_stream_cli_set_addr(s->oml, addr);
}

void osmo_abis_ipa_cli_set_oml_port(struct osmo_chan *c, uint16_t port)
{
	struct chan_abis_ipa_cli *s = (struct chan_abis_ipa_cli *)&c->data;

	osmo_stream_cli_set_port(s->oml, port);
}

void osmo_abis_ipa_cli_set_rsl_addr(struct osmo_chan *c, const char *addr)
{
	struct chan_abis_ipa_cli *s = (struct chan_abis_ipa_cli *)&c->data;

	osmo_stream_cli_set_addr(s->rsl, addr);
}

void osmo_abis_ipa_cli_set_rsl_port(struct osmo_chan *c, uint16_t port)
{
	struct chan_abis_ipa_cli *s = (struct chan_abis_ipa_cli *)&c->data;

	osmo_stream_cli_set_port(s->rsl, port);
}

void osmo_abis_ipa_cli_set_unit(struct osmo_chan *c, struct osmo_ipa_unit *unit)
{
	struct chan_abis_ipa_cli *s = (struct chan_abis_ipa_cli *)&c->data;

	osmo_ipa_unit_free(s->unit);
	s->unit = unit;
}

void osmo_abis_ipa_cli_set_cb_signalmsg(struct osmo_chan *c,
	void (*signal_msg)(struct msgb *msg, int type))
{
	struct chan_abis_ipa_cli *s = (struct chan_abis_ipa_cli *)&c->data;

	s->signal_msg = signal_msg;
}

static int
abis_ipa_cli_rcvmsg(struct osmo_chan *c, struct osmo_stream_cli *conn,
		    struct msgb *msg, int type)
{
	uint8_t msg_type = *(msg->l2h);
	struct osmo_fd *ofd = osmo_stream_cli_get_ofd(conn);
	struct chan_abis_ipa_cli *chan = (struct chan_abis_ipa_cli *)&c->data;
	int ret;

	/* Handle IPA PING, PONG and ID_ACK messages. */
	if (osmo_ipa_rcvmsg_base(msg, ofd, 0)) /* XXX: 0 indicates client */
		return 0;

	if (msg_type == IPAC_MSGT_ID_GET) {
		struct msgb *rmsg;
		uint8_t *data = msgb_l2(msg);
		int len = msgb_l2len(msg);

		LOGP(DLINP, LOGL_NOTICE, "received ID get\n");

		rmsg = ipa_cli_id_resp(chan->unit, data + 1, len - 1);
		osmo_stream_cli_send(conn, rmsg);

		/* send ID_ACK. */
		rmsg = ipa_cli_id_ack();
		osmo_stream_cli_send(conn, rmsg);
		ret = 0;
	} else {
		LOGP(DLINP, LOGL_ERROR, "Unknown IPA message type\n");
		ret = -EINVAL;
	}
	return ret;
}

static int read_cb(struct osmo_stream_cli *conn, int type)
{
	int ret;
	struct msgb *msg;
	struct osmo_chan *chan = osmo_stream_cli_get_data(conn);
	struct chan_abis_ipa_cli *s;
	struct ipa_head *hh;

	LOGP(DLINP, LOGL_DEBUG, "received message from stream\n");

	msg = osmo_ipa_msg_alloc(0);
	if (msg == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate message\n");
		return 0;
	}
	ret = osmo_stream_cli_recv(conn, msg);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "cannot receive message\n");
		msgb_free(msg);
		/* not the dummy connection, release it. */
		return 0;
	} else if (ret == 0) {
		/* link has vanished, dead socket. */
		LOGP(DLINP, LOGL_ERROR, "closed connection\n");
		msgb_free(msg);
		return 0;
	}

	if (osmo_ipa_process_msg(msg) < 0) {
		LOGP(DLINP, LOGL_ERROR, "Bad IPA message\n");
		msgb_free(msg);
		return -EIO;
	}

	hh = (struct ipa_head *) msg->data;
	if (hh->proto == IPAC_PROTO_IPACCESS) {
		abis_ipa_cli_rcvmsg(chan, conn, msg, type);
		msgb_free(msg);
		return -EIO;
	}

	chan = osmo_stream_cli_get_data(conn);
	if (chan == NULL) {
		LOGP(DLINP, LOGL_ERROR, "no matching signalling link\n");
		msgb_free(msg);
		return -EIO;
	}
	if (hh->proto != IPAC_PROTO_OML && hh->proto != IPAC_PROTO_RSL) {
		LOGP(DLINP, LOGL_ERROR, "wrong protocol\n");
		return -EIO;
	}
	msg->dst = chan;

	s = (struct chan_abis_ipa_cli *)chan->data;
	s->signal_msg(msg, type);

	return 0;
}

static int oml_read_cb(struct osmo_stream_cli *conn)
{
	return read_cb(conn, CHAN_SIGN_OML);
}

static int rsl_read_cb(struct osmo_stream_cli *conn)
{
	return read_cb(conn, CHAN_SIGN_RSL);
}

struct osmo_chan_type chan_abis_ipa_cli = {
	.type		= OSMO_CHAN_ABIS_IPA_CLI,
	.subtype	= OSMO_SUBCHAN_STREAM,
	.name		= "A-bis IPA client",
	.datasiz	= sizeof(struct chan_abis_ipa_cli),
	.create		= chan_abis_ipa_cli_create,
	.destroy	= chan_abis_ipa_cli_destroy,
	.open		= chan_abis_ipa_cli_open,
	.close		= chan_abis_ipa_cli_close,
	.enqueue	= chan_abis_ipa_cli_enqueue,
};
