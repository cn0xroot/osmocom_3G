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

/* default IPA srv ports. */
#define IPA_TCP_PORT_OML	3002
#define IPA_TCP_PORT_RSL	3003

static void *abis_ipa_srv_tall;

static int oml_accept_cb(struct osmo_stream_srv_link *srv, int fd);
static int rsl_accept_cb(struct osmo_stream_srv_link *srv, int fd);

struct chan_abis_ipa_srv {
	struct osmo_chan *chan;
	struct osmo_stream_srv_link *oml;
	struct osmo_stream_srv_link *rsl;

	struct llist_head bts_list;

	void (*signal_msg)(struct msgb *msg, int type);
};

struct chan_abis_ipa_srv_conn {
	struct chan_abis_ipa_srv *master;

	struct osmo_stream_srv	*oml;
	struct osmo_stream_srv	*rsl;
};

static int chan_abis_ipa_srv_create(struct osmo_chan *chan)
{
	struct chan_abis_ipa_srv *c = (struct chan_abis_ipa_srv *)chan->data;

	c->oml = osmo_stream_srv_link_create(abis_ipa_srv_tall);
	if (c->oml == NULL)
		goto err_oml;

	/* default address and port for OML. */
	osmo_stream_srv_link_set_addr(c->oml, "0.0.0.0");
	osmo_stream_srv_link_set_port(c->oml, IPA_TCP_PORT_OML);
	osmo_stream_srv_link_set_accept_cb(c->oml, oml_accept_cb);
	osmo_stream_srv_link_set_data(c->oml, c);

	c->rsl = osmo_stream_srv_link_create(abis_ipa_srv_tall);
	if (c->rsl == NULL)
		goto err_rsl;

	/* default address and port for RSL. */
	osmo_stream_srv_link_set_addr(c->rsl, "0.0.0.0");
	osmo_stream_srv_link_set_port(c->rsl, IPA_TCP_PORT_RSL);
	osmo_stream_srv_link_set_accept_cb(c->rsl, rsl_accept_cb);
	osmo_stream_srv_link_set_data(c->rsl, c);

	INIT_LLIST_HEAD(&c->bts_list);

	return 0;
err_rsl:
	osmo_stream_srv_link_destroy(c->oml);
err_oml:
	return -1;
}

static void chan_abis_ipa_srv_destroy(struct osmo_chan *chan)
{
	struct chan_abis_ipa_srv *c = (struct chan_abis_ipa_srv *)chan->data;

	osmo_stream_srv_link_destroy(c->rsl);
	osmo_stream_srv_link_destroy(c->oml);
}

static int chan_abis_ipa_srv_open(struct osmo_chan *chan)
{
	struct chan_abis_ipa_srv *c = (struct chan_abis_ipa_srv *)chan->data;
	struct osmo_fd *ofd;
	int ret, on = 1;

	if (osmo_stream_srv_link_open(c->oml) < 0)
		goto err;

	ofd = osmo_stream_srv_link_get_ofd(c->oml);
	ret = setsockopt(ofd->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (ret < 0)
		goto err_oml;

	if (osmo_stream_srv_link_open(c->rsl) < 0)
		goto err_oml;

	ofd = osmo_stream_srv_link_get_ofd(c->rsl);
	ret = setsockopt(ofd->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (ret < 0)
		goto err_rsl;

	return 0;

err_rsl:
	osmo_stream_srv_link_close(c->rsl);
err_oml:
	osmo_stream_srv_link_close(c->oml);
err:
	return -1;
}

static void chan_abis_ipa_srv_close(struct osmo_chan *chan)
{
	struct chan_abis_ipa_srv *c = (struct chan_abis_ipa_srv *)chan->data;

	osmo_stream_srv_link_close(c->oml);
	osmo_stream_srv_link_close(c->rsl);
}

static int chan_abis_ipa_srv_enqueue(struct osmo_chan *c, struct msgb *msg)
{
	osmo_stream_srv_send(msg->dst, msg);
	return 0;
}

void osmo_abis_ipa_srv_set_oml_addr(struct osmo_chan *c, const char *addr)
{
	struct chan_abis_ipa_srv *s = (struct chan_abis_ipa_srv *)&c->data;

	osmo_stream_srv_link_set_addr(s->oml, addr);
}

void osmo_abis_ipa_srv_set_oml_port(struct osmo_chan *c, uint16_t port)
{
	struct chan_abis_ipa_srv *s = (struct chan_abis_ipa_srv *)&c->data;

	osmo_stream_srv_link_set_port(s->oml, port);
}

void osmo_abis_ipa_srv_set_rsl_addr(struct osmo_chan *c, const char *addr)
{
	struct chan_abis_ipa_srv *s = (struct chan_abis_ipa_srv *)&c->data;

	osmo_stream_srv_link_set_addr(s->rsl, addr);
}

void osmo_abis_ipa_srv_set_rsl_port(struct osmo_chan *c, uint16_t port)
{
	struct chan_abis_ipa_srv *s = (struct chan_abis_ipa_srv *)&c->data;

	osmo_stream_srv_link_set_port(s->rsl, port);
}

void osmo_abis_ipa_srv_set_cb_signalmsg(struct osmo_chan *c,
	void (*signal_msg)(struct msgb *msg, int type))
{
	struct chan_abis_ipa_srv *s = (struct chan_abis_ipa_srv *)&c->data;

	s->signal_msg = signal_msg;
}

int
osmo_abis_ipa_unit_add(struct osmo_chan *c, uint16_t site_id, uint16_t bts_id)
{
	struct osmo_ipa_unit *unit;
	struct chan_abis_ipa_srv *s = (struct chan_abis_ipa_srv *)&c->data;
	struct chan_abis_ipa_srv_conn *inst;

	unit = osmo_ipa_unit_alloc(sizeof(struct chan_abis_ipa_srv_conn));
	if (unit == NULL)
		return -1;

	osmo_ipa_unit_set_site_id(unit, site_id);
	osmo_ipa_unit_set_bts_id(unit, bts_id);
	osmo_ipa_unit_add(&s->bts_list, unit);

	inst = osmo_ipa_unit_get_data(unit);
	inst->master = s;

	return 0;
}

static int oml_read_cb(struct osmo_stream_srv *conn);

static int oml_accept_cb(struct osmo_stream_srv_link *srv, int fd)
{
	struct osmo_stream_srv *conn;
	struct osmo_fd *ofd;

	conn = osmo_stream_srv_create(abis_ipa_srv_tall,
				      srv, fd, oml_read_cb, NULL, NULL);
	if (conn == NULL) {
		LOGP(DLINP, LOGL_ERROR, "error while creating connection\n");
		return -1;
	}

	ofd = osmo_stream_srv_get_ofd(conn);

	/* XXX: better use chan_abis_ipa_srv_enqueue. */
	ipaccess_send_id_req(ofd->fd);

	return 0;
}

static int rsl_read_cb(struct osmo_stream_srv *conn);

static int rsl_accept_cb(struct osmo_stream_srv_link *srv, int fd)
{
	struct osmo_stream_srv *conn;
	struct osmo_fd *ofd;

	conn = osmo_stream_srv_create(abis_ipa_srv_tall, srv, fd,
				      rsl_read_cb, NULL, NULL);
	if (conn == NULL) {
		LOGP(DLINP, LOGL_ERROR, "error while creating connection\n");
		return -1;
	}

	ofd = osmo_stream_srv_get_ofd(conn);

	/* XXX: better use chan_abis_ipa_srv_enqueue. */
	ipaccess_send_id_req(ofd->fd);

	return 0;
}

static void abis_ipa_put(struct osmo_ipa_unit *unit)
{
	struct chan_abis_ipa_srv_conn *inst = osmo_ipa_unit_get_data(unit);

	osmo_stream_srv_destroy(inst->oml);
	osmo_stream_srv_destroy(inst->rsl);
	inst->oml = NULL;
	inst->rsl = NULL;
}

static int
abis_ipa_srv_rcvmsg(struct osmo_stream_srv *conn, struct msgb *msg, int type)
{
	uint8_t msg_type = *(msg->l2h);
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	struct osmo_stream_srv_link *link = osmo_stream_srv_get_master(conn);
	struct chan_abis_ipa_srv *s = osmo_stream_srv_link_get_data(link);
	struct chan_abis_ipa_srv_conn *inst;
	int ret;

	/* Handle IPA PING, PONG and ID_ACK messages */
	if (osmo_ipa_rcvmsg_base(msg, ofd, 1)) /* XXX: 1 indicates server */
		return 0;

	if (msg_type == IPAC_MSGT_ID_RESP) {
		struct osmo_ipa_unit *unit;
		struct ipaccess_unit unit_data;

		if (osmo_ipa_parse_msg_id_resp(msg, &unit_data) < 0) {
			LOGP(DLINP, LOGL_ERROR, "bad ID RESP message\n");
			return -EIO;
		}

		unit = osmo_ipa_unit_find(&s->bts_list, unit_data.site_id,
					  unit_data.bts_id);

		if (unit == NULL) {
			LOGP(DLINP, LOGL_ERROR, "Unable to find BTS "
				"configuration for %u/%u/%u, disconnecting\n",
				unit_data.site_id, unit_data.bts_id,
				unit_data.trx_id);
			return 0;
		}
		DEBUGP(DLINP, "Identified BTS %u/%u/%u\n",
			unit_data.site_id, unit_data.bts_id,
			unit_data.trx_id);

		inst = osmo_ipa_unit_get_data(unit);

		if (type == CHAN_SIGN_OML) {
			if (inst->oml) {
				/* link already exists, kill it. */
				osmo_stream_srv_destroy(inst->oml);
				return 0;
			}
			inst->oml = conn;
		} else if (type == CHAN_SIGN_RSL) {
			if (!inst->oml) {
				/* no OML link? Restart from scratch. */
				abis_ipa_put(unit);
				return 0;
			}
			if (inst->rsl) {
				/* RSL link already exists, kill it. */
				osmo_stream_srv_destroy(inst->rsl);
				return 0;
			}
			inst->rsl = conn;
		}
		osmo_stream_srv_set_data(conn, unit);
		ret = 0;
	} else {
		LOGP(DLINP, LOGL_ERROR, "Unknown IPA message type\n");
		ret = -EINVAL;
	}
	return ret;
}

static int read_cb(struct osmo_stream_srv *conn, int type)
{
	int ret;
	struct msgb *msg;
	struct osmo_ipa_unit *unit = osmo_stream_srv_get_data(conn);
	struct chan_abis_ipa_srv_conn *inst;
	struct ipa_head *hh;

	LOGP(DLINP, LOGL_DEBUG, "received message from stream\n");

	msg = osmo_ipa_msg_alloc(0);
	if (msg == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate message\n");
		return 0;
	}
	ret = osmo_stream_srv_recv(conn, msg);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "cannot receive message\n");
		msgb_free(msg);
		if (unit != NULL)
			abis_ipa_put(unit);
		else
			osmo_stream_srv_destroy(conn);

		return 0;
	} else if (ret == 0) {
		/* link has vanished, dead socket. */
		LOGP(DLINP, LOGL_ERROR, "closed connection\n");
		msgb_free(msg);
		if (unit != NULL)
			abis_ipa_put(unit);
		else
			osmo_stream_srv_destroy(conn);

		return 0;
	}
	ret = osmo_ipa_process_msg(msg);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "invalid IPA message\n");
		msgb_free(msg);
	}

	hh = (struct ipa_head *) msg->data;
	if (hh->proto == IPAC_PROTO_IPACCESS) {
		abis_ipa_srv_rcvmsg(conn, msg, type);
		msgb_free(msg);
		return -EIO;
	}

	if (unit == NULL) {
		LOGP(DLINP, LOGL_ERROR, "no IPA unit associated to this "
					"connection\n");
		return -EIO;
	}
	inst = osmo_ipa_unit_get_data(unit);

	if (hh->proto != IPAC_PROTO_OML && hh->proto != IPAC_PROTO_RSL) {
		LOGP(DLINP, LOGL_ERROR, "wrong protocol\n");
		return -EIO;
	}
	msg->dst = conn;

	inst->master->signal_msg(msg, type);

	return 0;
}

static int oml_read_cb(struct osmo_stream_srv *conn)
{
	return read_cb(conn, CHAN_SIGN_OML);
}

static int rsl_read_cb(struct osmo_stream_srv *conn)
{
	return read_cb(conn, CHAN_SIGN_RSL);
}

struct osmo_chan_type chan_abis_ipa_srv = {
	.type		= OSMO_CHAN_ABIS_IPA_SRV,
	.subtype	= OSMO_SUBCHAN_STREAM,
	.name		= "A-bis IPA server",
	.datasiz	= sizeof(struct chan_abis_ipa_srv),
	.create		= chan_abis_ipa_srv_create,
	.destroy	= chan_abis_ipa_srv_destroy,
	.open		= chan_abis_ipa_srv_open,
	.close		= chan_abis_ipa_srv_close,
	.enqueue	= chan_abis_ipa_srv_enqueue,
};
