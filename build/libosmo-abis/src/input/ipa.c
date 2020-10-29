#include "internal.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <osmocom/core/select.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/abis/ipaccess.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/backtrace.h>

#include <osmocom/abis/ipa.h>

void ipa_msg_push_header(struct msgb *msg, uint8_t proto)
{
	struct ipaccess_head *hh;

	msg->l2h = msg->data;
	hh = (struct ipaccess_head *) msgb_push(msg, sizeof(*hh));
	hh->proto = proto;
	hh->len = htons(msgb_l2len(msg));
}

void ipa_client_conn_close(struct ipa_client_conn *link)
{
	/* be safe against multiple calls */
	if (link->ofd->fd != -1) {
		osmo_fd_unregister(link->ofd);
		close(link->ofd->fd);
		link->ofd->fd = -1;
	}
	msgb_free(link->pending_msg);
	link->pending_msg = NULL;
}

static void ipa_client_read(struct ipa_client_conn *link)
{
	struct osmo_fd *ofd = link->ofd;
	struct msgb *msg;
	int ret;

	LOGP(DLINP, LOGL_DEBUG, "message received\n");

	ret = ipa_msg_recv_buffered(ofd->fd, &msg, &link->pending_msg);
	if (ret < 0) {
		if (ret == -EAGAIN)
			return;
		if (ret == -EPIPE || ret == -ECONNRESET)
			LOGP(DLINP, LOGL_ERROR, "lost connection with server\n");
		ipa_client_conn_close(link);
		if (link->updown_cb)
			link->updown_cb(link, 0);
		return;
	} else if (ret == 0) {
		LOGP(DLINP, LOGL_ERROR, "connection closed with server\n");
		ipa_client_conn_close(link);
		if (link->updown_cb)
			link->updown_cb(link, 0);
		return;
	}
	if (link->read_cb)
		link->read_cb(link, msg);
}

static void ipa_client_write(struct ipa_client_conn *link)
{
	if (link->write_cb)
		link->write_cb(link);
}

static int ipa_client_write_default_cb(struct ipa_client_conn *link)
{
	struct osmo_fd *ofd = link->ofd;
	struct msgb *msg;
	struct llist_head *lh;
	int ret;

	LOGP(DLINP, LOGL_DEBUG, "sending data\n");

	if (llist_empty(&link->tx_queue)) {
		ofd->when &= ~BSC_FD_WRITE;
		return 0;
	}
	lh = link->tx_queue.next;
	llist_del(lh);
	msg = llist_entry(lh, struct msgb, list);

	ret = send(link->ofd->fd, msg->data, msg->len, 0);
	if (ret < 0) {
		if (errno == EPIPE || errno == ENOTCONN) {
			ipa_client_conn_close(link);
			if (link->updown_cb)
				link->updown_cb(link, 0);
		}
		LOGP(DLINP, LOGL_ERROR, "error to send\n");
	}
	msgb_free(msg);
	return 0;
}

static int ipa_client_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct ipa_client_conn *link = ofd->data;
	int error, ret;
	socklen_t len = sizeof(error);

	switch(link->state) {
	case IPA_CLIENT_LINK_STATE_CONNECTING:
		ret = getsockopt(ofd->fd, SOL_SOCKET, SO_ERROR, &error, &len);
		if (ret >= 0 && error > 0) {
			ipa_client_conn_close(link);
			if (link->updown_cb)
				link->updown_cb(link, 0);
			return 0;
		}
		ofd->when &= ~BSC_FD_WRITE;
		LOGP(DLINP, LOGL_NOTICE, "connection done.\n");
		link->state = IPA_CLIENT_LINK_STATE_CONNECTED;
		if (link->updown_cb)
			link->updown_cb(link, 1);
		break;
	case IPA_CLIENT_LINK_STATE_CONNECTED:
		if (what & BSC_FD_READ) {
			LOGP(DLINP, LOGL_DEBUG, "connected read\n");
			ipa_client_read(link);
		}
		if (what & BSC_FD_WRITE) {
			LOGP(DLINP, LOGL_DEBUG, "connected write\n");
			ipa_client_write(link);
		}
		break;
	default:
		break;
	}
        return 0;
}

struct ipa_client_conn *
ipa_client_conn_create(void *ctx, struct e1inp_ts *ts,
		       int priv_nr, const char *addr, uint16_t port,
		       void (*updown_cb)(struct ipa_client_conn *link, int up),
		       int (*read_cb)(struct ipa_client_conn *link,
				      struct msgb *msgb),
		       int (*write_cb)(struct ipa_client_conn *link),
		       void *data)
{
	struct ipa_client_conn *ipa_link;

	ipa_link = talloc_zero(ctx, struct ipa_client_conn);
	if (!ipa_link)
		return NULL;

	if (ts) {
		if (ts->line->driver == NULL) {
			talloc_free(ipa_link);
			return NULL;
		}
		ipa_link->ofd = &ts->driver.ipaccess.fd;
	} else {
		ipa_link->ofd = talloc_zero(ctx, struct osmo_fd);
		if (ipa_link->ofd == NULL) {
			talloc_free(ipa_link);
			return NULL;
		}
	}

	ipa_link->ofd->when |= BSC_FD_READ | BSC_FD_WRITE;
	ipa_link->ofd->priv_nr = priv_nr;
	ipa_link->ofd->cb = ipa_client_fd_cb;
	ipa_link->ofd->data = ipa_link;
	ipa_link->ofd->fd = -1;
	ipa_link->state = IPA_CLIENT_LINK_STATE_CONNECTING;
	ipa_link->addr = talloc_strdup(ipa_link, addr);
	ipa_link->port = port;
	ipa_link->updown_cb = updown_cb;
	ipa_link->read_cb = read_cb;
	/* default to generic write callback if not set. */
	if (write_cb == NULL)
		ipa_link->write_cb = ipa_client_write_default_cb;
	else
		ipa_link->write_cb = write_cb;

	if (ts)
		ipa_link->line = ts->line;
	ipa_link->data = data;
	INIT_LLIST_HEAD(&ipa_link->tx_queue);

	return ipa_link;
}

void ipa_client_conn_destroy(struct ipa_client_conn *link)
{
	talloc_free(link);
}

int ipa_client_conn_open(struct ipa_client_conn *link)
{
	int ret;

	link->state = IPA_CLIENT_LINK_STATE_CONNECTING;
	ret = osmo_sock_init(AF_INET, SOCK_STREAM, IPPROTO_TCP,
			     link->addr, link->port,
			     OSMO_SOCK_F_CONNECT|OSMO_SOCK_F_NONBLOCK);
	if (ret < 0)
		return ret;
	link->ofd->fd = ret;
	link->ofd->when |= BSC_FD_WRITE;
	if (osmo_fd_register(link->ofd) < 0) {
		close(ret);
		link->ofd->fd = -1;
		return -EIO;
	}

	return 0;
}

void ipa_client_conn_send(struct ipa_client_conn *link, struct msgb *msg)
{
	msgb_enqueue(&link->tx_queue, msg);
	link->ofd->when |= BSC_FD_WRITE;
}

size_t ipa_client_conn_clear_queue(struct ipa_client_conn *link)
{
	size_t deleted = 0;

	while (!llist_empty(&link->tx_queue)) {
		struct msgb *msg = msgb_dequeue(&link->tx_queue);
		msgb_free(msg);
		deleted += 1;
	}

	link->ofd->when &= ~BSC_FD_WRITE;
	return deleted;
}

static int ipa_server_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	int fd, ret;
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);
	struct ipa_server_link *link = ofd->data;

	fd = accept(ofd->fd, (struct sockaddr *)&sa, &sa_len);
	if (fd < 0) {
		LOGP(DLINP, LOGL_ERROR, "failed to accept from origin "
			"peer, reason=`%s'\n", strerror(errno));
		return fd;
	}
	LOGP(DLINP, LOGL_NOTICE, "accept()ed new link from %s to port %u\n",
		inet_ntoa(sa.sin_addr), link->port);

	ret = link->accept_cb(link, fd);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR,
		     "failed to processs accept()ed new link, "
		     "reason=`%s'\n", strerror(-ret));
		close(fd);
		return ret;
	}

	return 0;
}

struct ipa_server_link *
ipa_server_link_create(void *ctx, struct e1inp_line *line,
		       const char *addr, uint16_t port,
		       int (*accept_cb)(struct ipa_server_link *link, int fd),
		       void *data)
{
	struct ipa_server_link *ipa_link;

	OSMO_ASSERT(accept_cb != NULL);

	ipa_link = talloc_zero(ctx, struct ipa_server_link);
	if (!ipa_link)
		return NULL;

	ipa_link->ofd.when |= BSC_FD_READ | BSC_FD_WRITE;
	ipa_link->ofd.cb = ipa_server_fd_cb;
	ipa_link->ofd.data = ipa_link;
	ipa_link->addr = talloc_strdup(ipa_link, addr);
	ipa_link->port = port;
	ipa_link->accept_cb = accept_cb;
	ipa_link->line = line;
	ipa_link->data = data;

	return ipa_link;

}

void ipa_server_link_destroy(struct ipa_server_link *link)
{
	talloc_free(link);
}

int ipa_server_link_open(struct ipa_server_link *link)
{
	int ret;

	ret = osmo_sock_init(AF_INET, SOCK_STREAM, IPPROTO_TCP,
			     link->addr, link->port, OSMO_SOCK_F_BIND);
	if (ret < 0)
		return ret;

	link->ofd.fd = ret;
	if (osmo_fd_register(&link->ofd) < 0) {
		close(ret);
		return -EIO;
	}
	return 0;
}

void ipa_server_link_close(struct ipa_server_link *link)
{
	osmo_fd_unregister(&link->ofd);
	close(link->ofd.fd);
}

static void ipa_server_conn_read(struct ipa_server_conn *conn)
{
	struct osmo_fd *ofd = &conn->ofd;
	struct msgb *msg;
	int ret;

	LOGP(DLINP, LOGL_DEBUG, "message received\n");

	ret = ipa_msg_recv_buffered(ofd->fd, &msg, &conn->pending_msg);
	if (ret < 0) {
		if (ret == -EAGAIN)
			return;
		if (ret == -EPIPE || ret == -ECONNRESET)
			LOGP(DLINP, LOGL_ERROR, "lost connection with server\n");
		ipa_server_conn_destroy(conn);
		return;
	} else if (ret == 0) {
		LOGP(DLINP, LOGL_ERROR, "connection closed with server\n");
		ipa_server_conn_destroy(conn);
		return;
	}
	if (conn->cb)
		conn->cb(conn, msg);

	return;
}

static void ipa_server_conn_write(struct ipa_server_conn *conn)
{
	struct osmo_fd *ofd = &conn->ofd;
	struct msgb *msg;
	struct llist_head *lh;
	int ret;

	LOGP(DLINP, LOGL_DEBUG, "sending data\n");

	if (llist_empty(&conn->tx_queue)) {
		ofd->when &= ~BSC_FD_WRITE;
		return;
	}
	lh = conn->tx_queue.next;
	llist_del(lh);
	msg = llist_entry(lh, struct msgb, list);

	ret = send(conn->ofd.fd, msg->data, msg->len, 0);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "error to send\n");
	}
	msgb_free(msg);
}

static int ipa_server_conn_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct ipa_server_conn *conn = ofd->data;

	LOGP(DLINP, LOGL_DEBUG, "connected read/write\n");
	if (what & BSC_FD_READ)
		ipa_server_conn_read(conn);
	if (what & BSC_FD_WRITE)
		ipa_server_conn_write(conn);

	return 0;
}

struct ipa_server_conn *
ipa_server_conn_create(void *ctx, struct ipa_server_link *link, int fd,
		int (*cb)(struct ipa_server_conn *conn, struct msgb *msg),
		int (*closed_cb)(struct ipa_server_conn *conn), void *data)
{
	struct ipa_server_conn *conn;
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);

	conn = talloc_zero(ctx, struct ipa_server_conn);
	if (conn == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate new peer in server, "
			"reason=`%s'\n", strerror(errno));
		return NULL;
	}
	conn->server = link;
	conn->ofd.fd = fd;
	conn->ofd.data = conn;
	conn->ofd.cb = ipa_server_conn_cb;
	conn->ofd.when = BSC_FD_READ;
	conn->cb = cb;
	conn->closed_cb = closed_cb;
	conn->data = data;
	INIT_LLIST_HEAD(&conn->tx_queue);

	if (!getpeername(fd, (struct sockaddr *)&sa, &sa_len)) {
		char *str = inet_ntoa(sa.sin_addr);
		conn->addr = talloc_strdup(conn, str);
		conn->port = ntohs(sa.sin_port);
	}

	if (osmo_fd_register(&conn->ofd) < 0) {
		LOGP(DLINP, LOGL_ERROR, "could not register FD\n");
		talloc_free(conn);
		return NULL;
	}
	return conn;
}

int ipa_server_conn_ccm(struct ipa_server_conn *conn, struct msgb *msg)
{
	struct tlv_parsed tlvp;
	uint8_t msg_type = *(msg->l2h);
	struct ipaccess_unit unit_data = {};
	char *unitid;
	int len, rc;

	/* shared CCM handling on both server and client */
	rc = ipa_ccm_rcvmsg_base(msg, &conn->ofd);
	switch (rc) {
	case -1:
		/* error in IPA CCM processing */
		goto err;
	case 1:
		/* IPA CCM message that was handled in _base */
		return 0;
	case 0:
		/* IPA CCM message that we need to handle */
		break;
	default:
		/* Error */
		LOGP(DLINP, LOGL_ERROR, "Unexpected return from "
		     "ipa_ccm_rcvmsg_base: %d\n", rc);
		goto err;
	}

	switch (msg_type) {
	case IPAC_MSGT_ID_RESP:
		rc = ipa_ccm_idtag_parse(&tlvp, (uint8_t *)msg->l2h + 2,
					 msgb_l2len(msg)-2);
		if (rc < 0) {
			LOGP(DLINP, LOGL_ERROR, "IPA CCM RESPonse with "
				"malformed TLVs\n");
			goto err;
		}
		if (!TLVP_PRESENT(&tlvp, IPAC_IDTAG_UNIT)) {
			LOGP(DLINP, LOGL_ERROR, "IPA CCM RESP without "
				"unit ID\n");
			goto err;
		}
		len = TLVP_LEN(&tlvp, IPAC_IDTAG_UNIT);
		if (len < 1) {
			LOGP(DLINP, LOGL_ERROR, "IPA CCM RESP with short"
				"unit ID\n");
			goto err;
		}
		unitid = (char *) TLVP_VAL(&tlvp, IPAC_IDTAG_UNIT);
		unitid[len-1] = '\0';
		ipa_parse_unitid(unitid, &unit_data);

		/* FIXME */
		rc = conn->ccm_cb(conn, msg, &tlvp, &unit_data);
		if (rc < 0)
			goto err;
		break;
	default:
		LOGP(DLINP, LOGL_ERROR, "Unknown IPA message type\n");
		break;
	}
	return 0;
err:
	/* in case of any error, we close the connection */
	ipa_server_conn_destroy(conn);
	return -1;
}

void ipa_server_conn_destroy(struct ipa_server_conn *conn)
{
	close(conn->ofd.fd);
	msgb_free(conn->pending_msg);
	osmo_fd_unregister(&conn->ofd);
	if (conn->closed_cb)
		conn->closed_cb(conn);
	talloc_free(conn);
}

void ipa_server_conn_send(struct ipa_server_conn *conn, struct msgb *msg)
{
	msgb_enqueue(&conn->tx_queue, msg);
	conn->ofd.when |= BSC_FD_WRITE;
}
