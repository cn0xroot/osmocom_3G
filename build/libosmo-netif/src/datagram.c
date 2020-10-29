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
#include <netinet/in.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/select.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/socket.h>

#include <osmocom/netif/datagram.h>

/*! \addtogroup datagram Osmocom Datagram Socket
 *  @{
 */

/*! \file datagram.c
 *  \brief Osmocom datagram socket helpers
 */


/*
 * Client side.
 */

#define OSMO_DGRAM_CLI_F_RECONF	(1 << 0)

struct osmo_dgram_tx {
	struct osmo_fd			ofd;
	struct llist_head		tx_queue;
	char				*addr;
	uint16_t			port;
	char				*local_addr;
	uint16_t			local_port;
	int (*write_cb)(struct osmo_dgram_tx *conn);
	void				*data;
	unsigned int			flags;
};

/*! \brief Close an Osmocom Datagram Transmitter
 *  \param[in] conn Osmocom Datagram Transmitter to be closed
 *  We unregister the socket fd from the osmocom select() loop
 *  abstraction and close the socket */
void osmo_dgram_tx_close(struct osmo_dgram_tx *conn)
{
	if (conn->ofd.fd == -1)
		return;
	osmo_fd_unregister(&conn->ofd);
	close(conn->ofd.fd);
	conn->ofd.fd = -1;
}

static int osmo_dgram_tx_write(struct osmo_dgram_tx *conn)
{
	struct msgb *msg;
	struct llist_head *lh;
	int ret;

	LOGP(DLINP, LOGL_DEBUG, "sending data\n");

	if (llist_empty(&conn->tx_queue)) {
		conn->ofd.when &= ~BSC_FD_WRITE;
		return 0;
	}
	lh = conn->tx_queue.next;
	llist_del(lh);
	msg = llist_entry(lh, struct msgb, list);

	ret = send(conn->ofd.fd, msg->data, msg->len, 0);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "error to send (%s)\n",
			strerror(errno));
	}
	msgb_free(msg);
	return 0;
}

static int osmo_dgram_tx_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_dgram_tx *conn = ofd->data;

	if (what & BSC_FD_WRITE) {
		LOGP(DLINP, LOGL_DEBUG, "write\n");
		osmo_dgram_tx_write(conn);
	}
        return 0;
}

/*! \brief Create an Osmocom datagram transmitter
 *  \param[in] ctx talloc context from which to allocate memory
 *  This function allocates a new \ref osmo_dgram_tx and initializes
 *  it with default values
 *  \returns Osmocom Datagram Transmitter; NULL on error */
struct osmo_dgram_tx *osmo_dgram_tx_create(void *ctx)
{
	struct osmo_dgram_tx *conn;

	conn = talloc_zero(ctx, struct osmo_dgram_tx);
	if (!conn)
		return NULL;

	conn->ofd.fd = -1;
	conn->ofd.when |= BSC_FD_READ;
	conn->ofd.priv_nr = 0;	/* XXX */
	conn->ofd.cb = osmo_dgram_tx_fd_cb;
	conn->ofd.data = conn;
	INIT_LLIST_HEAD(&conn->tx_queue);

	return conn;
}


/*! \brief Set the remote address to which we transmit
 *  \param[in] conn Datagram Transmitter to modify
 *  \param[in] addr Remote IP address */
void
osmo_dgram_tx_set_addr(struct osmo_dgram_tx *conn,
				const char *addr)
{
	osmo_talloc_replace_string(conn, &conn->addr, addr);
	conn->flags |= OSMO_DGRAM_CLI_F_RECONF;
}

/*! \brief Set the remote port to which we transmit
 *  \param[in] conn Datagram Transmitter to modify
 *  \param[in] port Remote Port Number */
void
osmo_dgram_tx_set_port(struct osmo_dgram_tx *conn,
				uint16_t port)
{
	conn->port = port;
	conn->flags |= OSMO_DGRAM_CLI_F_RECONF;
}

/*! \brief Set the local address from which we transmit
 *  \param[in] conn Datagram Transmitter to modify
 *  \param[in] addr Local IP address */
void
osmo_dgram_tx_set_local_addr(struct osmo_dgram_tx *conn, const char *addr)
{
	osmo_talloc_replace_string(conn, &conn->local_addr, addr);
	conn->flags |= OSMO_DGRAM_CLI_F_RECONF;
}

/*! \brief Set the local port from which we transmit
 *  \param[in] conn Datagram Transmitter to modify
 *  \param[in] port Local Port Number */
void
osmo_dgram_tx_set_local_port(struct osmo_dgram_tx *conn, uint16_t port)
{
	conn->local_port = port;
	conn->flags |= OSMO_DGRAM_CLI_F_RECONF;
}

/*! \brief Set application private data of the datagram transmitter
 *  \param[in] conn Datagram Transmitter to modify
 *  \param[in] data User-specific data (available in call-back functions) */
void
osmo_dgram_tx_set_data(struct osmo_dgram_tx *conn, void *data)
{
	conn->data = data;
}

/*! \brief Destroy a Osmocom datagram transmitter
 *  \param[in] conn Datagram Transmitter to destroy */
void osmo_dgram_tx_destroy(struct osmo_dgram_tx *conn)
{
	osmo_dgram_tx_close(conn);
	talloc_free(conn);
}

/*! \brief Open connection of an Osmocom datagram transmitter
 *  \param[in] conn Stream Client to connect
 *  \returns 0 on success; negative in case of error */
int osmo_dgram_tx_open(struct osmo_dgram_tx *conn)
{
	int ret;

	/* we are reconfiguring this socket, close existing first. */
	if ((conn->flags & OSMO_DGRAM_CLI_F_RECONF) && conn->ofd.fd >= 0)
		osmo_dgram_tx_close(conn);

	conn->flags &= ~OSMO_DGRAM_CLI_F_RECONF;

	ret = osmo_sock_init2(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			      conn->local_addr, conn->local_port, conn->addr, conn->port,
			      OSMO_SOCK_F_BIND|OSMO_SOCK_F_CONNECT|OSMO_SOCK_F_NONBLOCK);
	if (ret < 0)
		return ret;

	conn->ofd.fd = ret;
	if (osmo_fd_register(&conn->ofd) < 0) {
		close(ret);
		conn->ofd.fd = -1;
		return -EIO;
	}
	return 0;
}

/*! \brief Enqueue data to be sent via an Osmocom datagram transmitter
 *  \param[in] conn Datagram Transmitter through which we want to send
 *  \param[in] msg Message buffer to enqueue in transmit queue */
void osmo_dgram_tx_send(struct osmo_dgram_tx *conn,
				 struct msgb *msg)
{
	msgb_enqueue(&conn->tx_queue, msg);
	conn->ofd.when |= BSC_FD_WRITE;
}

/*
 * Server side.
 */

#define OSMO_DGRAM_RX_F_RECONF	(1 << 0)

struct osmo_dgram_rx {
        struct osmo_fd                  ofd;
        char                            *addr;
        uint16_t                        port;
	int (*cb)(struct osmo_dgram_rx *conn);
        void                            *data;
	unsigned int			flags;
};

/*! \brief Receive data via Osmocom datagram receiver
 *  \param[in] conn Datagram Receiver from which to receive
 *  \param msg pre-allocate message buffer to which received data is appended
 *  \returns number of bytes read, negative on error. */
int osmo_dgram_rx_recv(struct osmo_dgram_rx *conn,
				struct msgb *msg)
{
	int ret;

	ret = recv(conn->ofd.fd, msg->data, msg->data_len, 0);
	if (ret <= 0) {
		LOGP(DLINP, LOGL_ERROR, "error receiving data from tx\n");
		return ret;
	}
	msgb_put(msg, ret);
	LOGP(DLINP, LOGL_DEBUG, "received %d bytes from tx\n", ret);
	return ret;
}

static void osmo_dgram_rx_read(struct osmo_dgram_rx *conn)
{
	LOGP(DLINP, LOGL_DEBUG, "message received\n");

	if (conn->cb)
		conn->cb(conn);
}

static int osmo_dgram_rx_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_dgram_rx *conn = ofd->data;

	LOGP(DLINP, LOGL_DEBUG, "read\n");
	if (what & BSC_FD_READ)
		osmo_dgram_rx_read(conn);

	return 0;
}

/*! \brief Create an Osmocom datagram receiver
 *  \param[in] ctx talloc context from which to allocate memory
 *  This function allocates a new \ref osmo_dgram_rx and initializes
 *  it with default values
 *  \returns Datagram Receiver; NULL on error */
struct osmo_dgram_rx *osmo_dgram_rx_create(void *ctx)
{
	struct osmo_dgram_rx *conn;

	conn = talloc_zero(ctx, struct osmo_dgram_rx);
	if (!conn)
		return NULL;

	conn->ofd.fd = -1;
	conn->ofd.when |= BSC_FD_READ;
	conn->ofd.cb = osmo_dgram_rx_cb;
	conn->ofd.data = conn;

	return conn;
}

/*! \brief Set the local address to which we bind
 *  \param[in] conn Datagram Receiver to modify
 *  \param[in] addr Local IP address */
void osmo_dgram_rx_set_addr(struct osmo_dgram_rx *conn,
				     const char *addr)
{
	osmo_talloc_replace_string(conn, &conn->addr, addr);
	conn->flags |= OSMO_DGRAM_RX_F_RECONF;
}

/*! \brief Set the local port to which we bind
 *  \param[in] conn Datagram Receiver to modify
 *  \param[in] port Local port number */
void osmo_dgram_rx_set_port(struct osmo_dgram_rx *conn,
				     uint16_t port)
{
	conn->port = port;
	conn->flags |= OSMO_DGRAM_RX_F_RECONF;
}

/*! \brief Set the read() call-back of the datagram receiver
 *  \param[in] conn Datagram Receiver to modify
 *  \param[in] read_cb Call-back function executed after read() */
void osmo_dgram_rx_set_read_cb(struct osmo_dgram_rx *conn,
	int (*read_cb)(struct osmo_dgram_rx *conn))
{
	conn->cb = read_cb;
}

/*! \brief Destroy the datagram receiver. Releases Memory.
 *  \param[in] conn Datagram Receiver */
void osmo_dgram_rx_destroy(struct osmo_dgram_rx *conn)
{
	osmo_dgram_rx_close(conn);
	talloc_free(conn);
}

/*! \brief Open the datagram receiver.  This actually initializes the
 *  underlying socket and binds it to the configured ip/port
 *  \param[in] conn Datagram Receiver to open */
int osmo_dgram_rx_open(struct osmo_dgram_rx *conn)
{
	int ret;

	/* we are reconfiguring this socket, close existing first. */
	if ((conn->flags & OSMO_DGRAM_RX_F_RECONF) && conn->ofd.fd >= 0)
		osmo_dgram_rx_close(conn);

	conn->flags &= ~OSMO_DGRAM_RX_F_RECONF;

	ret = osmo_sock_init(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			     conn->addr, conn->port, OSMO_SOCK_F_BIND);
	if (ret < 0)
		return ret;

	conn->ofd.fd = ret;
	if (osmo_fd_register(&conn->ofd) < 0) {
		close(ret);
		conn->ofd.fd = -1;
		return -EIO;
	}
	return 0;
}


/*! \brief Close the datagram receiver and unregister from select loop
 *  Does not destroy the datagram receiver, merely closes it!
 *  \param[in] conn Stream Server Link to close */
void osmo_dgram_rx_close(struct osmo_dgram_rx *conn)
{
	if (conn->ofd.fd == -1)
		return;
	osmo_fd_unregister(&conn->ofd);
	close(conn->ofd.fd);
	conn->ofd.fd = -1;
}

/*
 * Client+Server (bidirectional communications).
 */

struct osmo_dgram {
	struct osmo_dgram_rx	*rx;
	struct osmo_dgram_tx	*tx;
	int (*read_cb)(struct osmo_dgram *conn);
	void				*data;
};

static int
dgram_rx_cb(struct osmo_dgram_rx *rx)
{
	struct osmo_dgram *conn = rx->data;

	if (conn->read_cb)
		return conn->read_cb(conn);

	return 0;
}


/*! \brief Create an Osmocom datagram transceiver (bidirectional)
 *  \param[in] ctx talloc context from which to allocate memory
 *  This function allocates a new \ref osmo_dgram and initializes
 *  it with default values.  Internally, the Transceiver is based on a
 *  tuple of transmitter (\ref osmo_dgram_tx) and receiver (\ref osmo_dgram_rx)
 *  \returns Osmocom Datagram Transceiver; NULL on error */
struct osmo_dgram *osmo_dgram_create(void *ctx)
{
	struct osmo_dgram *conn;

	conn = talloc_zero(ctx, struct osmo_dgram);
	if (!conn)
		return NULL;

	conn->rx= osmo_dgram_rx_create(ctx);
	if (conn->rx == NULL)
		return NULL;

	osmo_dgram_rx_set_read_cb(conn->rx, dgram_rx_cb);
	conn->rx->data = conn;

	conn->tx = osmo_dgram_tx_create(ctx);
	if (conn->tx == NULL) {
		osmo_dgram_rx_destroy(conn->rx);
		return NULL;
	}

	return conn;
}

/*! \brief Destroy a Osmocom datagram transceiver
 *  \param[in] conn Datagram Transceiver to destroy */
void osmo_dgram_destroy(struct osmo_dgram *conn)
{
	osmo_dgram_rx_destroy(conn->rx);
	osmo_dgram_tx_destroy(conn->tx);
}

/*! \brief Set the local address to which we bind
 *  \param[in] conn Datagram Transceiver to modify
 *  \param[in] addr Local IP address */
void
osmo_dgram_set_local_addr(struct osmo_dgram *conn, const char *addr)
{
	osmo_dgram_rx_set_addr(conn->rx, addr);
}

/*! \brief Set the remote address to which we transmit/connect
 *  \param[in] conn Datagram Transceiver to modify
 *  \param[in] addr Remote IP address */
void
osmo_dgram_set_remote_addr(struct osmo_dgram *conn, const char *addr)
{
	osmo_dgram_tx_set_addr(conn->tx, addr);
}

/*! \brief Set the local port to which we bind
 *  \param[in] conn Datagram Transceiver to modify
 *  \param[in] port Local Port Number */
void
osmo_dgram_set_local_port(struct osmo_dgram *conn, uint16_t port)
{
	osmo_dgram_rx_set_port(conn->rx, port);
}

/*! \brief Set the remote port to which we transmit
 *  \param[in] conn Datagram Transceiver to modify
 *  \param[in] port Remote Port Number */
void
osmo_dgram_set_remote_port(struct osmo_dgram *conn, uint16_t port)
{
	osmo_dgram_tx_set_port(conn->tx, port);
}

/*! \brief Set the read() call-back of the datagram receiver
 *  \param[in] conn Datagram Receiver to modify
 *  \param[in] read_cb Call-back function executed after read() */
void osmo_dgram_set_read_cb(struct osmo_dgram *conn,
			    int (*read_cb)(struct osmo_dgram *conn))
{
	conn->read_cb = read_cb;
}

/*! \brief Set application private data of the datagram transmitter
 *  \param[in] conn Datagram Transmitter to modify
 *  \param[in] data User-specific data (available in call-back functions) */
void osmo_dgram_set_data(struct osmo_dgram *conn, void *data)
{
	conn->data = data;
}

/*! \brief Get application private data of the datagram transceiver
 *  \param[in] conn Datagram Transceiver
 *  \returns Application private data, as set by \ref osmo_dgram_set_data() */
void *osmo_dgram_get_data(struct osmo_dgram *conn)
{
	return conn->data;
}

/*! \brief Open the datagram transceiver.  This actually initializes the
 * underlying sockets and binds/connects them to the configured ips/ports
 *  \param[in] conn Datagram Transceiver to open */
int osmo_dgram_open(struct osmo_dgram *conn)
{
	int ret;

	ret = osmo_dgram_rx_open(conn->rx);
	if (ret < 0)
		return ret;

	ret = osmo_dgram_tx_open(conn->tx);
	if (ret < 0) {
		osmo_dgram_rx_close(conn->rx);
		return ret;
	}
	return ret;
}

/*! \brief Close an Osmocom Datagram Transceiver
 *  \param[in] conn Osmocom Datagram Transceiver to be closed
 *  We unregister the socket fds from the osmocom select() loop
 *  and close them. */
void osmo_dgram_close(struct osmo_dgram *conn)
{
	osmo_dgram_rx_close(conn->rx);
	osmo_dgram_tx_close(conn->tx);
}

/*! \brief Enqueue data to be sent via an Osmocom datagram transceiver
 *  \param[in] conn Datagram Transceiver through which we want to send
 *  \param[in] msg Message buffer to enqueue in transmit queue */
void osmo_dgram_send(struct osmo_dgram *conn, struct msgb *msg)
{
	osmo_dgram_tx_send(conn->tx, msg);
}

/*! \brief Receive data via Osmocom datagram transceiver
 *  \param[in] conn Datagram Transceiver from which to receive
 *  \param msg pre-allocate message buffer to which received data is appended
 *  \returns number of bytes read, negative on error. */
int osmo_dgram_recv(struct osmo_dgram *conn, struct msgb *msg)
{
	return osmo_dgram_rx_recv(conn->rx, msg);
}

/*! @} */
