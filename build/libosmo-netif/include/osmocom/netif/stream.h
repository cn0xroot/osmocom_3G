#ifndef _OSMO_STREAM_H_
#define _OSMO_STREAM_H_

#include <stdbool.h>
#include <stdint.h>

/*! \addtogroup stream
 *  @{
 */

/*! \brief Access the SCTP PPID from the msgb control buffer */
#define msgb_sctp_ppid(msg)             (msg)->cb[3]
/*! \brief Access the SCTP Stream ID from the msgb control buffer */
#define msgb_sctp_stream(msg)           (msg)->cb[4]

/*! \brief Osmocom Stream Server Link: A server socket listening/accepting */
struct osmo_stream_srv_link;

struct osmo_stream_srv_link *osmo_stream_srv_link_create(void *ctx);
void osmo_stream_srv_link_destroy(struct osmo_stream_srv_link *link);

void osmo_stream_srv_link_set_nodelay(struct osmo_stream_srv_link *link, bool nodelay);
void osmo_stream_srv_link_set_addr(struct osmo_stream_srv_link *link, const char *addr);
void osmo_stream_srv_link_set_port(struct osmo_stream_srv_link *link, uint16_t port);
void osmo_stream_srv_link_set_proto(struct osmo_stream_srv_link *link, uint16_t proto);
void osmo_stream_srv_link_set_accept_cb(struct osmo_stream_srv_link *link, int (*accept_cb)(struct osmo_stream_srv_link *link, int fd));
void osmo_stream_srv_link_set_data(struct osmo_stream_srv_link *link, void *data);
void *osmo_stream_srv_link_get_data(struct osmo_stream_srv_link *link);
struct osmo_fd *osmo_stream_srv_link_get_ofd(struct osmo_stream_srv_link *link);

int osmo_stream_srv_link_open(struct osmo_stream_srv_link *link);
void osmo_stream_srv_link_close(struct osmo_stream_srv_link *link);

/*! \brief Osmocom Stream Server: Single connection accept()ed via \ref
 * osmo_stream_srv_link */
struct osmo_stream_srv;

struct osmo_stream_srv *osmo_stream_srv_create(void *ctx, struct osmo_stream_srv_link *link, int fd, int (*cb)(struct osmo_stream_srv *conn), int (*closed_cb)(struct osmo_stream_srv *conn), void *data);
void *osmo_stream_srv_get_data(struct osmo_stream_srv *conn);
struct osmo_stream_srv_link *osmo_stream_srv_get_master(struct osmo_stream_srv *conn);
struct osmo_fd *osmo_stream_srv_get_ofd(struct osmo_stream_srv *srv);
void osmo_stream_srv_destroy(struct osmo_stream_srv *conn);

void osmo_stream_srv_set_data(struct osmo_stream_srv *conn, void *data);

void osmo_stream_srv_send(struct osmo_stream_srv *conn, struct msgb *msg);
int osmo_stream_srv_recv(struct osmo_stream_srv *conn, struct msgb *msg);

/*! \brief Osmocom Stream Client: Single client connection */
struct osmo_stream_cli;

void osmo_stream_cli_set_nodelay(struct osmo_stream_cli *cli, bool nodelay);
void osmo_stream_cli_set_addr(struct osmo_stream_cli *cli, const char *addr);
void osmo_stream_cli_set_port(struct osmo_stream_cli *cli, uint16_t port);
void osmo_stream_cli_set_proto(struct osmo_stream_cli *cli, uint16_t proto);
void osmo_stream_cli_set_local_addr(struct osmo_stream_cli *cli, const char *addr);
void osmo_stream_cli_set_local_port(struct osmo_stream_cli *cli, uint16_t port);
void osmo_stream_cli_set_data(struct osmo_stream_cli *cli, void *data);
void osmo_stream_cli_set_reconnect_timeout(struct osmo_stream_cli *cli, int timeout);
void *osmo_stream_cli_get_data(struct osmo_stream_cli *cli);
struct osmo_fd *osmo_stream_cli_get_ofd(struct osmo_stream_cli *cli);
void osmo_stream_cli_set_connect_cb(struct osmo_stream_cli *cli, int (*connect_cb)(struct osmo_stream_cli *cli));
void osmo_stream_cli_set_read_cb(struct osmo_stream_cli *cli, int (*read_cb)(struct osmo_stream_cli *cli));
void osmo_stream_cli_reconnect(struct osmo_stream_cli *cli);

struct osmo_stream_cli *osmo_stream_cli_create(void *ctx);
void osmo_stream_cli_destroy(struct osmo_stream_cli *cli);

int osmo_stream_cli_open(struct osmo_stream_cli *cli);
int osmo_stream_cli_open2(struct osmo_stream_cli *cli, int reconnect);
void osmo_stream_cli_close(struct osmo_stream_cli *cli);

void osmo_stream_cli_send(struct osmo_stream_cli *cli, struct msgb *msg);
int osmo_stream_cli_recv(struct osmo_stream_cli *conn, struct msgb *msg);

/*! @} */

#endif
