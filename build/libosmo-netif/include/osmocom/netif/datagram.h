#ifndef _OSMO_DGRAM_H_
#define _OSMO_DGRAM_H_

struct osmo_dgram_tx;

struct osmo_dgram_tx *osmo_dgram_tx_create(void *ctx);
void osmo_dgram_tx_destroy(struct osmo_dgram_tx *conn);

void osmo_dgram_tx_set_addr(struct osmo_dgram_tx *conn, const char *addr);
void osmo_dgram_tx_set_port(struct osmo_dgram_tx *conn, uint16_t port);
void osmo_dgram_tx_set_local_addr(struct osmo_dgram_tx *conn, const char *addr);
void osmo_dgram_tx_set_local_port(struct osmo_dgram_tx *conn, uint16_t port);
void osmo_dgram_tx_set_data(struct osmo_dgram_tx *conn, void *data);

int osmo_dgram_tx_open(struct osmo_dgram_tx *conn);
void osmo_dgram_tx_close(struct osmo_dgram_tx *conn);

void osmo_dgram_tx_send(struct osmo_dgram_tx *conn, struct msgb *msg);

struct osmo_dgram_rx;

struct osmo_dgram_rx *osmo_dgram_rx_create(void *ctx);

void osmo_dgram_rx_set_addr(struct osmo_dgram_rx *conn, const char *addr);
void osmo_dgram_rx_set_port(struct osmo_dgram_rx *conn, uint16_t port);
void osmo_dgram_rx_set_read_cb(struct osmo_dgram_rx *conn, int (*read_cb)(struct osmo_dgram_rx *conn));
void osmo_dgram_rx_destroy(struct osmo_dgram_rx *conn);

int osmo_dgram_rx_open(struct osmo_dgram_rx *conn);
void osmo_dgram_rx_close(struct osmo_dgram_rx *conn);

int osmo_dgram_rx_recv(struct osmo_dgram_rx *conn, struct msgb *msg);

struct osmo_dgram;

struct osmo_dgram *osmo_dgram_create(void *ctx);
void osmo_dgram_destroy(struct osmo_dgram *conn);

int osmo_dgram_open(struct osmo_dgram *conn);
void osmo_dgram_close(struct osmo_dgram *conn);

void osmo_dgram_set_local_addr(struct osmo_dgram *conn, const char *addr);
void osmo_dgram_set_remote_addr(struct osmo_dgram *conn, const char *addr);
void osmo_dgram_set_local_port(struct osmo_dgram *conn, uint16_t port);
void osmo_dgram_set_remote_port(struct osmo_dgram *conn, uint16_t port);
void osmo_dgram_set_read_cb(struct osmo_dgram *conn, int (*read_cb)(struct osmo_dgram *conn));
void osmo_dgram_set_data(struct osmo_dgram *conn, void *data);
void *osmo_dgram_get_data(struct osmo_dgram *conn);

void osmo_dgram_send(struct osmo_dgram *conn, struct msgb *msg);
int osmo_dgram_recv(struct osmo_dgram *conn, struct msgb *msg);

#endif
