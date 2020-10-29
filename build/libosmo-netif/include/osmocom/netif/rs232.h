#ifndef _OSMO_RS232_H_
#define _OSMO_RS232_H_

struct osmo_rs232;

struct osmo_rs232 *osmo_rs232_create(void *ctx);

void osmo_rs232_set_serial_port(struct osmo_rs232 *, const char *serial_port);
void osmo_rs232_set_delay_us(struct osmo_rs232 *, int delay_us);
void osmo_rs232_set_baudrate(struct osmo_rs232 *, int baudrate);
void osmo_rs232_set_read_cb(struct osmo_rs232 *r, int (*read_cb)(struct osmo_rs232 *r));

int osmo_rs232_open(struct osmo_rs232 *r);

int osmo_rs232_read(struct osmo_rs232 *r, struct msgb *msg);
int osmo_rs232_write(struct osmo_rs232 *r, struct msgb *msg);

void osmo_rs232_close(struct osmo_rs232 *r);
void osmo_rs232_destroy(struct osmo_rs232 *r);

#endif /* _OSMO_RS232_H_ */
