/* T-Link interface using POSIX serial port */

/* (C) 2008-2011 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * Authors:	Harald Welte <laforge@gnumonks.org>
 *		Pablo Neira Ayuso <pablo@gnumonks.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>

#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/abis/e1_input.h>

static void *tall_rs232_ctx;

struct serial_handle {
	struct e1inp_line	*line;

	struct msgb		*rx_msg;
	unsigned int		rxmsg_bytes_missing;

	unsigned int		delay_ms;
};

#define CRAPD_HDR_LEN	10

static int handle_ser_write(struct osmo_fd *bfd);

static void rs232_build_msg(struct msgb *msg)
{
	uint8_t *crapd;
	unsigned int len;

	msg->l2h = msg->data;

	/* prepend CRAPD header */
	crapd = msgb_push(msg, CRAPD_HDR_LEN);

	len = msg->len - 2;

	crapd[0] = (len >> 8) & 0xff;
	crapd[1] = len & 0xff; /* length of bytes startign at crapd[2] */
	crapd[2] = 0x00;
	crapd[3] = 0x07;
	crapd[4] = 0x01;
	crapd[5] = 0x3e;
	crapd[6] = 0x00;
	crapd[7] = 0x00;
	crapd[8] = msg->len - 10; /* length of bytes starting at crapd[10] */
	crapd[9] = crapd[8] ^ 0x38;
}

/* select.c callback in case we can write to the rs232 */
static int handle_ser_write(struct osmo_fd *bfd)
{
	struct serial_handle *sh = bfd->data;
	struct e1inp_ts *e1i_ts = &sh->line->ts[0];
	struct e1inp_sign_link *sign_link;
	struct msgb *msg;
	int written;

	bfd->when &= ~BSC_FD_WRITE;

	/* get the next msg for this timeslot */
	msg = e1inp_tx_ts(e1i_ts, &sign_link);
	if (!msg) {
		/* no message after tx delay timer */
		return 0;
	}
	DEBUGP(DLMI, "rs232 TX: %s\n", osmo_hexdump(msg->data, msg->len));

	rs232_build_msg(msg);

	/* send over serial line */
	written = write(bfd->fd, msg->data, msg->len);
	if (written < msg->len) {
		LOGP(DLMI, LOGL_ERROR, "rs232: short write\n");
		msgb_free(msg);
		return -1;
	}

	msgb_free(msg);
	usleep(sh->delay_ms*1000);

	return 0;
}

#define SERIAL_ALLOC_SIZE	300

/* select.c callback in case we can read from the rs232 */
static int handle_ser_read(struct osmo_fd *bfd)
{
	struct serial_handle *sh = bfd->data;
	struct msgb *msg;
	int rc = 0;

	if (!sh->rx_msg) {
		sh->rx_msg = msgb_alloc(SERIAL_ALLOC_SIZE, "rs232 Rx");
		sh->rx_msg->l2h = NULL;
	}
	msg = sh->rx_msg;

	/* first read two byes to obtain length */
	if (msg->len < 2) {
		rc = read(bfd->fd, msg->tail, 2 - msg->len);
		if (rc < 0) {
			LOGP(DLMI, LOGL_ERROR, "rs232: error reading from "
				"serial port: %s\n", strerror(errno));
			msgb_free(msg);
			return rc;
		}
		msgb_put(msg, rc);

		if (msg->len >= 2) {
			/* parse CRAPD payload length */
			if (msg->data[0] != 0) {
				LOGP(DLMI, LOGL_ERROR,
					"Suspicious header byte 0: 0x%02x\n",
					msg->data[0]);
			}
			sh->rxmsg_bytes_missing = msg->data[0] << 8;
			sh->rxmsg_bytes_missing += msg->data[1];

			if (sh->rxmsg_bytes_missing < CRAPD_HDR_LEN -2) {
				LOGP(DLMI, LOGL_ERROR,
					"Invalid length in hdr: %u\n",
					sh->rxmsg_bytes_missing);
			}
		}
	} else {
		/* try to read as many of the missing bytes as are available */
		rc = read(bfd->fd, msg->tail, sh->rxmsg_bytes_missing);
		if (rc < 0) {
			LOGP(DLMI, LOGL_ERROR, "rs232: error reading from "
				"serial port: %s", strerror(errno));
			msgb_free(msg);
			return rc;
		}
		msgb_put(msg, rc);
		sh->rxmsg_bytes_missing -= rc;

		if (sh->rxmsg_bytes_missing == 0) {
			struct e1inp_ts *e1i_ts = &sh->line->ts[0];

			/* we have one complete message now */
			sh->rx_msg = NULL;

			if (msg->len > CRAPD_HDR_LEN)
				msg->l2h = msg->data + CRAPD_HDR_LEN;

			DEBUGP(DLMI, "rs232 RX: %s",
				osmo_hexdump(msg->data, msg->len));

			/* don't use e1inp_tx_ts() here, this header does not
			 * contain any SAPI and TEI values. */
			if (!e1i_ts->line->ops->sign_link) {
				LOGP(DLMI, LOGL_ERROR, "rs232: no callback set, "
					"skipping message.\n");
					return -EINVAL;
			}
			e1i_ts->line->ops->sign_link(msg);
		}
	}

	return rc;
}

/* select.c callback */
static int serial_fd_cb(struct osmo_fd *bfd, unsigned int what)
{
	int rc = 0;

	if (what & BSC_FD_READ)
		rc = handle_ser_read(bfd);

	if (rc < 0)
		return rc;

	if (what & BSC_FD_WRITE)
		rc = handle_ser_write(bfd);

	return rc;
}

static int rs232_want_write(struct e1inp_ts *e1i_ts)
{
	e1i_ts->driver.rs232.fd.when |= BSC_FD_WRITE;

	return 0;
}

static int
rs232_setup(struct e1inp_line *line, const char *serial_port, unsigned int delay_ms)
{
	int rc;
	struct osmo_fd *bfd = &line->ts[0].driver.rs232.fd;
	struct serial_handle *ser_handle;
	struct termios tio;

	rc = open(serial_port, O_RDWR);
	if (rc < 0) {
		LOGP(DLMI, LOGL_ERROR, "rs232: cannot open serial port: %s",
			strerror(errno));
		return rc;
	}
	bfd->fd = rc;

	/* set baudrate */
	rc = tcgetattr(bfd->fd, &tio);
	if (rc < 0) {
		LOGP(DLMI, LOGL_ERROR, "rs232: tcgetattr says: %s",
			strerror(errno));
		return rc;
	}
	cfsetispeed(&tio, B19200);
	cfsetospeed(&tio, B19200);
	tio.c_cflag |=  (CREAD | CLOCAL | CS8);
	tio.c_cflag &= ~(PARENB | CSTOPB | CSIZE | CRTSCTS);
	tio.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
	tio.c_iflag |=  (INPCK | ISTRIP);
	tio.c_iflag &= ~(ISTRIP | IXON | IXOFF | IGNBRK | INLCR | ICRNL | IGNCR);
	tio.c_oflag &= ~(OPOST);
	rc = tcsetattr(bfd->fd, TCSADRAIN, &tio);
	if (rc < 0) {
		LOGP(DLMI, LOGL_ERROR, "rs232: tcsetattr says: %s",
			strerror(errno));
		return rc;
	}

	ser_handle = talloc_zero(tall_rs232_ctx, struct serial_handle);
	if (ser_handle == NULL) {
		close(bfd->fd);
		LOGP(DLMI, LOGL_ERROR, "rs232: cannot allocate memory for "
			"serial handler\n");
		return -ENOMEM;
	}
	ser_handle->line = line;
	ser_handle->delay_ms = delay_ms;

	bfd->when = BSC_FD_READ;
	bfd->cb = serial_fd_cb;
	bfd->data = ser_handle;

	rc = osmo_fd_register(bfd);
	if (rc < 0) {
		close(bfd->fd);
		LOGP(DLMI, LOGL_ERROR, "rs232: could not register FD: %s\n",
			strerror(-rc));
		return rc;
	}

	return 0;
}

static int rs232_line_update(struct e1inp_line *line);

static struct e1inp_driver rs232_driver = {
	.name		= "rs232",
	.want_write	= rs232_want_write,
	.line_update	= rs232_line_update,
};

static int rs232_line_update(struct e1inp_line *line)
{
	if (line->driver != &rs232_driver)
		return -EINVAL;

	return rs232_setup(line, line->ops->cfg.rs232.port,
				 line->ops->cfg.rs232.delay);
}

int e1inp_rs232_init(void)
{
	return e1inp_driver_register(&rs232_driver);
}
