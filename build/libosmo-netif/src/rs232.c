/* T-Link interface using POSIX serial port */

/* (C) 2008-2011 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * Authors:	Harald Welte <laforge@gnumonks.org>
 *		Pablo Neira Ayuso <pablo@gnumonks.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
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
#include <limits.h>

#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/abis/e1_input.h>

struct osmo_rs232 {
	struct osmo_fd		ofd;
	struct llist_head	tx_queue;

	struct {
		int (*read)(struct osmo_rs232 *);
	} cb;

	/* sometimes we want to delay the transmission. */
	struct osmo_timer_list	tx_timer;

	struct {
		char		serial_port[PATH_MAX];
		int		baudrate;
		unsigned int	delay_us;
	} cfg;
};

void rs232_tx_timer_cb(void *ptr)
{
	struct osmo_rs232 *r = ptr;

	/* we're again ready to transmit. */
	r->ofd.when |= BSC_FD_WRITE;
}

static int handle_ser_write(struct osmo_fd *bfd)
{
	struct osmo_rs232 *r = bfd->data;
	struct llist_head *lh;
	struct msgb *msg;
	int written;

        LOGP(DLINP, LOGL_DEBUG, "writing data to rs232\n");

        if (llist_empty(&r->tx_queue)) {
                r->ofd.when &= ~BSC_FD_WRITE;
                return 0;
        }
        lh = r->tx_queue.next;
        llist_del(lh);
        msg = llist_entry(lh, struct msgb, list);

	written = write(bfd->fd, msg->data, msg->len);
	if (written < msg->len) {
		LOGP(DLINP, LOGL_ERROR, "rs232: short write\n");
		msgb_free(msg);
		return -1;
	}
	msgb_free(msg);

	/* We've got more data to write, but we have to wait to make it. */
	if (!llist_empty(&r->tx_queue) && r->cfg.delay_us) {
		r->ofd.when &= ~BSC_FD_WRITE;
		osmo_timer_schedule(&r->tx_timer, 0, r->cfg.delay_us);
	}
	return 0;
}

static int handle_ser_read(struct osmo_fd *bfd)
{
	struct osmo_rs232 *r = bfd->data;

	LOGP(DLINP, LOGL_DEBUG, "data to be read in rs232\n");

	if (r->cb.read)
		r->cb.read(r);

	return 0;
}

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

struct osmo_rs232 *osmo_rs232_create(void *ctx)
{
	struct osmo_rs232 *r;

	r = talloc_zero(ctx, struct osmo_rs232);
	if (r == NULL)
		return NULL;

	INIT_LLIST_HEAD(&r->tx_queue);

	return r;
}

void osmo_rs232_set_serial_port(struct osmo_rs232 *r, char *serial_port)
{
	strncpy(r->cfg.serial_port, serial_port, PATH_MAX);
	r->cfg.serial_port[PATH_MAX-1] = '\0';
}

void osmo_rs232_set_baudrate(struct osmo_rs232 *r, int baudrate)
{
	r->cfg.baudrate = baudrate;
}

void osmo_rs232_set_delay_us(struct osmo_rs232 *r, int delay_us)
{
	r->cfg.delay_us = delay_us;
}

void osmo_rs232_set_read_cb(struct osmo_rs232 *r,
			    int (*read_cb)(struct osmo_rs232 *r))
{
	r->cb.read = read_cb;
}

/* XXX: Better use TIOCGSERIAL / TIOCSSERIAL to allow setting non-standard. */
static struct baudrate2termbits {
	int rate;
	int def;
} baudrate2termbits[] = {
	{ 9600, B9600 },
	{ 19200, B19200 },
	{ 38400, B38400 },
	{ 115200, B115200 },
	{ -1, -1 },
};

int osmo_rs232_open(struct osmo_rs232 *r)
{
	int rc, i, speed = 0;
	struct osmo_fd *bfd = &r->ofd;
	struct termios tio;

	rc = open(r->cfg.serial_port, O_RDWR);
	if (rc < 0) {
		LOGP(DLINP, LOGL_ERROR, "rs232: cannot open serial port: %s",
			strerror(errno));
		return rc;
	}
	bfd->fd = rc;

	/* set baudrate */
	rc = tcgetattr(bfd->fd, &tio);
	if (rc < 0) {
		LOGP(DLINP, LOGL_ERROR, "rs232: tcgetattr says: %s",
			strerror(errno));
		return rc;
	}
	for (i=0; i<baudrate2termbits[i].rate; i++) {
		if (baudrate2termbits[i].rate == -1)
			break;

		if (baudrate2termbits[i].rate == r->cfg.baudrate) {
			speed = baudrate2termbits[i].def;
			break;
		}
	}
	if (speed == 0) {
		close(rc);
		bfd->fd = -1;
		return -1;
	}

	cfsetispeed(&tio, speed);
	cfsetospeed(&tio, speed);
	tio.c_cflag |=  (CREAD | CLOCAL | CS8);
	tio.c_cflag &= ~(PARENB | CSTOPB | CSIZE | CRTSCTS);
	tio.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
	tio.c_iflag |=  (INPCK | ISTRIP);
	tio.c_iflag &= ~(ISTRIP | IXON | IXOFF | IGNBRK | INLCR | ICRNL | IGNCR);
	tio.c_oflag &= ~(OPOST);
	rc = tcsetattr(bfd->fd, TCSADRAIN, &tio);
	if (rc < 0) {
		LOGP(DLINP, LOGL_ERROR, "rs232: tcsetattr says: %s",
			strerror(errno));
		return rc;
	}

	bfd->when = BSC_FD_READ;
	bfd->cb = serial_fd_cb;
	bfd->data = r;

	rc = osmo_fd_register(bfd);
	if (rc < 0) {
		close(bfd->fd);
		LOGP(DLINP, LOGL_ERROR, "rs232: could not register FD: %s\n",
			strerror(-rc));
		return rc;
	}

	if (r->cfg.delay_us) {
		r->tx_timer.cb = rs232_tx_timer_cb;
		r->tx_timer.data = r;
	}
	return 0;
}

int osmo_rs232_read(struct osmo_rs232 *r, struct msgb *msg)
{
	int ret;

	ret = read(r->ofd.fd, msg->data, msg->data_len);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "read error: %s\n", strerror(errno));
		return -EIO;
	}
	msgb_put(msg, ret);
	return ret;
}

void osmo_rs232_write(struct osmo_rs232 *r, struct msgb *msg)
{
        msgb_enqueue(&r->tx_queue, msg);
        r->ofd.when |= BSC_FD_WRITE;
}

void osmo_rs232_close(struct osmo_rs232 *r)
{
	close(r->ofd.fd);
	r->ofd.fd = -1;
}

void osmo_rs232_destroy(struct osmo_rs232 *r)
{
	talloc_free(r);
}
