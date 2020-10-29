/* OpenBSC Abis input driver for DAHDI */

/* (C) 2008-2011 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by Digium and Matthew Fredrickson <creslin@digium.com>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "config.h"

#ifdef HAVE_DAHDI_USER_H

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
#include <dahdi/user.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/signal.h>
#include <osmocom/core/rate_ctr.h>

#include <osmocom/vty/vty.h>

#include <osmocom/abis/subchan_demux.h>
#include <osmocom/abis/e1_input.h>

#include <osmocom/abis/lapd.h>

#define TS1_ALLOC_SIZE	300

struct span_cfg {
	struct llist_head list;

	unsigned int span_nr;
	unsigned int chan_base;
	unsigned int chan_num;
};

static struct span_cfg *span_cfgs[DAHDI_MAX_SPANS];

static int reread_span_cfgs(void)
{
	struct dahdi_spaninfo si;
	unsigned int basechan = 1;
	int span_nr;
	int fd;

	if ((fd = open("/dev/dahdi/ctl", O_RDWR)) < 0) {
		LOGP(DLMI, LOGL_ERROR, "Unable to open DAHDI ctl: %s\n",
			strerror(errno));
		return -EIO;
	}

	for (span_nr = 1; span_nr < DAHDI_MAX_SPANS; span_nr++) {
		struct span_cfg *scfg;
		/* our array index starts at 0, but DAHDI span at 1 */
		int i = span_nr - 1;

		/* clear any old cached information */
		if (span_cfgs[i]) {
			talloc_free(span_cfgs[i]);
			span_cfgs[i] = NULL;
		}

		memset(&si, 0, sizeof(si));
		si.spanno = span_nr;
		if (ioctl(fd, DAHDI_SPANSTAT, &si))
			continue;

		/* create and link new span_cfg */
		scfg = talloc_zero(NULL, struct span_cfg);
		if (!scfg) {
			close(fd);
			return -ENOMEM;
		}
		scfg->span_nr = span_nr;
		scfg->chan_num = si.totalchans;
		scfg->chan_base = basechan;
		span_cfgs[i] = scfg;

		basechan += si.totalchans;
	}

	close(fd);

	return 0;
}

/* Corresponds to dahdi/user.h, only PRI related events */
static const struct value_string dahdi_evt_names[] = {
	{ DAHDI_EVENT_NONE,		"NONE" },
	{ DAHDI_EVENT_ALARM,		"ALARM" },
	{ DAHDI_EVENT_NOALARM,		"NOALARM" },
	{ DAHDI_EVENT_ABORT,		"HDLC ABORT" },
	{ DAHDI_EVENT_OVERRUN,		"HDLC OVERRUN" },
	{ DAHDI_EVENT_BADFCS,		"HDLC BAD FCS" },
	{ DAHDI_EVENT_REMOVED,		"REMOVED" },
	{ 0, NULL }
};

static void handle_dahdi_exception(struct e1inp_ts *ts)
{
	int rc, evt;
	struct e1inp_line *line = ts->line;
	struct input_signal_data isd;

	rc = ioctl(ts->driver.dahdi.fd.fd, DAHDI_GETEVENT, &evt);
	if (rc < 0)
		return;

	LOGP(DLMI, LOGL_NOTICE, "Line %u(%s) / TS %u DAHDI EVENT %s\n",
		ts->line->num, ts->line->name, ts->num,
		get_value_string(dahdi_evt_names, evt));

	isd.line = ts->line;
	isd.ts_nr = ts->num;

	switch (evt) {
	case DAHDI_EVENT_ALARM:
		/* we should notify the code that the line is gone */
		osmo_signal_dispatch(SS_L_INPUT, S_L_INP_LINE_ALARM, &isd);
		rate_ctr_inc(&line->rate_ctr->ctr[E1I_CTR_ALARM]);
		break;
	case DAHDI_EVENT_NOALARM:
		/* alarm has gone, we should re-start the SABM requests */
		osmo_signal_dispatch(SS_L_INPUT, S_L_INP_LINE_NOALARM, &isd);
		break;
	case DAHDI_EVENT_ABORT:
		rate_ctr_inc(&line->rate_ctr->ctr[E1I_CTR_HDLC_ABORT]);
		break;
	case DAHDI_EVENT_OVERRUN:
		rate_ctr_inc(&line->rate_ctr->ctr[E1I_CTR_HDLC_OVERR]);
		break;
	case DAHDI_EVENT_BADFCS:
		rate_ctr_inc(&line->rate_ctr->ctr[E1I_CTR_HDLC_BADFCS]);
		break;
	case DAHDI_EVENT_REMOVED:
		rate_ctr_inc(&line->rate_ctr->ctr[E1I_CTR_REMOVED]);
		break;
	}
}

static int handle_ts1_read(struct osmo_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct msgb *msg = msgb_alloc(TS1_ALLOC_SIZE, "DAHDI TS1");
	int ret;

	if (!msg)
		return -ENOMEM;

	ret = read(bfd->fd, msg->data, TS1_ALLOC_SIZE - 16);
	if (ret == -1)
		handle_dahdi_exception(e1i_ts);
	else if (ret < 0) {
		perror("read ");
	}
	msgb_put(msg, ret - 2);
	if (ret <= 3) {
		perror("read ");
	}

	return e1inp_rx_ts_lapd(e1i_ts, msg);
}

static int ts_want_write(struct e1inp_ts *e1i_ts)
{
	/* We never include the DAHDI B-Channel FD into the
	 * writeset, since it doesn't support poll() based
	 * write flow control */
	if (e1i_ts->type == E1INP_TS_TYPE_TRAU) {
		LOGP(DLINP, LOGL_DEBUG, "Trying to write TRAU ts\n");
		return 0;
	}

	e1i_ts->driver.dahdi.fd.when |= BSC_FD_WRITE;

	return 0;
}

static void timeout_ts1_write(void *data)
{
	struct e1inp_ts *e1i_ts = (struct e1inp_ts *)data;

	/* trigger write of ts1, due to tx delay timer */
	ts_want_write(e1i_ts);
}

static void dahdi_write_msg(struct msgb *msg, void *cbdata)
{
	struct osmo_fd *bfd = cbdata;
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	int ret;

	ret = write(bfd->fd, msg->data, msg->len + 2);
	msgb_free(msg);
	if (ret == -1)
		handle_dahdi_exception(e1i_ts);
	else if (ret < 0)
		LOGP(DLMI, LOGL_NOTICE, "%s write failed %d\n", __func__, ret);
}

static int handle_ts1_write(struct osmo_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct e1inp_sign_link *sign_link;
	struct msgb *msg;

	bfd->when &= ~BSC_FD_WRITE;

	/* get the next msg for this timeslot */
	msg = e1inp_tx_ts(e1i_ts, &sign_link);
	if (!msg) {
		/* no message after tx delay timer */
		return 0;
	}

	DEBUGP(DLMI, "TX: %s\n", osmo_hexdump(msg->data, msg->len));
	lapd_transmit(e1i_ts->lapd, sign_link->tei,
			sign_link->sapi, msg);

	/* set tx delay timer for next event */
	e1i_ts->sign.tx_timer.cb = timeout_ts1_write;
	e1i_ts->sign.tx_timer.data = e1i_ts;
	osmo_timer_schedule(&e1i_ts->sign.tx_timer, 0, 50000);

	return 0;
}

static void handle_hdlc_write(struct osmo_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct msgb *msg;
	int ret;

	/* get the next msg for this timeslot */
	msg = e1inp_tx_ts(e1i_ts, NULL);
	if (!msg)
		return;

	ret = write(bfd->fd, msg->data, msg->len + 2);
	msgb_free(msg);
	if (ret == -1)
		handle_dahdi_exception(e1i_ts);
	else if (ret < 0)
		LOGP(DLMI, LOGL_NOTICE, "%s write failed %d\n", __func__, ret);
}

static int handle_hdlc_read(struct osmo_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct msgb *msg = msgb_alloc(TS1_ALLOC_SIZE, "DAHDI HDLC Rx");
	int ret;

	if (!msg)
		return -ENOMEM;

	ret = read(bfd->fd, msg->data, TS1_ALLOC_SIZE - 16);
	if (ret == -1)
		handle_dahdi_exception(e1i_ts);
	else if (ret < 0) {
		perror("read ");
	}
	msgb_put(msg, ret - 2);
	if (ret <= 3) {
		perror("read ");
	}

	return e1inp_rx_ts(e1i_ts, msg, 0, 0);
}

static int invertbits = 1;

static uint8_t flip_table[256];

static void init_flip_bits(void)
{
        int i,k;

        for (i = 0 ; i < 256 ; i++) {
                uint8_t sample = 0 ;
                for (k = 0; k<8; k++) {
                        if ( i & 1 << k ) sample |= 0x80 >>  k;
                }
                flip_table[i] = sample;
        }
}

static uint8_t * flip_buf_bits ( uint8_t * buf , int len)
{
        int i;
        uint8_t * start = buf;

        for (i = 0 ; i < len; i++) {
                buf[i] = flip_table[(uint8_t)buf[i]];
        }

        return start;
}

#define D_BCHAN_TX_GRAN 160
/* write to a B channel TS */
static int handle_tsX_write(struct osmo_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	uint8_t tx_buf[D_BCHAN_TX_GRAN];
	struct subch_mux *mx = &e1i_ts->trau.mux;
	int ret;

	ret = subchan_mux_out(mx, tx_buf, D_BCHAN_TX_GRAN);

	if (ret != D_BCHAN_TX_GRAN) {
		LOGP(DLINP, LOGL_DEBUG, "Huh, got ret of %d\n", ret);
		if (ret < 0)
			return ret;
	}

	DEBUGP(DLMIB, "BCHAN TX: %s\n",
		osmo_hexdump(tx_buf, D_BCHAN_TX_GRAN));

	if (invertbits) {
		flip_buf_bits(tx_buf, ret);
	}

	ret = write(bfd->fd, tx_buf, ret);
	if (ret < D_BCHAN_TX_GRAN)
		LOGP(DLINP, LOGL_DEBUG, "send returns %d instead of %d\n",
			ret, D_BCHAN_TX_GRAN);

	return ret;
}

#define D_TSX_ALLOC_SIZE (D_BCHAN_TX_GRAN)
/* FIXME: read from a B channel TS */
static int handle_tsX_read(struct osmo_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct msgb *msg = msgb_alloc(D_TSX_ALLOC_SIZE, "DAHDI TSx");
	int ret;

	if (!msg)
		return -ENOMEM;

	ret = read(bfd->fd, msg->data, D_TSX_ALLOC_SIZE);
	if (ret < 0 || ret != D_TSX_ALLOC_SIZE) {
		LOGP(DLINP, LOGL_DEBUG, "read error  %d %s\n",
			ret, strerror(errno));
		return ret;
	}

	if (invertbits) {
		flip_buf_bits(msg->data, ret);
	}

	msgb_put(msg, ret);

	msg->l2h = msg->data;
	DEBUGP(DLMIB, "BCHAN RX: %s\n",
		osmo_hexdump(msgb_l2(msg), ret));
	ret = e1inp_rx_ts(e1i_ts, msg, 0, 0);
	/* physical layer indicates that data has been sent,
	 * we thus can send some more data */
	ret = handle_tsX_write(bfd);

	return ret;
}

/* write to a raw channel TS */
static int handle_ts_raw_write(struct osmo_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct msgb *msg;
	int ret;

	/* get the next msg for this timeslot */
	msg = e1inp_tx_ts(e1i_ts, NULL);
	if (!msg)
		return 0;

	if (msg->len != D_BCHAN_TX_GRAN) {
		/* This might lead to a transmit underrun, as we call tx
		 * from the rx path, as there's no select/poll on dahdi
		 * */
		LOGP(DLINP, LOGL_NOTICE, "unexpected msg->len = %u, "
		     "expected %u\n", msg->len, D_BCHAN_TX_GRAN);
	}

	DEBUGP(DLMIB, "RAW CHAN TX: %s\n",
		osmo_hexdump(msg->data, msg->len));

	if (0/*invertbits*/) {
		flip_buf_bits(msg->data, msg->len);
	}

	ret = write(bfd->fd, msg->data, msg->len);
	if (ret < msg->len)
		LOGP(DLINP, LOGL_DEBUG, "send returns %d instead of %d\n",
			ret, msg->len);
	msgb_free(msg);

	return ret;
}

static int handle_ts_raw_read(struct osmo_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct msgb *msg = msgb_alloc(D_TSX_ALLOC_SIZE, "DAHDI Raw TS");
	int ret;

	if (!msg)
		return -ENOMEM;

	ret = read(bfd->fd, msg->data, D_TSX_ALLOC_SIZE);
	if (ret < 0 || ret != D_TSX_ALLOC_SIZE) {
		LOGP(DLINP, LOGL_DEBUG, "read error  %d %s\n",
			ret, strerror(errno));
		return ret;
	}

	if (0/*invertbits*/) {
		flip_buf_bits(msg->data, ret);
	}

	msgb_put(msg, ret);

	msg->l2h = msg->data;
	DEBUGP(DLMIB, "RAW CHAN RX: %s\n",
		osmo_hexdump(msgb_l2(msg), ret));
	ret = e1inp_rx_ts(e1i_ts, msg, 0, 0);
	/* physical layer indicates that data has been sent,
	 * we thus can send some more data */
	ret = handle_ts_raw_write(bfd);

	return ret;
}

/* callback from select.c in case one of the fd's can be read/written */
static int dahdi_fd_cb(struct osmo_fd *bfd, unsigned int what)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	unsigned int idx = ts_nr-1;
	struct e1inp_ts *e1i_ts = &line->ts[idx];
	int rc = 0;

	switch (e1i_ts->type) {
	case E1INP_TS_TYPE_SIGN:
		if (what & BSC_FD_EXCEPT)
			handle_dahdi_exception(e1i_ts);
		if (what & BSC_FD_READ)
			rc = handle_ts1_read(bfd);
		if (what & BSC_FD_WRITE)
			rc = handle_ts1_write(bfd);
		break;
	case E1INP_TS_TYPE_HDLC:
		if (what & BSC_FD_EXCEPT)
			handle_dahdi_exception(e1i_ts);
		if (what & BSC_FD_READ)
			rc = handle_hdlc_read(bfd);
		if (what & BSC_FD_WRITE)
			handle_hdlc_write(bfd);
		break;
	case E1INP_TS_TYPE_TRAU:
		if (what & BSC_FD_EXCEPT)
			handle_dahdi_exception(e1i_ts);
		if (what & BSC_FD_READ)
			rc = handle_tsX_read(bfd);
		if (what & BSC_FD_WRITE)
			rc = handle_tsX_write(bfd);
		/* We never include the DAHDI B-Channel FD into the
		 * writeset, since it doesn't support poll() based
		 * write flow control */
		break;
	case E1INP_TS_TYPE_RAW:
		if (what & BSC_FD_EXCEPT)
			handle_dahdi_exception(e1i_ts);
		if (what & BSC_FD_READ)
			rc = handle_ts_raw_read(bfd);
		if (what & BSC_FD_WRITE)
			rc = handle_ts_raw_write(bfd);
		/* We never include the DAHDI B-Channel FD into the
		 * writeset, since it doesn't support poll() based
		 * write flow control */
		break;
	default:
		LOGP(DLINP, LOGL_NOTICE,
			"unknown E1 TS type %u\n", e1i_ts->type);
		break;
	}

	return rc;
}

static void dahdi_vty_show(struct vty *vty, struct e1inp_line *line)
{
	struct span_cfg *scfg;

	if (line->port_nr >= ARRAY_SIZE(span_cfgs))
		return;

	scfg = span_cfgs[line->port_nr];
	if (!scfg) {
		vty_out(vty, "DAHDI Span %u non-existant%s",
			line->port_nr+1, VTY_NEWLINE);
		return;
	}

	vty_out(vty, "DAHDI Span #%u, Base Nr %u, Timeslots: %u%s",
		line->port_nr+1, scfg->chan_base, scfg->chan_num,
		VTY_NEWLINE);
}

static int dahdi_e1_line_update(struct e1inp_line *line);

struct e1inp_driver dahdi_driver = {
	.name = "dahdi",
	.want_write = ts_want_write,
	.line_update = &dahdi_e1_line_update,
	.vty_show = &dahdi_vty_show,
};

int dahdi_set_bufinfo(int fd, int as_sigchan)
{
	struct dahdi_bufferinfo bi;
	int x = 0;

	if (ioctl(fd, DAHDI_GET_BUFINFO, &bi)) {
		LOGP(DLINP, LOGL_ERROR, "Error getting bufinfo\n");
		return -EIO;
	}

	if (as_sigchan) {
		bi.numbufs = 4;
		bi.bufsize = 512;
	} else {
		bi.numbufs = 8;
		bi.bufsize = D_BCHAN_TX_GRAN;
		bi.txbufpolicy = DAHDI_POLICY_WHEN_FULL;
	}

	if (ioctl(fd, DAHDI_SET_BUFINFO, &bi)) {
		LOGP(DLINP, LOGL_ERROR, "Error setting bufinfo\n");
		return -EIO;
	}

	if (!as_sigchan) {
		if (ioctl(fd, DAHDI_AUDIOMODE, &x)) {
			LOGP(DLINP, LOGL_ERROR, "Error setting bufinfo\n");
			return -EIO;
		}
	} else {
		int one = 1;
		ioctl(fd, DAHDI_HDLCFCSMODE, &one);
		/* we cannot reliably check for the ioctl return value here
		 * as this command will fail if the slot _already_ was a
		 * signalling slot before :( */
	}
	return 0;
}

static int dahdi_e1_setup(struct e1inp_line *line)
{
	struct span_cfg *scfg;
	int ts, ret;

	reread_span_cfgs();

	scfg = span_cfgs[line->port_nr];
	if (!scfg) {
		LOGP(DLMI, LOGL_ERROR, "Line %u(%s): DAHDI Port %u (Span %u) "
			"doesn't exist\n", line->num, line->name, line->port_nr,
			line->port_nr+1);
		return -EIO;
	}

	line->num_ts = scfg->chan_num;

	/* TS0 is CRC4, don't need any fd for it */
	for (ts = 1; ts <= scfg->chan_num; ts++) {
		unsigned int idx = ts-1;
		char openstr[128];
		struct e1inp_ts *e1i_ts = &line->ts[idx];
		struct osmo_fd *bfd = &e1i_ts->driver.dahdi.fd;
		int dev_nr;

		/* unregister FD if it was already registered */
		if (bfd->list.next && bfd->list.next != LLIST_POISON1)
			osmo_fd_unregister(bfd);

		/* DAHDI device names/numbers just keep incrementing
		 * even over multiple boards.  So TS1 of the second
		 * board will be 32 */
		dev_nr = scfg->chan_base + idx;

		bfd->data = line;
		bfd->priv_nr = ts;
		bfd->cb = dahdi_fd_cb;
		snprintf(openstr, sizeof(openstr), "/dev/dahdi/%d", dev_nr);

		switch (e1i_ts->type) {
		case E1INP_TS_TYPE_NONE:
			/* close/release LAPD instance, if any */
			if (e1i_ts->lapd) {
				lapd_instance_free(e1i_ts->lapd);
				e1i_ts->lapd = NULL;
			}
			if (bfd->fd) {
				close(bfd->fd);
				bfd->fd = 0;
			}
			continue;
			break;
		case E1INP_TS_TYPE_SIGN:
			if (!bfd->fd)
				bfd->fd = open(openstr, O_RDWR | O_NONBLOCK);
			if (bfd->fd == -1) {
				LOGP(DLINP, LOGL_ERROR,
					"%s could not open %s %s\n",
					__func__, openstr, strerror(errno));
				return -EIO;
			}
			bfd->when = BSC_FD_READ | BSC_FD_EXCEPT;
			ret = dahdi_set_bufinfo(bfd->fd, 1);
			if (ret < 0)
				return ret;

			if (!e1i_ts->lapd)
				e1i_ts->lapd = lapd_instance_alloc(1,
					dahdi_write_msg, bfd, e1inp_dlsap_up,
					e1i_ts, &lapd_profile_abis);
			break;
		case E1INP_TS_TYPE_HDLC:
			if (!bfd->fd)
				bfd->fd = open(openstr, O_RDWR | O_NONBLOCK);
			if (bfd->fd == -1) {
				LOGP(DLINP, LOGL_ERROR,
					"%s could not open %s %s\n",
					__func__, openstr, strerror(errno));
				return -EIO;
			}
			bfd->when = BSC_FD_READ | BSC_FD_EXCEPT;
			ret = dahdi_set_bufinfo(bfd->fd, 1);
			if (ret < 0)
				return ret;
			break;
		case E1INP_TS_TYPE_TRAU:
		case E1INP_TS_TYPE_RAW:
			/* close/release LAPD instance, if any */
			if (e1i_ts->lapd) {
				lapd_instance_free(e1i_ts->lapd);
				e1i_ts->lapd = NULL;
			}
			if (!bfd->fd)
				bfd->fd = open(openstr, O_RDWR | O_NONBLOCK);
			if (bfd->fd == -1) {
				LOGP(DLINP, LOGL_ERROR,
					"%s could not open %s %s\n",
					__func__, openstr, strerror(errno));
				return -EIO;
			}
			ret = dahdi_set_bufinfo(bfd->fd, 0);
			if (ret < 0)
				return -EIO;
			/* We never include the DAHDI B-Channel FD into the
			 * writeset, since it doesn't support poll() based
			 * write flow control */
			bfd->when = BSC_FD_READ | BSC_FD_EXCEPT;// | BSC_FD_WRITE;
			break;
		}

		if (bfd->fd < 0) {
			LOGP(DLINP, LOGL_ERROR,
				"%s could not open %s %s\n",
				__func__, openstr, strerror(errno));
			return bfd->fd;
		}

		ret = osmo_fd_register(bfd);
		if (ret < 0) {
			LOGP(DLINP, LOGL_ERROR,
				"could not register FD: %s\n",
				strerror(ret));
			return ret;
		}
	}

	return 0;
}

static int dahdi_e1_line_update(struct e1inp_line *line)
{
	if (line->driver != &dahdi_driver)
		return -EINVAL;

	return dahdi_e1_setup(line);
}

int e1inp_dahdi_init(void)
{
	init_flip_bits();

	/* register the driver with the core */
	return e1inp_driver_register(&dahdi_driver);
}

#endif /* HAVE_DAHDI_USER_H */
