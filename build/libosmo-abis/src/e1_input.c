/* OpenBSC Abis interface to E1 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
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

#include "internal.h"
#include "../config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <osmocom/abis/lapd.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/signal.h>
#include <osmocom/abis/e1_input.h>

#define NUM_E1_TS	32

static void *tall_e1inp_ctx;

/* list of all E1 drivers */
LLIST_HEAD(e1inp_driver_list);

/* list of all E1 lines */
LLIST_HEAD(e1inp_line_list);

static void *tall_sigl_ctx;

static const struct rate_ctr_desc e1inp_ctr_d[] = {
	[E1I_CTR_HDLC_ABORT]  = {
		"hdlc.abort", 	"HDLC abort"
	},
	[E1I_CTR_HDLC_BADFCS] = {
		"hdlc.bad_fcs",	"HLDC Bad FCS"
	},
	[E1I_CTR_HDLC_OVERR]  = {
		"hdlc.overrun",	"HDLC Overrun"
	},
	[E1I_CTR_ALARM] = {
		"alarm", 	"Alarm"
	},
	[E1I_CTR_REMOVED] = {
		"removed", 	"Line removed"
	},
};

static const struct rate_ctr_group_desc e1inp_ctr_g_d = {
	.group_name_prefix = "e1inp",
	.group_description = "E1 Input subsystem",
	.num_ctr = ARRAY_SIZE(e1inp_ctr_d),
	.ctr_desc = e1inp_ctr_d,
};

/*
 * pcap writing of the misdn load
 * pcap format is from http://wiki.wireshark.org/Development/LibpcapFileFormat
 */
#define DLT_LINUX_LAPD		177
#define PCAP_INPUT		0
#define PCAP_OUTPUT		1

struct pcap_hdr {
	uint32_t magic_number;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t  thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t network;
} __attribute__((packed));

struct pcaprec_hdr {
	uint32_t ts_sec;
	uint32_t ts_usec;
	uint32_t incl_len;
	uint32_t orig_len;
} __attribute__((packed));

struct fake_linux_lapd_header {
        uint16_t pkttype;
	uint16_t hatype;
	uint16_t halen;
	uint64_t addr;
	int16_t protocol;
} __attribute__((packed));

struct lapd_header {
	uint8_t ea1 : 1;
	uint8_t cr : 1;
	uint8_t sapi : 6;
	uint8_t ea2 : 1;
	uint8_t tei : 7;
	uint8_t control_foo; /* fake UM's ... */
} __attribute__((packed));

osmo_static_assert(offsetof(struct fake_linux_lapd_header, hatype) == 2,    hatype_offset);
osmo_static_assert(offsetof(struct fake_linux_lapd_header, halen) == 4,     halen_offset);
osmo_static_assert(offsetof(struct fake_linux_lapd_header, addr) == 6,      addr_offset);
osmo_static_assert(offsetof(struct fake_linux_lapd_header, protocol) == 14, proto_offset);
osmo_static_assert(sizeof(struct fake_linux_lapd_header) == 16,	       lapd_header_size);


static int pcap_fd = -1;

int e1_set_pcap_fd(int fd)
{
	struct pcap_hdr header = {
		.magic_number	= 0xa1b2c3d4,
		.version_major	= 2,
		.version_minor	= 4,
		.thiszone	= 0,
		.sigfigs	= 0,
		.snaplen	= 65535,
		.network	= DLT_LINUX_LAPD,
	};

	pcap_fd = fd;
	return write(pcap_fd, &header, sizeof(header));
}

/* This currently only works for the D-Channel */
static void write_pcap_packet(int direction, int sapi, int tei,
			      struct msgb *msg) {
	if (pcap_fd < 0)
		return;

	time_t cur_time;
	struct tm *tm;

	struct fake_linux_lapd_header header = {
		.pkttype	= 4,
		.hatype		= 0,
		.halen		= 0,
		.addr		= direction == PCAP_OUTPUT ? 0x0 : 0x1,
		.protocol	= ntohs(48),
	};

	struct lapd_header lapd_header = {
		.ea1		= 0,
		.cr		= direction == PCAP_OUTPUT ? 1 : 0,
		.sapi		= sapi & 0x3F,
		.ea2		= 1,
		.tei		= tei & 0x7F,
		.control_foo	= 0x03 /* UI */,
	};

	struct pcaprec_hdr payload_header = {
		.ts_sec	    = 0,
		.ts_usec    = 0,
		.incl_len   = msgb_l2len(msg) + sizeof(struct fake_linux_lapd_header)
				+ sizeof(struct lapd_header),
		.orig_len   = msgb_l2len(msg) + sizeof(struct fake_linux_lapd_header)
				+ sizeof(struct lapd_header),
	};


	cur_time = time(NULL);
	tm = localtime(&cur_time);
	payload_header.ts_sec = mktime(tm);

	write(pcap_fd, &payload_header, sizeof(payload_header));
	write(pcap_fd, &header, sizeof(header));
	write(pcap_fd, &lapd_header, sizeof(lapd_header));
	write(pcap_fd, msg->l2h, msgb_l2len(msg));
}

const struct value_string e1inp_sign_type_names[5] = {
	{ E1INP_SIGN_NONE,	"None" },
	{ E1INP_SIGN_OML,	"OML" },
	{ E1INP_SIGN_RSL,	"RSL" },
	{ E1INP_SIGN_OSMO,	"OSMO" },
	{ 0, NULL }
};

const char *e1inp_signtype_name(enum e1inp_sign_type tp)
{
	return get_value_string(e1inp_sign_type_names, tp);
}

const struct value_string e1inp_ts_type_names[6] = {
	{ E1INP_TS_TYPE_NONE,	"None" },
	{ E1INP_TS_TYPE_SIGN,	"Signalling" },
	{ E1INP_TS_TYPE_TRAU,	"TRAU" },
	{ E1INP_TS_TYPE_RAW,	"RAW" },
	{ E1INP_TS_TYPE_HDLC,	"HDLC" },
	{ 0, NULL }
};

const char *e1inp_tstype_name(enum e1inp_ts_type tp)
{
	return get_value_string(e1inp_ts_type_names, tp);
}

int abis_sendmsg(struct msgb *msg)
{
	struct e1inp_sign_link *sign_link = msg->dst;
	struct e1inp_driver *e1inp_driver;
	struct e1inp_ts *e1i_ts;

	msg->l2h = msg->data;

	/* don't know how to route this message. */
	if (sign_link == NULL) {
		LOGP(DLINP, LOGL_ERROR, "abis_sendmsg: msg->dst == NULL: %s\n",
			osmo_hexdump(msg->data, msg->len));
		talloc_free(msg);
		return -EINVAL;
	}
	e1i_ts = sign_link->ts;
	if (!osmo_timer_pending(&e1i_ts->sign.tx_timer)) {
		/* notify the driver we have something to write */
		e1inp_driver = sign_link->ts->line->driver;
		e1inp_driver->want_write(e1i_ts);
	}
	msgb_enqueue(&sign_link->tx_list, msg);

	/* we only need to write a 'Fake LAPD' packet here, if the
	 * underlying driver hides LAPD from us.  If we use the
	 * libosmocore LAPD implementation, it will take care of writing
	 * the _actual_ LAPD packet */
	if (!e1i_ts->lapd) {
		write_pcap_packet(PCAP_OUTPUT, sign_link->sapi,
				  sign_link->tei, msg);
	}

	return 0;
}

int abis_rsl_sendmsg(struct msgb *msg)
{
	return abis_sendmsg(msg);
}

/* Timeslot */
int e1inp_ts_config_trau(struct e1inp_ts *ts, struct e1inp_line *line,
			 int (*trau_rcv_cb)(struct subch_demux *dmx, int ch,
					uint8_t *data, int len, void *_priv))
{
	if (ts->type == E1INP_TS_TYPE_TRAU && ts->line && line)
		return 0;

	ts->type = E1INP_TS_TYPE_TRAU;
	ts->line = line;

	subchan_mux_init(&ts->trau.mux);
	ts->trau.demux.out_cb = trau_rcv_cb;
	ts->trau.demux.data = ts;
	subch_demux_init(&ts->trau.demux);
	return 0;
}

int e1inp_ts_config_sign(struct e1inp_ts *ts, struct e1inp_line *line)
{
	if (ts->type == E1INP_TS_TYPE_SIGN && ts->line && line)
		return 0;

	ts->type = E1INP_TS_TYPE_SIGN;
	ts->line = line;

	if (line && line->driver)
		ts->sign.delay = line->driver->default_delay;
	else
		ts->sign.delay = 100000;
	INIT_LLIST_HEAD(&ts->sign.sign_links);
	return 0;
}

int e1inp_ts_config_raw(struct e1inp_ts *ts, struct e1inp_line *line,
			void (*raw_recv_cb)(struct e1inp_ts *ts,
					    struct msgb *msg))
{
	if (ts->type == E1INP_TS_TYPE_RAW && ts->line && line)
		return 0;

	ts->type = E1INP_TS_TYPE_RAW;
	ts->line = line;
	ts->raw.recv_cb = raw_recv_cb;
	INIT_LLIST_HEAD(&ts->raw.tx_queue);

	return 0;
}

int e1inp_ts_config_hdlc(struct e1inp_ts *ts, struct e1inp_line *line,
			 void (*hdlc_recv_cb)(struct e1inp_ts *ts,
					      struct msgb *msg))
{
	if (ts->type == E1INP_TS_TYPE_HDLC && ts->line && line)
		return 0;

	ts->type = E1INP_TS_TYPE_HDLC;
	ts->line = line;
	ts->hdlc.recv_cb = hdlc_recv_cb;
	INIT_LLIST_HEAD(&ts->hdlc.tx_queue);

	return 0;
}

struct e1inp_line *e1inp_line_find(uint8_t e1_nr)
{
	struct e1inp_line *e1i_line;

	/* iterate over global list of e1 lines */
	llist_for_each_entry(e1i_line, &e1inp_line_list, list) {
		if (e1i_line->num == e1_nr)
			return e1i_line;
	}
	return NULL;
}

struct e1inp_line *
e1inp_line_create(uint8_t e1_nr, const char *driver_name)
{
	struct e1inp_driver *driver;
	struct e1inp_line *line;
	int i;

	line = e1inp_line_find(e1_nr);
	if (line) {
		LOGP(DLINP, LOGL_ERROR, "E1 Line %u already exists\n",
		     e1_nr);
		return NULL;
	}

	driver = e1inp_driver_find(driver_name);
	if (!driver) {
		LOGP(DLINP, LOGL_ERROR, "No such E1 driver '%s'\n",
		     driver_name);
		return NULL;
	}

	line = talloc_zero(tall_e1inp_ctx, struct e1inp_line);
	if (!line)
		return NULL;

	line->driver = driver;
	line->num = e1_nr;

	line->rate_ctr = rate_ctr_group_alloc(line, &e1inp_ctr_g_d, line->num);

	line->num_ts = NUM_E1_TS;
	for (i = 0; i < line->num_ts; i++) {
		line->ts[i].num = i+1;
		line->ts[i].line = line;
	}
	line->refcnt++;
	llist_add_tail(&line->list, &e1inp_line_list);

	return line;
}

struct e1inp_line *
e1inp_line_clone(void *ctx, struct e1inp_line *line)
{
	struct e1inp_line *clone;

	/* clone virtual E1 line for this new OML link. */
	clone = talloc_zero(ctx, struct e1inp_line);
	if (clone == NULL)
	        return NULL;

	memcpy(clone, line, sizeof(struct e1inp_line));
	clone->refcnt = 1;
	return clone;
}

void e1inp_line_get(struct e1inp_line *line)
{
	line->refcnt++;
}

void e1inp_line_put(struct e1inp_line *line)
{
	line->refcnt--;
	if (line->refcnt == 0)
		talloc_free(line);
}

void
e1inp_line_bind_ops(struct e1inp_line *line, const struct e1inp_line_ops *ops)
{
	line->ops = ops;
}

#if 0
struct e1inp_line *e1inp_line_find_create(uint8_t e1_nr)
{
	struct e1inp_line *line;
	int i;

	line = e1inp_line_find(e1_nr);
	if (line)
		return line;

	line = talloc_zero(tall_e1inp_ctx, struct e1inp_line);
	if (!line)
		return NULL;

	line->num = e1_nr;
	for (i = 0; i < NUM_E1_TS; i++) {
		line->ts[i].num = i+1;
		line->ts[i].line = line;
	}
	llist_add_tail(&line->list, &e1inp_line_list);

	return line;
}
#endif

static struct e1inp_ts *e1inp_ts_get(uint8_t e1_nr, uint8_t ts_nr)
{
	struct e1inp_line *e1i_line;

	e1i_line = e1inp_line_find(e1_nr);
	if (!e1i_line)
		return NULL;

	return &e1i_line->ts[ts_nr-1];
}

struct subch_mux *e1inp_get_mux(uint8_t e1_nr, uint8_t ts_nr)
{
	struct e1inp_ts *e1i_ts = e1inp_ts_get(e1_nr, ts_nr);

	if (!e1i_ts)
		return NULL;

	return &e1i_ts->trau.mux;
}

/* Signalling Link */

struct e1inp_sign_link *e1inp_lookup_sign_link(struct e1inp_ts *e1i,
						uint8_t tei, uint8_t sapi)
{
	struct e1inp_sign_link *link;

	llist_for_each_entry(link, &e1i->sign.sign_links, list) {
		if (link->sapi == sapi && link->tei == tei)
			return link;
	}

	return NULL;
}

/* create a new signalling link in a E1 timeslot */

struct e1inp_sign_link *
e1inp_sign_link_create(struct e1inp_ts *ts, enum e1inp_sign_type type,
			struct gsm_bts_trx *trx, uint8_t tei,
			uint8_t sapi)
{
	struct e1inp_sign_link *link;

	if (ts->type != E1INP_TS_TYPE_SIGN)
		return NULL;

	link = talloc_zero(tall_sigl_ctx, struct e1inp_sign_link);
	if (!link)
		return NULL;

	link->ts = ts;
	link->type = type;
	INIT_LLIST_HEAD(&link->tx_list);
	link->trx = trx;
	link->tei = tei;
	link->sapi = sapi;

	llist_add_tail(&link->list, &ts->sign.sign_links);

	return link;
}

void e1inp_sign_link_destroy(struct e1inp_sign_link *link)
{
	struct msgb *msg;

	llist_del(&link->list);
	while (!llist_empty(&link->tx_list)) {
		msg = msgb_dequeue(&link->tx_list);
		msgb_free(msg);
	}

	if (link->ts->type == E1INP_TS_TYPE_SIGN)
		osmo_timer_del(&link->ts->sign.tx_timer);

	if (link->ts->line->driver->close)
		link->ts->line->driver->close(link);

	e1inp_line_put(link->ts->line);
	talloc_free(link);
}

/* XXX */
/* the E1 driver tells us he has received something on a TS */
int e1inp_rx_ts(struct e1inp_ts *ts, struct msgb *msg,
		uint8_t tei, uint8_t sapi)
{
	struct e1inp_sign_link *link;
	int ret = 0;

	switch (ts->type) {
	case E1INP_TS_TYPE_SIGN:
		/* we only need to write a 'Fake LAPD' packet here, if
		 * the underlying driver hides LAPD from us.  If we use
		 * the libosmocore LAPD implementation, it will take
		 * care of writing the _actual_ LAPD packet */
		if (!ts->lapd)
			write_pcap_packet(PCAP_INPUT, sapi, tei, msg);
		/* consult the list of signalling links */
		link = e1inp_lookup_sign_link(ts, tei, sapi);
		if (!link) {
			LOGP(DLMI, LOGL_ERROR, "didn't find signalling link for "
				"tei %d, sapi %d\n", tei, sapi);
			msgb_free(msg);
			return -EINVAL;
		}
		if (!ts->line->ops->sign_link) {
	                LOGP(DLINP, LOGL_ERROR, "Fix your application, "
				"no action set for signalling messages.\n");
			msgb_free(msg);
			return -ENOENT;
		}
		msg->dst = link;
		ts->line->ops->sign_link(msg);
		break;
	case E1INP_TS_TYPE_TRAU:
		ret = subch_demux_in(&ts->trau.demux, msg->l2h, msgb_l2len(msg));
		msgb_free(msg);
		break;
	case E1INP_TS_TYPE_RAW:
		ts->raw.recv_cb(ts, msg);
		break;
	case E1INP_TS_TYPE_HDLC:
		ts->hdlc.recv_cb(ts, msg);
		break;
	default:
		ret = -EINVAL;
		LOGP(DLMI, LOGL_ERROR, "unknown TS type %u\n", ts->type);
		msgb_free(msg);
		break;
	}

	return ret;
}

/*! \brief Receive some data from the L1/HDLC into LAPD of a timeslot
 *  \param[in] e1i_ts E1 Timeslot data structure
 *  \param[in] msg Message buffer containing full LAPD message
 *
 * This is a wrapper around e1inp_rx_ts(), but feeding the incoming
 * message first into our LAPD code.  This allows a driver to read raw
 * (HDLC decoded) data from the timeslot, instead of a LAPD stack
 * present in any underlying driver.
 */
int e1inp_rx_ts_lapd(struct e1inp_ts *e1i_ts, struct msgb *msg)
{
	unsigned int sapi, tei;
	int ret = 0, error = 0;

	sapi = msg->data[0] >> 2;
	if ((msg->data[0] & 0x1))
		tei = 0;
	else
		tei = msg->data[1] >> 1;

	DEBUGP(DLMI, "<= len = %d, sapi(%d) tei(%d)\n", msg->len, sapi, tei);

	ret = lapd_receive(e1i_ts->lapd, msg, &error);
	if (ret < 0) {
		switch(error) {
		case LAPD_ERR_UNKNOWN_TEI:
			/* We don't know about this TEI, probably the BSC
			 * lost local states (it crashed or it was stopped),
			 * notify the driver to see if it can do anything to
			 * recover the existing signalling links with the BTS.
			 */
			e1inp_event(e1i_ts, S_L_INP_TEI_UNKNOWN, tei, sapi);
			return -EIO;
		}
	}

	return 0;
}

void e1inp_dlsap_up(struct osmo_dlsap_prim *dp, uint8_t tei, uint8_t sapi,
        void *rx_cbdata)
{
	struct e1inp_ts *e1i_ts = rx_cbdata;
	struct msgb *msg = dp->oph.msg;

	switch (dp->oph.primitive) {
	case PRIM_DL_EST:
		DEBUGP(DLMI, "DL_EST: sapi(%d) tei(%d)\n", sapi, tei);
		e1inp_event(e1i_ts, S_L_INP_TEI_UP, tei, sapi);
		break;
	case PRIM_DL_REL:
		DEBUGP(DLMI, "DL_REL: sapi(%d) tei(%d)\n", sapi, tei);
		e1inp_event(e1i_ts, S_L_INP_TEI_DN, tei, sapi);
		break;
	case PRIM_DL_DATA:
	case PRIM_DL_UNIT_DATA:
		if (dp->oph.operation == PRIM_OP_INDICATION) {
			msg->l2h = msg->l3h;
			DEBUGP(DLMI, "RX: %s sapi=%d tei=%d\n",
				osmo_hexdump(msgb_l2(msg), msgb_l2len(msg)),
				sapi, tei);
			e1inp_rx_ts(e1i_ts, msg, tei, sapi);
			return;
		}
		break;
	case PRIM_MDL_ERROR:
		DEBUGP(DLMI, "MDL_EERROR: cause(%d)\n", dp->u.error_ind.cause);
		break;
	default:
		printf("ERROR: unknown prim\n");
		break;
	}

	msgb_free(msg);

	return;
}

#define TSX_ALLOC_SIZE 4096

/* called by driver if it wants to transmit on a given TS */
struct msgb *e1inp_tx_ts(struct e1inp_ts *e1i_ts,
			 struct e1inp_sign_link **sign_link)
{
	struct e1inp_sign_link *link;
	struct msgb *msg = NULL;
	int len;

	switch (e1i_ts->type) {
	case E1INP_TS_TYPE_SIGN:
		/* FIXME: implement this round robin */
		llist_for_each_entry(link, &e1i_ts->sign.sign_links, list) {
			msg = msgb_dequeue(&link->tx_list);
			if (msg) {
				if (sign_link)
					*sign_link = link;
				break;
			}
		}
		break;
	case E1INP_TS_TYPE_TRAU:
		msg = msgb_alloc(TSX_ALLOC_SIZE, "TRAU_TX");
		if (!msg)
			return NULL;
		len = subchan_mux_out(&e1i_ts->trau.mux, msg->data, 40);
		if (len != 40) {
			LOGP(DLMI, LOGL_ERROR,
			     "cannot transmit, failed to mux\n");
			msgb_free(msg);
			return NULL;
		}
		msgb_put(msg, 40);
		break;
	case E1INP_TS_TYPE_RAW:
		/* Get msgb from tx_queue */
		msg = msgb_dequeue(&e1i_ts->raw.tx_queue);
		break;
	case E1INP_TS_TYPE_HDLC:
		/* Get msgb from tx_queue */
		msg = msgb_dequeue(&e1i_ts->hdlc.tx_queue);
		break;
	default:
		LOGP(DLMI, LOGL_ERROR, "unsupported E1 TS type %u\n", e1i_ts->type);
		return NULL;
	}
	return msg;
}

static int e1inp_int_snd_event(struct e1inp_ts *ts,
			       struct e1inp_sign_link *link, int evt)
{
	struct input_signal_data isd;
	isd.line = ts->line;
	isd.ts_nr = ts->num;
	isd.link_type = link->type;
	isd.trx = link->trx;
	isd.tei = link->tei;
	isd.sapi = link->sapi;

	/* report further upwards */
	osmo_signal_dispatch(SS_L_INPUT, evt, &isd);
	return 0;
}


/* called by driver in case some kind of link state event */
int e1inp_event(struct e1inp_ts *ts, int evt, uint8_t tei, uint8_t sapi)
{
	struct e1inp_sign_link *link;

	link = e1inp_lookup_sign_link(ts, tei, sapi);
	if (!link)
		return -EINVAL;
	return e1inp_int_snd_event(ts, link, evt);
}

void e1inp_close_socket(struct e1inp_ts *ts,
			struct e1inp_sign_link *sign_link,
			struct osmo_fd *bfd)
{
	e1inp_int_snd_event(ts, sign_link, S_L_INP_TEI_DN);
	/* the first e1inp_sign_link_destroy call closes the socket. */
	if (bfd->fd != -1) {
		osmo_fd_unregister(bfd);
		close(bfd->fd);
		bfd->fd = -1;
	}
}

/* register a driver with the E1 core */
int e1inp_driver_register(struct e1inp_driver *drv)
{
	llist_add_tail(&drv->list, &e1inp_driver_list);
	return 0;
}

struct e1inp_driver *e1inp_driver_find(const char *name)
{
	struct e1inp_driver *drv;

	llist_for_each_entry(drv, &e1inp_driver_list, list) {
		if (!strcasecmp(name, drv->name))
			return drv;
	}
	return NULL;
}

int e1inp_line_update(struct e1inp_line *line)
{
	struct input_signal_data isd;
	int i, rc;

	e1inp_line_get(line);

	if (line->driver && line->ops && line->driver->line_update) {
		rc = line->driver->line_update(line);
	} else
		rc = 0;

	/* Set the PCAP file descriptor for all timeslots that have
	 * software LAPD instances, to ensure the osmo_lapd_pcap code is
	 * used to write PCAP files (if requested) */
	for (i = 0; i < ARRAY_SIZE(line->ts); i++) {
		struct e1inp_ts *e1i_ts = &line->ts[i];
		if (e1i_ts->lapd)
			e1i_ts->lapd->pcap_fd = pcap_fd;
	}

	/* Send a signal to anyone who is interested in new lines being
	 * configured */
	memset(&isd, 0, sizeof(isd));
	isd.line = line;
	osmo_signal_dispatch(SS_L_INPUT, S_L_INP_LINE_INIT, &isd);

	return rc;
}

static int e1i_sig_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	if (subsys != SS_L_GLOBAL ||
	    signal != S_L_GLOBAL_SHUTDOWN)
		return 0;

	if (pcap_fd) {
		close(pcap_fd);
		pcap_fd = -1;
	}

	return 0;
}

const struct value_string e1inp_signal_names[] = {
	{ S_L_INP_NONE,		"NONE" },
	{ S_L_INP_TEI_UP,	"TEI-UP" },
	{ S_L_INP_TEI_DN,	"TEI-DOWN" },
	{ S_L_INP_TEI_UNKNOWN,	"TEI-UNKNOWN" },
	{ S_L_INP_LINE_INIT,	"LINE-INIT" },
	{ S_L_INP_LINE_ALARM,	"LINE-ALARM" },
	{ S_L_INP_LINE_NOALARM,	"LINE-NOALARM" },
	{ 0, NULL }
};

void e1inp_misdn_init(void);
void e1inp_dahdi_init(void);
void e1inp_ipaccess_init(void);
void e1inp_rs232_init(void);
void e1inp_unixsocket_init(void);

void e1inp_init(void)
{
	tall_e1inp_ctx = talloc_named_const(libosmo_abis_ctx, 1, "e1inp");
	tall_sigl_ctx = talloc_named_const(tall_e1inp_ctx, 1,
					   "e1inp_sign_link");
	osmo_signal_register_handler(SS_L_GLOBAL, e1i_sig_cb, NULL);

	e1inp_misdn_init();
#ifdef HAVE_DAHDI_USER_H
	e1inp_dahdi_init();
#endif
	e1inp_ipaccess_init();
	e1inp_rs232_init();
	e1inp_unixsocket_init();
}
