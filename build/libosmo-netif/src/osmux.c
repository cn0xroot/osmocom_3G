/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2012 by On Waves ehf <http://www.on-waves.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>

#include <osmocom/netif/amr.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/netif/osmux.h>

#include <arpa/inet.h>

/*! \addtogroup osmux Osmocom Multiplex Protocol
 *  @{
 */

/*! \file osmux.c
 *  \brief Osmocom multiplex protocol helpers
 */


/* This allows you to debug timing reconstruction in the output path */
#if 0
#define DEBUG_TIMING		0
#endif

/* This allows you to debug osmux message transformations (spamming) */
#if 0
#define DEBUG_MSG		0
#endif

/* delta time between two RTP messages (in microseconds) */
#define DELTA_RTP_MSG		20000
/* delta time between two RTP messages (in samples, 8kHz) */
#define DELTA_RTP_TIMESTAMP	160

static void *osmux_ctx;

static uint32_t osmux_get_payload_len(struct osmux_hdr *osmuxh)
{
	return osmo_amr_bytes(osmuxh->amr_ft) * (osmuxh->ctr+1);
}

static uint32_t osmux_ft_dummy_size(uint8_t amr_ft, uint8_t batch_factor)
{
	return sizeof(struct osmux_hdr) + (osmo_amr_bytes(amr_ft) * batch_factor);
}

struct osmux_hdr *osmux_xfrm_output_pull(struct msgb *msg)
{
	struct osmux_hdr *osmuxh;
next:
	osmuxh = NULL;
	if (msg->len > sizeof(struct osmux_hdr)) {
		size_t len;

		osmuxh = (struct osmux_hdr *)msg->data;

		switch (osmuxh->ft) {
		case OSMUX_FT_VOICE_AMR:
			break;
		case OSMUX_FT_DUMMY:
			msgb_pull(msg, osmux_ft_dummy_size(osmuxh->amr_ft,
							   osmuxh->ctr + 1));
			goto next;
		default:
			LOGP(DLMIB, LOGL_ERROR, "Discarding unsupported Osmux FT %d\n",
			     osmuxh->ft);
			return NULL;
		}
		if (!osmo_amr_ft_valid(osmuxh->amr_ft)) {
			LOGP(DLMIB, LOGL_ERROR, "Discarding bad AMR FT %d\n",
			     osmuxh->amr_ft);
			return NULL;
		}

		len = osmo_amr_bytes(osmuxh->amr_ft) * (osmuxh->ctr+1) +
			sizeof(struct osmux_hdr);

		if (len > msg->len) {
			LOGP(DLMIB, LOGL_ERROR, "Discarding malformed "
						"OSMUX message\n");
			return NULL;
		}

		msgb_pull(msg, len);
	} else if (msg->len > 0) {
		LOGP(DLMIB, LOGL_ERROR,
			"remaining %d bytes, broken osmuxhdr?\n", msg->len);
	}

	return osmuxh;
}

static struct msgb *
osmux_rebuild_rtp(struct osmux_out_handle *h, struct osmux_hdr *osmuxh,
		  void *payload, int payload_len, bool first_pkt)
{
	struct msgb *out_msg;
	struct rtp_hdr *rtph;
	struct amr_hdr *amrh;

	out_msg = msgb_alloc(sizeof(struct rtp_hdr) +
			     sizeof(struct amr_hdr) +
			     osmo_amr_bytes(osmuxh->amr_ft),
			     "OSMUX test");
	if (out_msg == NULL)
		return NULL;

	/* Reconstruct RTP header */
	rtph = (struct rtp_hdr *)out_msg->data;
	rtph->csrc_count = 0;
	rtph->extension = 0;
	rtph->version = RTP_VERSION;
	rtph->payload_type = 98;
	/* ... emulate timestamp and ssrc */
	rtph->timestamp = htonl(h->rtp_timestamp);
	rtph->sequence = htons(h->rtp_seq);
	rtph->ssrc = htonl(h->rtp_ssrc);
	/* rtp packet with the marker bit is always warranted to be the first one */
	rtph->marker = first_pkt && osmuxh->rtp_m;

	msgb_put(out_msg, sizeof(struct rtp_hdr));

	/* Reconstruct AMR header */
	amrh = (struct amr_hdr *)out_msg->tail;
	amrh->cmr = osmuxh->amr_cmr;
	amrh->f = osmuxh->amr_f;
	amrh->ft = osmuxh->amr_ft;
	amrh->q = osmuxh->amr_q;

	msgb_put(out_msg, sizeof(struct amr_hdr));

	/* add AMR speech data */
	memcpy(out_msg->tail, payload, payload_len);
	msgb_put(out_msg, payload_len);

	/* bump last RTP sequence number and timestamp that has been used */
	h->rtp_seq++;
	h->rtp_timestamp += DELTA_RTP_TIMESTAMP;

	return out_msg;
}

int osmux_xfrm_output(struct osmux_hdr *osmuxh, struct osmux_out_handle *h,
		      struct llist_head *list)
{
	struct msgb *msg;
	int i;

	INIT_LLIST_HEAD(list);

	for (i=0; i<osmuxh->ctr+1; i++) {
		struct rtp_hdr *rtph;

		msg = osmux_rebuild_rtp(h, osmuxh,
					osmux_get_payload(osmuxh) +
					i * osmo_amr_bytes(osmuxh->amr_ft),
					osmo_amr_bytes(osmuxh->amr_ft), !i);
		if (msg == NULL)
			continue;

		rtph = osmo_rtp_get_hdr(msg);
		if (rtph == NULL)
			continue;

#ifdef DEBUG_MSG
		{
			char buf[4096];

			osmo_rtp_snprintf(buf, sizeof(buf), msg);
			buf[sizeof(buf)-1] = '\0';
			LOGP(DLMIB, LOGL_DEBUG, "to BTS: %s\n", buf);
		}
#endif
		llist_add_tail(&msg->list, list);
	}
	return i;
}

struct osmux_batch {
	struct osmo_timer_list	timer;
	struct osmux_hdr	*osmuxh;
	struct llist_head	circuit_list;
	unsigned int		remaining_bytes;
	uint8_t			seq;
	uint32_t		nmsgs;
	int			ndummy;
};

struct osmux_circuit {
	struct llist_head	head;
	int			ccid;
	struct llist_head	msg_list;
	int			nmsgs;
	int			dummy;
};

static int osmux_batch_enqueue(struct msgb *msg, struct osmux_circuit *circuit,
				uint8_t batch_factor)
{
	/* Too many messages per batch, discard it. The counter field of the
	 * osmux header is just 3 bits long, so make sure it doesn't overflow.
	 */
	if (circuit->nmsgs >= batch_factor || circuit->nmsgs >= 8) {
		struct rtp_hdr *rtph;

		rtph = osmo_rtp_get_hdr(msg);
		if (rtph == NULL)
			return -1;

		LOGP(DLMIB, LOGL_ERROR, "too many messages for this RTP "
					"ssrc=%u\n", rtph->ssrc);
		return -1;
	}

	llist_add_tail(&msg->list, &circuit->msg_list);
	circuit->nmsgs++;
	return 0;
}

static void osmux_batch_dequeue(struct msgb *msg, struct osmux_circuit *circuit)
{
	llist_del(&msg->list);
	circuit->nmsgs--;
}

static void osmux_circuit_del_msgs(struct osmux_batch *batch, struct osmux_circuit *circuit)
{
	struct msgb *cur, *tmp;
	llist_for_each_entry_safe(cur, tmp, &circuit->msg_list, list) {
		osmux_batch_dequeue(cur, circuit);
		msgb_free(cur);
		batch->nmsgs--;
	}
}

struct osmux_input_state {
	struct msgb	*out_msg;
	struct msgb	*msg;
	struct rtp_hdr	*rtph;
	struct amr_hdr	*amrh;
	uint32_t	amr_payload_len;
	int		ccid;
	int		add_osmux_hdr;
};

static int osmux_batch_put(struct osmux_batch *batch,
			   struct osmux_input_state *state)
{
	struct osmux_hdr *osmuxh;

	if (state->add_osmux_hdr) {
		osmuxh = (struct osmux_hdr *)state->out_msg->tail;
		osmuxh->ft = OSMUX_FT_VOICE_AMR;
		osmuxh->ctr = 0;
		osmuxh->rtp_m = osmuxh->rtp_m || state->rtph->marker;
		osmuxh->amr_f = state->amrh->f;
		osmuxh->amr_q= state->amrh->q;
		osmuxh->seq = batch->seq++;
		osmuxh->circuit_id = state->ccid;
		osmuxh->amr_cmr = state->amrh->cmr;
		osmuxh->amr_ft = state->amrh->ft;
		msgb_put(state->out_msg, sizeof(struct osmux_hdr));

		/* annotate current osmux header */
		batch->osmuxh = osmuxh;
	} else {
		if (batch->osmuxh->ctr == 0x7) {
			LOGP(DLMIB, LOGL_ERROR, "cannot add msg=%p, "
			     "too many messages for this RTP ssrc=%u\n",
			     state->msg, state->rtph->ssrc);
			return 0;
		}
		batch->osmuxh->ctr++;
	}

	memcpy(state->out_msg->tail, osmo_amr_get_payload(state->amrh),
	       state->amr_payload_len);
	msgb_put(state->out_msg, state->amr_payload_len);

	return 0;
}

static int osmux_xfrm_encode_amr(struct osmux_batch *batch,
				 struct osmux_input_state *state)
{
	uint32_t amr_len;

	state->amrh = osmo_rtp_get_payload(state->rtph, state->msg, &amr_len);
	if (state->amrh == NULL)
		return -1;

	state->amr_payload_len = amr_len - sizeof(struct amr_hdr);

	if (osmux_batch_put(batch, state) < 0)
		return -1;

	return 0;
}

static void osmux_encode_dummy(struct osmux_batch *batch, uint8_t batch_factor,
			       struct osmux_input_state *state)
{
	struct osmux_hdr *osmuxh;
	/* TODO: This should be configurable at some point. */
	uint32_t payload_size = osmux_ft_dummy_size(AMR_FT_3, batch_factor) -
				sizeof(struct osmux_hdr);

	osmuxh = (struct osmux_hdr *)state->out_msg->tail;
	osmuxh->ft = OSMUX_FT_DUMMY;
	osmuxh->ctr = batch_factor - 1;
	osmuxh->amr_f = 0;
	osmuxh->amr_q= 0;
	osmuxh->seq = 0;
	osmuxh->circuit_id = state->ccid;
	osmuxh->amr_cmr = 0;
	osmuxh->amr_ft = AMR_FT_3;
	msgb_put(state->out_msg, sizeof(struct osmux_hdr));

	memset(state->out_msg->tail, 0xff, payload_size);
	msgb_put(state->out_msg, payload_size);
}

static struct msgb *osmux_build_batch(struct osmux_batch *batch,
				      uint32_t batch_size, uint8_t batch_factor)
{
	struct msgb *batch_msg;
	struct osmux_circuit *circuit;

#ifdef DEBUG_MSG
	LOGP(DLMIB, LOGL_DEBUG, "Now building batch\n");
#endif

	batch_msg = msgb_alloc(batch_size, "osmux");
	if (batch_msg == NULL) {
		LOGP(DLMIB, LOGL_ERROR, "Not enough memory\n");
		return NULL;
	}

	llist_for_each_entry(circuit, &batch->circuit_list, head) {
		struct msgb *cur, *tmp;
		int ctr = 0;

		if (circuit->dummy) {
			struct osmux_input_state state = {
				.out_msg	= batch_msg,
				.ccid		= circuit->ccid,
			};
			osmux_encode_dummy(batch, batch_factor, &state);
			continue;
		}

		llist_for_each_entry_safe(cur, tmp, &circuit->msg_list, list) {
			struct osmux_input_state state = {
				.msg		= cur,
				.out_msg	= batch_msg,
				.ccid		= circuit->ccid,
			};
#ifdef DEBUG_MSG
			char buf[4096];

			osmo_rtp_snprintf(buf, sizeof(buf), cur);
			buf[sizeof(buf)-1] = '\0';
			LOGP(DLMIB, LOGL_DEBUG, "to BSC-NAT: %s\n", buf);
#endif

			state.rtph = osmo_rtp_get_hdr(cur);
			if (state.rtph == NULL)
				return NULL;

			if (ctr == 0) {
#ifdef DEBUG_MSG
				LOGP(DLMIB, LOGL_DEBUG, "add osmux header\n");
#endif
				state.add_osmux_hdr = 1;
			}

			osmux_xfrm_encode_amr(batch, &state);
			osmux_batch_dequeue(cur, circuit);
			msgb_free(cur);
			ctr++;
			batch->nmsgs--;
		}
	}
	return batch_msg;
}

void osmux_xfrm_input_deliver(struct osmux_in_handle *h)
{
	struct msgb *batch_msg;
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;

#ifdef DEBUG_MSG
	LOGP(DLMIB, LOGL_DEBUG, "invoking delivery function\n");
#endif
	batch_msg = osmux_build_batch(batch, h->batch_size, h->batch_factor);
	if (!batch_msg)
		return;
	h->stats.output_osmux_msgs++;
	h->stats.output_osmux_bytes += batch_msg->len;

	h->deliver(batch_msg, h->data);
	osmo_timer_del(&batch->timer);
	batch->remaining_bytes = h->batch_size;

	if (batch->ndummy) {
		osmo_timer_schedule(&batch->timer, 0,
				    h->batch_factor * DELTA_RTP_MSG);
	}
}

static void osmux_batch_timer_expired(void *data)
{
	struct osmux_in_handle *h = data;

#ifdef DEBUG_MSG
	LOGP(DLMIB, LOGL_DEBUG, "osmux_batch_timer_expired\n");
#endif
	osmux_xfrm_input_deliver(h);
}

static int osmux_rtp_amr_payload_len(struct msgb *msg, struct rtp_hdr *rtph)
{
	struct amr_hdr *amrh;
	unsigned int amr_len;
	int amr_payload_len;

	amrh = osmo_rtp_get_payload(rtph, msg, &amr_len);
	if (amrh == NULL)
		return -1;

	if (!osmo_amr_ft_valid(amrh->ft))
		return -1;

	amr_payload_len = amr_len - sizeof(struct amr_hdr);

	/* The AMR payload does not fit with what we expect */
	if (osmo_amr_bytes(amrh->ft) != amr_payload_len) {
		LOGP(DLMIB, LOGL_ERROR,
		     "Bad AMR frame, expected %zd bytes, got %d bytes\n",
		     osmo_amr_bytes(amrh->ft), amr_len);
		return -1;
	}
	return amr_payload_len;
}

static void osmux_replay_lost_packets(struct osmux_circuit *circuit,
				      struct rtp_hdr *cur_rtph, int batch_factor)
{
	int16_t diff;
	struct msgb *last;
	struct rtp_hdr *rtph;
	int i;

	/* Have we see any RTP packet in this batch before? */
	if (llist_empty(&circuit->msg_list))
		return;

	/* Get last RTP packet seen in this batch */
	last = llist_entry(circuit->msg_list.prev, struct msgb, list);
	rtph = osmo_rtp_get_hdr(last);
	if (rtph == NULL)
		return;

	diff = ntohs(cur_rtph->sequence) - ntohs(rtph->sequence);

	/* Lifesaver: make sure bugs don't spawn lots of clones */
	if (diff > 16)
		diff = 16;

	/* If diff between last RTP packet seen and this one is > 1,
	 * then we lost several RTP packets, let's replay them.
	 */
	for (i=1; i<diff; i++) {
		struct msgb *clone;

		/* Clone last RTP packet seen */
		clone = msgb_alloc(last->data_len, "RTP clone");
		if (!clone)
			continue;

		memcpy(clone->data, last->data, last->len);
		msgb_put(clone, last->len);

		/* The original RTP message has been already sanity check. */
		rtph = osmo_rtp_get_hdr(clone);

		/* Adjust sequence number and timestamp */
		rtph->sequence = htons(ntohs(rtph->sequence) + i);
		rtph->timestamp = htonl(ntohl(rtph->timestamp) +
					DELTA_RTP_TIMESTAMP);

		/* No more room in this batch, skip padding with more clones */
		if (osmux_batch_enqueue(clone, circuit, batch_factor) < 0) {
			msgb_free(clone);
			break;
		}

		LOGP(DLMIB, LOGL_ERROR, "adding cloned RTP\n");
	}
}

static struct osmux_circuit *
osmux_batch_find_circuit(struct osmux_batch *batch, int ccid)
{
	struct osmux_circuit *circuit;

	llist_for_each_entry(circuit, &batch->circuit_list, head) {
		if (circuit->ccid == ccid)
			return circuit;
	}
	return NULL;
}

static struct osmux_circuit *
osmux_batch_add_circuit(struct osmux_batch *batch, int ccid, int dummy,
			uint8_t batch_factor)
{
	struct osmux_circuit *circuit;

	circuit = osmux_batch_find_circuit(batch, ccid);
	if (circuit != NULL) {
		LOGP(DLMIB, LOGL_ERROR, "circuit %u already exists!\n", ccid);
		return NULL;
	}

	circuit = talloc_zero(osmux_ctx, struct osmux_circuit);
	if (circuit == NULL) {
		LOGP(DLMIB, LOGL_ERROR, "OOM on circuit %u\n", ccid);
		return NULL;
	}

	circuit->ccid = ccid;
	INIT_LLIST_HEAD(&circuit->msg_list);
	llist_add_tail(&circuit->head, &batch->circuit_list);

	if (dummy) {
		circuit->dummy = dummy;
		batch->ndummy++;
		if (!osmo_timer_pending(&batch->timer))
			osmo_timer_schedule(&batch->timer, 0,
					    batch_factor * DELTA_RTP_MSG);
	}
	return circuit;
}

static void osmux_batch_del_circuit(struct osmux_batch *batch, struct osmux_circuit *circuit)
{
	if (circuit->dummy)
		batch->ndummy--;
	llist_del(&circuit->head);
	osmux_circuit_del_msgs(batch, circuit);
	talloc_free(circuit);
}

static int
osmux_batch_add(struct osmux_batch *batch, uint32_t batch_factor, struct msgb *msg,
		struct rtp_hdr *rtph, int ccid)
{
	int bytes = 0, amr_payload_len;
	struct osmux_circuit *circuit;
	struct msgb *cur;

	circuit = osmux_batch_find_circuit(batch, ccid);
	if (!circuit)
		return -1;

	/* We've seen the first RTP message, disable dummy padding */
	if (circuit->dummy) {
		circuit->dummy = 0;
		batch->ndummy--;
	}
	amr_payload_len = osmux_rtp_amr_payload_len(msg, rtph);
	if (amr_payload_len < 0)
		return -1;

	/* First check if there is room for this message in the batch */
	bytes += amr_payload_len;
	if (circuit->nmsgs == 0)
		bytes += sizeof(struct osmux_hdr);

	/* No room, sorry. You'll have to retry */
	if (bytes > batch->remaining_bytes)
		return 1;

	/* Init of talkspurt (RTP M marker bit) needs to be in the first AMR slot
	 * of the OSMUX packet, enforce sending previous batch if required:
	 */
	if (rtph->marker && circuit->nmsgs != 0)
		return 1;


	/* Extra validation: check if this message already exists, should not
	 * happen but make sure we don't propagate duplicated messages.
	 */
	llist_for_each_entry(cur, &circuit->msg_list, list) {
		struct rtp_hdr *rtph2 = osmo_rtp_get_hdr(cur);
		if (rtph2 == NULL)
			return -1;

		/* Already exists message with this sequence, skip */
		if (rtph2->sequence == rtph->sequence) {
			LOGP(DLMIB, LOGL_ERROR, "already exists "
				"message with seq=%u, skip it\n",
				rtph->sequence);
			return -1;
		}
	}
	/* Handle RTP packet loss scenario */
	osmux_replay_lost_packets(circuit, rtph, batch_factor);

	/* This batch is full, force batch delivery */
	if (osmux_batch_enqueue(msg, circuit, batch_factor) < 0)
		return 1;

#ifdef DEBUG_MSG
	LOGP(DLMIB, LOGL_DEBUG, "adding msg with ssrc=%u to batch\n",
		rtph->ssrc);
#endif

	/* Update remaining room in this batch */
	batch->remaining_bytes -= bytes;

	if (batch->nmsgs == 0) {
#ifdef DEBUG_MSG
		LOGP(DLMIB, LOGL_DEBUG, "osmux start timer batch\n");
#endif
		osmo_timer_schedule(&batch->timer, 0,
				    batch_factor * DELTA_RTP_MSG);
	}
	batch->nmsgs++;

	return 0;
}

/**
 * osmux_xfrm_input - add RTP message to OSmux batch
 * \param msg: RTP message that you want to batch into one OSmux message
 *
 * If 0 is returned, this indicates that the message has been batched or that
 * an error occured and we have skipped the message. If 1 is returned, you
 * have to invoke osmux_xfrm_input_deliver and try again.
 *
 * The function takes care of releasing the messages in case of error and
 * when building the batch.
 */
int osmux_xfrm_input(struct osmux_in_handle *h, struct msgb *msg, int ccid)
{
	int ret;
	struct rtp_hdr *rtph;
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;

	/* Ignore too big RTP/RTCP messages, most likely forged. Sanity check
	 * to avoid a possible forever loop in the caller.
	 */
	if (msg->len > h->batch_size - sizeof(struct osmux_hdr)) {
		msgb_free(msg);
		return 0;
	}

	rtph = osmo_rtp_get_hdr(msg);
	if (rtph == NULL) {
		msgb_free(msg);
		return 0;
	}

	switch(rtph->payload_type) {
		case RTP_PT_RTCP:
			msgb_free(msg);
			return 0;
		default:
			/* The RTP payload type is dynamically allocated,
			 * although we use static ones. Assume that we always
			 * receive AMR traffic.
			 */

			/* Add this RTP to the OSMUX batch */
			ret = osmux_batch_add(batch, h->batch_factor,
					      msg, rtph, ccid);
			if (ret < 0) {
				/* Cannot put this message into the batch.
				 * Malformed, duplicated, OOM. Drop it and tell
				 * the upper layer that we have digest it.
				 */
				msgb_free(msg);
				return 0;
			}

			h->stats.input_rtp_msgs++;
			h->stats.input_rtp_bytes += msg->len;
			break;
	}
	return ret;
}

void osmux_xfrm_input_init(struct osmux_in_handle *h)
{
	struct osmux_batch *batch;

	/* Default to osmux packet size if not specified */
	if (h->batch_size == 0)
		h->batch_size = OSMUX_BATCH_DEFAULT_MAX;

	batch = talloc_zero(osmux_ctx, struct osmux_batch);
	if (batch == NULL)
		return;

	INIT_LLIST_HEAD(&batch->circuit_list);
	batch->remaining_bytes = h->batch_size;
	batch->timer.cb = osmux_batch_timer_expired;
	batch->timer.data = h;

	h->internal_data = (void *)batch;

	LOGP(DLMIB, LOGL_DEBUG, "initialized osmux input converter\n");
}

int osmux_xfrm_input_open_circuit(struct osmux_in_handle *h, int ccid,
				  int dummy)
{
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;

	return osmux_batch_add_circuit(batch, ccid, dummy, h->batch_factor) ? 0 : -1;
}

void osmux_xfrm_input_close_circuit(struct osmux_in_handle *h, int ccid)
{
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;
	struct osmux_circuit *circuit;

	circuit = osmux_batch_find_circuit(batch, ccid);
	if (circuit == NULL)
		return;

	osmux_batch_del_circuit(batch, circuit);
}

void osmux_xfrm_input_fini(struct osmux_in_handle *h)
{
	struct osmux_batch *batch = (struct osmux_batch *)h->internal_data;
	struct osmux_circuit *circuit, *next;

	llist_for_each_entry_safe(circuit, next, &batch->circuit_list, head)
		osmux_batch_del_circuit(batch, circuit);

	osmo_timer_del(&batch->timer);
	talloc_free(batch);
}

struct osmux_tx_handle {
	struct osmo_timer_list	timer;
	struct msgb		*msg;
	void			(*tx_cb)(struct msgb *msg, void *data);
	void			*data;
#ifdef DEBUG_TIMING
	struct timeval		start;
	struct timeval		when;
#endif
};

static void osmux_tx_cb(void *data)
{
	struct osmux_tx_handle *h = data;
#ifdef DEBUG_TIMING
	struct timeval now, diff;

	osmo_gettimeofday(&now, NULL);
	timersub(&now, &h->start, &diff);
	timersub(&diff,&h->when, &diff);
	LOGP(DLMIB, LOGL_DEBUG, "we are lagging %lu.%.6lu in scheduled "
		"transmissions\n", diff.tv_sec, diff.tv_usec);
#endif

	h->tx_cb(h->msg, h->data);

	talloc_free(h);
}

static void
osmux_tx(struct msgb *msg, struct timeval *when,
	 void (*tx_cb)(struct msgb *msg, void *data), void *data)
{
	struct osmux_tx_handle *h;

	h = talloc_zero(osmux_ctx, struct osmux_tx_handle);
	if (h == NULL)
		return;

	h->msg = msg;
	h->tx_cb = tx_cb;
	h->data = data;
	h->timer.cb = osmux_tx_cb;
	h->timer.data = h;

#ifdef DEBUG_TIMING
	osmo_gettimeofday(&h->start, NULL);
	h->when.tv_sec = when->tv_sec;
	h->when.tv_usec = when->tv_usec;
#endif
	/* send it now */
	if (when->tv_sec == 0 && when->tv_usec == 0) {
		osmux_tx_cb(h);
		return;
	}
	osmo_timer_schedule(&h->timer, when->tv_sec, when->tv_usec);
}

void
osmux_tx_sched(struct llist_head *list,
	       void (*tx_cb)(struct msgb *msg, void *data), void *data)
{
	struct msgb *cur, *tmp;
	struct timeval delta = { .tv_sec = 0, .tv_usec = DELTA_RTP_MSG };
	struct timeval when;

	timerclear(&when);

	llist_for_each_entry_safe(cur, tmp, list, list) {

#ifdef DEBUG_MSG
		LOGP(DLMIB, LOGL_DEBUG, "scheduled transmision in %lu.%6lu "
			"seconds, msg=%p\n", when.tv_sec, when.tv_usec, cur);
#endif
		llist_del(&cur->list);
		osmux_tx(cur, &when, tx_cb, data);
		timeradd(&when, &delta, &when);
	}
}

void osmux_xfrm_output_init(struct osmux_out_handle *h, uint32_t rtp_ssrc)
{
	h->rtp_seq = (uint16_t)random();
	h->rtp_timestamp = (uint32_t)random();
	h->rtp_ssrc = rtp_ssrc;
}

#define SNPRINTF_BUFFER_SIZE(ret, size, len, offset)	\
	size += ret;					\
	if (ret > len)					\
		ret = len;				\
	offset += ret;					\
	len -= ret;

static int osmux_snprintf_header(char *buf, size_t size, struct osmux_hdr *osmuxh)
{
	int ret;
	int len = size, offset = 0;

	ret = snprintf(buf, len, "OSMUX seq=%03u ccid=%03u "
				 "ft=%01u ctr=%01u "
				 "amr_f=%01u amr_q=%01u "
				 "amr_ft=%02u amr_cmr=%02u ",
			osmuxh->seq, osmuxh->circuit_id,
			osmuxh->ft, osmuxh->ctr,
			osmuxh->amr_f, osmuxh->amr_q,
			osmuxh->amr_ft, osmuxh->amr_cmr);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int osmux_snprintf_payload(char *buf, size_t size,
				  const uint8_t *payload, int payload_len)
{
	int ret, i;
	int len = size, offset = 0;

	for (i=0; i<payload_len; i++) {
		ret = snprintf(buf+offset, len, "%02x ", payload[i]);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf+offset, len, "]");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}


int osmux_snprintf(char *buf, size_t size, struct msgb *msg)
{
	int ret;
	unsigned int offset = 0;
	int msg_len = msg->len, len = size;
	struct osmux_hdr *osmuxh;
	int this_len, msg_off = 0;

	while (msg_len > 0) {
		if (msg_len < sizeof(struct osmux_hdr)) {
			LOGP(DLMIB, LOGL_ERROR,
			     "No room for OSMUX header: only %d bytes\n",
			     msg_len);
			return -1;
		}
		osmuxh = (struct osmux_hdr *)((uint8_t *)msg->data + msg_off);

		if (!osmo_amr_ft_valid(osmuxh->amr_ft)) {
			LOGP(DLMIB, LOGL_ERROR, "Bad AMR FT %d, skipping\n",
			     osmuxh->amr_ft);
			return -1;
		}

		ret = osmux_snprintf_header(buf+offset, size, osmuxh);
		if (ret < 0)
			break;
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		this_len = sizeof(struct osmux_hdr) +
			   osmux_get_payload_len(osmuxh);
		msg_off += this_len;

		if (msg_len < this_len) {
			LOGP(DLMIB, LOGL_ERROR,
			     "No room for OSMUX payload: only %d bytes\n",
			     msg_len);
			return -1;
		}

		ret = osmux_snprintf_payload(buf+offset, size,
					     osmux_get_payload(osmuxh),
					     osmux_get_payload_len(osmuxh));
		if (ret < 0)
			break;
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		msg_len -= this_len;
	}

	return offset;
}

/*! @} */
