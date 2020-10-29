#include <stdint.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>	/* for memcpy. */
#include <arpa/inet.h>	/* for ntohs. */

#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>

#include <osmocom/netif/rtp.h>

/*
 * Internal definitions for this implementation.
 */

struct osmo_rtp_handle {
	struct {
		uint16_t		sequence;
		uint32_t		timestamp;
		uint32_t		ssrc;
		struct timeval		last_tv;
	} tx;
};

struct osmo_rtp_handle *osmo_rtp_handle_create(void *ctx)
{
	struct osmo_rtp_handle *h;

	h = talloc_zero(ctx, struct osmo_rtp_handle);
	if (h == NULL) {
		LOGP(DLMUX, LOGL_ERROR, "OOM\n");
		return NULL;
	}
	return h;
}

void osmo_rtp_handle_free(struct osmo_rtp_handle *h)
{
	DEBUGP(DLMUX, "%s (h=%p)\n", __FUNCTION__, h);

	talloc_free(h);
}

int osmo_rtp_handle_tx_set_sequence(struct osmo_rtp_handle *h, uint16_t seq)
{
	DEBUGP(DLMUX, "%s (handle=%p, seq=%hu)\n", __FUNCTION__, h, seq);

	h->tx.sequence = seq;

	return 0;
}

int osmo_rtp_handle_tx_set_ssrc(struct osmo_rtp_handle *h, uint32_t ssrc)
{
	DEBUGP(DLMUX, "%s (handle=%p, seq=%hu)\n", __FUNCTION__, h, ssrc);

	h->tx.ssrc = ssrc;
	return 0;
}

int osmo_rtp_handle_tx_set_timestamp(struct osmo_rtp_handle *h, uint32_t timestamp)
{
	DEBUGP(DLMUX, "%s (handle=%p, ts=%hu)\n", __FUNCTION__, h, timestamp);

	h->tx.timestamp = timestamp;
	return 0;
}

struct rtp_hdr *osmo_rtp_get_hdr(struct msgb *msg)
{
	struct rtp_hdr *rtph = (struct rtp_hdr *)msg->data;

	if (msg->len < sizeof(struct rtp_hdr)) {
		DEBUGPC(DLMUX, "received RTP frame too short (len = %d)\n",
			msg->len);
		return NULL;
	}
	if (rtph->version != RTP_VERSION) {
		DEBUGPC(DLMUX, "received RTP version %d not supported.\n",
			rtph->version);
		return NULL;
	}

	return rtph;
}

void *osmo_rtp_get_payload(struct rtp_hdr *rtph, struct msgb *msg,
			   uint32_t *plen)
{
	struct rtp_x_hdr *rtpxh;
	uint8_t *payload;
	int payload_len;
	int x_len;
	int csrc_len;

	csrc_len = rtph->csrc_count << 2;
	payload = msg->data + sizeof(struct rtp_hdr) + csrc_len;
	payload_len = msg->len - sizeof(struct rtp_hdr) - csrc_len;
	if (payload_len < 0) {
		DEBUGPC(DLMUX, "received RTP frame too short (len = %d, "
			"csrc count = %d)\n", msg->len, rtph->csrc_count);
		return NULL;
	}
	if (rtph->extension) {
		if (payload_len < sizeof(struct rtp_x_hdr)) {
			DEBUGPC(DLMUX, "received RTP frame too short for "
				"extension header\n");
			return NULL;
		}
		rtpxh = (struct rtp_x_hdr *)payload;
		x_len = ntohs(rtpxh->length) * 4 + sizeof(struct rtp_x_hdr);
		payload += x_len;
		payload_len -= x_len;
		if (payload_len < 0) {
			DEBUGPC(DLMUX, "received RTP frame too short, "
				"extension header exceeds frame length\n");
			return NULL;
		}
	}
	if (rtph->padding) {
		if (payload_len < 0) {
			DEBUGPC(DLMUX, "received RTP frame too short for "
				"padding length\n");
			return NULL;
		}
		payload_len -= payload[payload_len - 1];
		if (payload_len < 0) {
			DEBUGPC(DLMUX, "received RTP frame with padding "
				"greater than payload\n");
			return NULL;
		}
	}

	*plen = payload_len;
	return (uint8_t *)msg->data + msg->len - payload_len;
}

struct msgb *
osmo_rtp_build(struct osmo_rtp_handle *h, uint8_t payload_type,
	       uint32_t payload_len, const void *data, uint32_t duration)
{
	struct msgb *msg;
	struct rtp_hdr *rtph;
	struct timeval tv, tv_diff;
	long int usec_diff, frame_diff;

	gettimeofday(&tv, NULL);
	timersub(&tv, &h->tx.last_tv, &tv_diff);
	h->tx.last_tv = tv;

	usec_diff = tv_diff.tv_sec * 1000000 + tv_diff.tv_usec;
	frame_diff = (usec_diff / 20000);

	if (abs(frame_diff) > 1) {
		long int frame_diff_excess = frame_diff - 1;

		LOGP(DLMUX, LOGL_NOTICE,
			"Correcting frame difference of %ld frames\n",
			frame_diff_excess);
		h->tx.sequence += frame_diff_excess;
		h->tx.timestamp += frame_diff_excess * duration;
	}

	msg = msgb_alloc(sizeof(struct rtp_hdr) + payload_len, "RTP");
	if (!msg) {
		LOGP(DLMUX, LOGL_ERROR, "OOM\n");
		return NULL;
	}
	rtph = (struct rtp_hdr *)msg->data;
	rtph->version = RTP_VERSION;
	rtph->padding = 0;
	rtph->extension = 0;
	rtph->csrc_count = 0;
	rtph->marker = 0;
	rtph->payload_type = payload_type;
	rtph->sequence = htons(h->tx.sequence++);
	rtph->timestamp = htonl(h->tx.timestamp);
	h->tx.timestamp += duration;
	rtph->ssrc = htonl(h->tx.ssrc);
	memcpy(msg->data + sizeof(struct rtp_hdr), data, payload_len);
	msgb_put(msg, sizeof(struct rtp_hdr) + payload_len);

	return msg;
}

#define SNPRINTF_BUFFER_SIZE(ret, size, len, offset)	\
	size += ret;					\
	if (ret > len)					\
		ret = len;				\
	offset += ret;					\
	len -= ret;

int osmo_rtp_snprintf(char *buf, size_t size, struct msgb *msg)
{
	struct rtp_hdr *rtph;
	int ret, i;
	uint8_t *payload;
	unsigned int len = size, offset = 0;

	rtph = osmo_rtp_get_hdr(msg);
	if (rtph == NULL)
		return -1;

	payload = (uint8_t *)rtph + sizeof(struct rtp_hdr);

	ret = snprintf(buf, len, "RTP ver=%01u ssrc=%u type=%02u "
			"marker=%01u ext=%01u csrc_count=%01u "
			"sequence=%u timestamp=%u [", rtph->version,
			ntohl(rtph->ssrc), rtph->payload_type,
			rtph->marker, rtph->extension,
			rtph->csrc_count, ntohs(rtph->sequence),
			ntohl(rtph->timestamp));
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	for (i=0; i<msg->len - sizeof(struct rtp_hdr); i++) {
		ret = snprintf(buf+offset, len, "%02x ", payload[i]);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf+offset, len, "]");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return ret;
}
