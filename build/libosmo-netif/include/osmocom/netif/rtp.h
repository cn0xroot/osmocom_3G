#ifndef _OSMO_RTP_H_
#define _OSMO_RTP_H_

#include <osmocom/core/endian.h>

/* RTP header as defined by RFC 3550 */
struct rtp_hdr {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t  csrc_count:4,
		 extension:1,
		 padding:1,
		 version:2;
	uint8_t  payload_type:7,
		 marker:1;
#elif OSMO_IS_BIG_ENDIAN
	uint8_t  version:2,
		 padding:1,
		 extension:1,
		 csrc_count:4;
	uint8_t  marker:1,
		 payload_type:7;
#endif
	uint16_t sequence;
	uint32_t timestamp;
	uint32_t ssrc;
	uint8_t data[0];
} __attribute__((packed));

#define RTP_VERSION	2

/* 5.3.1 RTP Header Extension
 *
 * If the X bit in the RTP header is one, a variable-length header
 * extension MUST be appended to the RTP header, following the CSRC list
 * if present. The header extension contains a 16-bit length field that
 * counts the number of 32-bit words in the extension, excluding the
 * four-octet extension header (therefore zero is a valid length).  Only
 * a single extension can be appended to the RTP data header.
 */
struct rtp_x_hdr {
	uint16_t by_profile;
	uint16_t length;
} __attribute__((packed));

/* RTPC header. */
struct rtcp_hdr {
	uint8_t byte0;
	uint8_t type;
	uint16_t length;
} __attribute__((packed));

/* XXX: RFC specifies that MTU should used, add generic function to obtain
	existing MTU. */
#define RTP_MSGB_SIZE  1500


struct msgb;

struct osmo_rtp_handle *osmo_rtp_handle_create(void *ctx);
void osmo_rtp_handle_free(struct osmo_rtp_handle *h);

int osmo_rtp_handle_tx_set_sequence(struct osmo_rtp_handle *h, uint16_t seq);
int osmo_rtp_handle_tx_set_ssrc(struct osmo_rtp_handle *h, uint32_t ssrc);
int osmo_rtp_handle_tx_set_timestamp(struct osmo_rtp_handle *h, uint32_t timestamp);

struct rtp_hdr *osmo_rtp_get_hdr(struct msgb *msg);
void *osmo_rtp_get_payload(struct rtp_hdr *rtph, struct msgb *msg, uint32_t *plen);

struct msgb *osmo_rtp_build(struct osmo_rtp_handle *h, uint8_t payload_type, uint32_t payload_len, const void *data, uint32_t duration);

int osmo_rtp_snprintf(char *buf, size_t size, struct msgb *msg);

/* supported RTP payload types. */
#define RTP_PT_RTCP			72	/* RFC 3551: 72-76 for RTCP */

#define RTP_PT_GSM_FULL			3
#define RTP_PT_GSM_FULL_PAYLOAD_LEN	33
#define RTP_PT_GSM_FULL_DURATION	160	/* in samples. */

#define RTP_PT_GSM_HALF			96

#define RTP_PT_GSM_EFR			97
#define RTP_PT_GSM_EFR_PAYLOAD_LEN	31
#define RTP_PT_GSM_EFR_DURATION		160	/* in samples. */

#define RTP_PT_AMR			98

#endif
