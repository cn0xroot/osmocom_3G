#ifndef _OSMO_AMR_H_
#define _OSMO_AMR_H_

#include <osmocom/core/endian.h>

/* As defined by RFC3267: Adaptive Multi-Rate (AMR) */

/*
 *  +----------------+-------------------+----------------
 *  | payload header | table of contents | speech data ...
 *  +----------------+-------------------+----------------
 */

/*
 * 4.4. Octet-aligned Mode:
 *
 * 4.4.1. The Payload Header:
 *
 *   0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+
 *  |  CMR  |X X X X|
 *  +-+-+-+-+-+-+-+-+
 *
 * According to: 3GPP TS 26.201 "AMR Wideband speech codec; Frame Structure",
 * version 5.0.0 (2001-03), 3rd Generation Partnership Project (3GPP):
 *
 * Possible Frame type / CMR values:
 *
 * 0-8 for AMR-WB (from 6.60 kbit/s to 23.85 kbit/s)
 * 9 (SID) confort noise.
 * 10-13 future use.
 * 14 means lost speech frame (only available for AMR-WB)
 * 15 means no data
 *
 * 4.4.2. The table of contents:
 *
 *   0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+
 *  |F|  FT   |Q|X X|
 *  +-+-+-+-+-+-+-+-+
 *
 * X means padding.
 */

struct amr_hdr {
#if OSMO_IS_BIG_ENDIAN
	/* Payload Header */
	uint8_t cmr:4,	/* Codec Mode Request */
		pad1:4;
	/* Table of Contents */
	uint8_t f:1,	/* followed by another speech frame? */
		ft:4,	/* coding mode */
		q:1,	/* OK (not damaged) at origin? */
		pad2:2;
#elif OSMO_IS_LITTLE_ENDIAN
	/* Payload Header */
	uint8_t pad1:4,
		cmr:4;
	/* Table of Contents */
	uint8_t pad2:2,
		q:1,
		ft:4,
		f:1;
#endif
} __attribute__((packed));

static inline void *osmo_amr_get_payload(struct amr_hdr *amrh)
{
	return (uint8_t *)amrh + sizeof(struct amr_hdr);
}

#define AMR_FT_0	0	/* 4.75 */
#define AMR_FT_1	1	/* 5.15 */
#define AMR_FT_2	2	/* 5.90 */
#define AMR_FT_3	3	/* 6.70 */
#define AMR_FT_4	4	/* 7.40 */
#define AMR_FT_5	5	/* 7.95 */
#define AMR_FT_6	6	/* 10.2 */
#define AMR_FT_7	7	/* 12.2 */
#define AMR_FT_SID	8	/* SID */
#define AMR_FT_MAX	9

int osmo_amr_ft_valid(uint8_t amr_ft);
size_t osmo_amr_bytes(uint8_t amr_cmr);

#endif
