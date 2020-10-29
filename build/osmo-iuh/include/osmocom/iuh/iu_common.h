#pragma once

/* A humble attempt of reading the Iu messages (RUA/RANAP/HNBAP) without an asn.1 parser.
 * Not actually used anywhere (yet?) */

struct iu_common_hdr {
	uint8_t	msg_type;
	uint8_t procedure_code;
	uint8_t criticality;
	uint8_t len;		/* first byte of length field */
	uint8_t payload[0];	/* possible further length field + payload */
	/* extension? */
	/* ? */
	/* number of ProtocolIEs */
} __attribute__ ((packed));

struct iu_common_ie {
	uint16_t iei;
	uint8_t criticality;
	uint8_t len;		/* first byte of length field */
	uint8_t payload[0];	/* possible further length field + payload */
} __attribute__ ((packed));

