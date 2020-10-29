/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2012 by On Waves ehf <http://www.on-waves.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later vers
 */

#include <netinet/ip.h>
#include <netinet/udp.h>

#include "proto.h"

static int l4_udp_pkt_hdr_len(const uint8_t *pkt)
{
	return sizeof(struct udphdr);
}

static int l4_udp_pkt_no_data(const uint8_t *pkt)
{
	/* UDP has no control packets. */
	return 0;
}

static struct osmo_pcap_proto_l4 udp = {
	.l4protonum	= IPPROTO_UDP,
	.l4pkt_hdr_len	= l4_udp_pkt_hdr_len,
	.l4pkt_no_data	= l4_udp_pkt_no_data,
};

void l4_udp_init(void)
{
	osmo_pcap_proto_l4_register(&udp);
}
