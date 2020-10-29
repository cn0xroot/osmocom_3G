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
#include <netinet/tcp.h>

#include "proto.h"

static int l4_tcp_pkt_hdr_len(const uint8_t *pkt)
{
	const struct tcphdr *tcph = (const struct tcphdr *)pkt;

	return tcph->doff << 2;
}

static int l4_tcp_pkt_no_data(const uint8_t *pkt)
{
	const struct tcphdr *tcph = (const struct tcphdr *)pkt;
	return tcph->syn || tcph->fin || tcph->rst || !tcph->psh;
}

static struct osmo_pcap_proto_l4 tcp = {
	.l4protonum	= IPPROTO_TCP,
	.l4pkt_hdr_len	= l4_tcp_pkt_hdr_len,
	.l4pkt_no_data	= l4_tcp_pkt_no_data,
};

void l4_tcp_init(void)
{
	osmo_pcap_proto_l4_register(&tcp);
}
