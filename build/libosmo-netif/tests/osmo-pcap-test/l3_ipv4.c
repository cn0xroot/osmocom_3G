/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2012 by On Waves ehf <http://www.on-waves.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later vers
 */

#include <stdlib.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>

#include "proto.h"

#define PRINT_CMP(...)

static int l3_ipv4_pkt_l4proto_num(const uint8_t *pkt)
{
	const struct iphdr *iph = (const struct iphdr *)pkt;

	return iph->protocol;
}

static int l3_ipv4_pkt_l3hdr_len(const uint8_t *pkt)
{
	const struct iphdr *iph = (const struct iphdr *)pkt;

	return iph->ihl << 2;
}

static struct osmo_pcap_proto_l2l3 ipv4 = {
	.l2protonum	= ETH_P_IP,
	.l3protonum	= AF_INET,
	.l2hdr_len	= ETH_HLEN,
	.l3pkt_hdr_len	= l3_ipv4_pkt_l3hdr_len,
	.l4pkt_proto	= l3_ipv4_pkt_l4proto_num,
};

void l2l3_ipv4_init(void)
{
	osmo_pcap_proto_l2l3_register(&ipv4);
}
