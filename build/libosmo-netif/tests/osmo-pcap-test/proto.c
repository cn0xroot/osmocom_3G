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
#include <netinet/in.h>
#include <linux/if_ether.h>

#include <osmocom/core/linuxlist.h>
#include "proto.h"

static LLIST_HEAD(l2l3_proto_list);
static LLIST_HEAD(l4_proto_list);

struct osmo_pcap_proto_l2l3 *osmo_pcap_proto_l2l3_find(const uint8_t *pkt)
{
	const struct ethhdr *eh = (const struct ethhdr *)pkt;
	struct osmo_pcap_proto_l2l3 *cur;

	llist_for_each_entry(cur, &l2l3_proto_list, head) {
		if (ntohs(cur->l2protonum) == eh->h_proto)
			return cur;
	}
	return NULL;
}

void osmo_pcap_proto_l2l3_register(struct osmo_pcap_proto_l2l3 *h)
{
	llist_add(&h->head, &l2l3_proto_list);
}

struct osmo_pcap_proto_l4 *
osmo_pcap_proto_l4_find(const uint8_t *pkt, unsigned int l4protocol)
{
	struct osmo_pcap_proto_l4 *cur;

	llist_for_each_entry(cur, &l4_proto_list, head) {
		if (cur->l4protonum == l4protocol)
			return cur;
	}
	return NULL;
}

void osmo_pcap_proto_l4_register(struct osmo_pcap_proto_l4 *h)
{
	llist_add(&h->head, &l4_proto_list);
}
