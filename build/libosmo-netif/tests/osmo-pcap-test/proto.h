#ifndef _OSMO_PCAP_PROTO_H_
#define _OSMO_PCAP_PROTO_H_

#include <stdint.h>

#include <osmocom/core/linuxlist.h>

struct osmo_pcap_proto_l4 {
	struct llist_head	head;

	unsigned int		l4protonum;

	int	(*l4pkt_hdr_len)(const uint8_t *pkt);
	int	(*l4pkt_no_data)(const uint8_t *pkt);
};

struct osmo_pcap_proto_l2l3 {
	struct llist_head	head;

	unsigned int		l2protonum;
	unsigned int		l2hdr_len;

	unsigned int		l3protonum;

	int	(*l3pkt_hdr_len)(const uint8_t *pkt);
	int	(*l4pkt_proto)(const uint8_t *pkt);
};

struct osmo_pcap_proto_l2l3 *osmo_pcap_proto_l2l3_find(const uint8_t *pkt);
void osmo_pcap_proto_l2l3_register(struct osmo_pcap_proto_l2l3 *h);

struct osmo_pcap_proto_l4 *osmo_pcap_proto_l4_find(const uint8_t *pkt, unsigned int l4protonum);
void osmo_pcap_proto_l4_register(struct osmo_pcap_proto_l4 *h);

/* Initialization of supported protocols here. */
void l2l3_ipv4_init(void);
void l4_tcp_init(void);
void l4_udp_init(void);

#endif
