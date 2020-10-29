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
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/select.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>

#include <osmocom/netif/rtp.h>
#include <osmocom/netif/osmux.h>

#include "osmo_pcap.h"

#define DOSMUXTEST 0

/*
 * This is the output handle for osmux, it stores last RTP sequence and
 * timestamp that has been used. There should be one per circuit ID.
 */
static struct osmux_out_handle h_output;

static void tx_cb(struct msgb *msg, void *data)
{
	printf("now sending message scheduled [emulated], msg=%p\n", msg);
	/*
	 * Here we should call the real function that sends the message
	 * instead of releasing it.
	 */
	msgb_free(msg);
}

static void deliver(struct msgb *batch_msg)
{
	struct osmux_hdr *osmuxh;
	struct llist_head list;

	printf("sending batch (len=%d) [emulated]\n", batch_msg->len);

	/* This code below belongs to the osmux receiver */
	while((osmuxh = osmux_xfrm_output_pull(batch_msg)) != NULL) {

		osmux_xfrm_output(osmuxh, &h_output, &list);
		osmux_tx_sched(&list, tx_cb, NULL);
	}
	msgb_free(batch_msg);
}

/*
 * This is the input handle for osmux. It stores the last osmux sequence that
 * has been used and the deliver function that sends the osmux batch.
 */
struct osmux_in_handle h_input = {
	.osmux_seq	= 0, /* sequence number to start OSmux message from */
	.batch_factor = 4, /* batch up to 4 RTP messages */
	.deliver	= deliver,
};

#define MAX_CONCURRENT_CALLS	8

static int ccid[MAX_CONCURRENT_CALLS] = { -1, -1, -1, -1, -1, -1, -1, -1 };

static void register_ccid(uint32_t ssrc)
{
       int i, found = 0;

       for (i=0; i<MAX_CONCURRENT_CALLS; i++) {
               if (ccid[i] == ssrc)
                       continue;
               if (ccid[i] < 0) {
                       found = 1;
                       break;
               }
       }

       if (found) {
               ccid[i] = ssrc;
               LOGP(DOSMUXTEST, LOGL_DEBUG, "mapping ssrc=%u to ccid=%d\n",
                       ntohl(ssrc), i);
       } else {
               LOGP(DOSMUXTEST, LOGL_ERROR, "cannot map ssrc to ccid!\n");
       }
}

static int get_ccid(uint32_t ssrc)
{
       int i, found = 0;

       for (i=0; i<MAX_CONCURRENT_CALLS; i++) {
               if (ccid[i] == ssrc) {
                       found = 1;
                       break;
               }
       }

       return found ? i : -1;
}

static int pcap_test_run(struct msgb *msg)
{
	int ret, ccid;
	struct rtp_hdr *rtph;

	rtph = osmo_rtp_get_hdr(msg);
	if (rtph == NULL)
		return 0;

	ccid = get_ccid(rtph->ssrc);
	if (ccid < 0)
		register_ccid(rtph->ssrc);

	while ((ret = osmux_xfrm_input(&h_input, msg, ccid)) > 1) {
		/* batch full, deliver it */
		osmux_xfrm_input_deliver(&h_input);
	}
	if (ret == -1)
		printf("something is wrong\n");

	return 0;
}

static struct osmo_pcap osmo_pcap;

static void osmo_pcap_pkt_timer_cb(void *data)
{
	if (osmo_pcap_test_run(&osmo_pcap, IPPROTO_UDP, pcap_test_run) < 0) {
		osmo_pcap_stats_printf();
		printf("\e[1;34mDone.\e[0m\n");
		osmo_pcap_test_close(osmo_pcap.h);
		exit(EXIT_SUCCESS);
	}
}

struct log_info_cat osmux_test_cat[] = {
	[DOSMUXTEST] = {
		.name = "DOSMUXTEST",
		.description = "osmux test",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
};

const struct log_info osmux_log_info = {
	.filter_fn = NULL,
	.cat = osmux_test_cat,
	.num_cat = ARRAY_SIZE(osmux_test_cat),
};

static void *tall_test;

int main(int argc, char *argv[])
{
	int ret;

	if (argc != 2) {
		fprintf(stderr, "Wrong usage:\n");
		fprintf(stderr, "%s <pcap_file>\n", argv[0]);
		fprintf(stderr, "example: %s file.pcap\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	tall_test = talloc_named_const(NULL, 1, "osmux_pcap_test");
	osmo_init_logging(&osmux_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);

	osmo_pcap_init();

	printf("\e[1;34mStarting test...\e[0m\n");

	osmo_pcap.h = osmo_pcap_test_open(argv[1]);
	if (osmo_pcap.h == NULL)
		exit(EXIT_FAILURE);

	osmo_pcap.timer.cb = osmo_pcap_pkt_timer_cb;

	osmux_xfrm_input_init(&h_input);
	osmux_xfrm_output_init(&h_output);

	/* first run */
	osmo_pcap_pkt_timer_cb(NULL);

	while(1) {
		osmo_select_main(0);
	}

	return ret;
}
