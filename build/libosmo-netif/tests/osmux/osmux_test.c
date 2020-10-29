/*
 * (C) 2013 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2013 by On Waves ehf <http://www.on-waves.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define OSMUX_TEST_USE_TIMING 0

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#if OSMUX_TEST_USE_TIMING
#include <sys/time.h>
#endif

#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/netif/osmux.h>
#include <osmocom/netif/rtp.h>

#define DOSMUX_TEST 0

struct log_info_cat osmux_test_cat[] = {
	[DOSMUX_TEST] = {
		.name = "DOSMUX_TEST",
		.description = "osmux test",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

const struct log_info osmux_test_log_info = {
	.filter_fn = NULL,
	.cat = osmux_test_cat,
	.num_cat = ARRAY_SIZE(osmux_test_cat),
};

/* RTP packet with AMR payload */
static uint8_t rtp_pkt[] = {
	0x80, 0x62, 0x3f, 0xcc, 0x00, 0x01, 0xa7, 0x6f, /* RTP */
	0x07, 0x09, 0x00, 0x62, 0x20, 0x14, 0xff, 0xd4, /* AMR */
	0xf9, 0xff, 0xfb, 0xe7, 0xeb, 0xf9, 0x9f, 0xf8,
	0xf2, 0x26, 0x33, 0x65, 0x54,
};

#define PKT_TIME_USEC 20*1000

static int rtp_pkts;
static int mark_pkts;
#if OSMUX_TEST_USE_TIMING
static struct timeval last;
#endif

static void tx_cb(struct msgb *msg, void *data)
{
	char buf[4096];
	struct rtp_hdr *rtph = (struct rtp_hdr *)msg->data;
#if OSMUX_TEST_USE_TIMING
	struct timeval now, diff;

	osmo_gettimeofday(&now, NULL);
	timersub(&now, &last, &diff);
	last = now;

	if (diff.tv_usec > 2*17000) {
		fprintf(stdout, "delivery of reconstructed RTP lagged"
			" (diff.tv_usec=%u > 2*17000)\n",
			(unsigned int)diff.tv_usec);
		exit(EXIT_FAILURE);
	}
#endif

	osmo_rtp_snprintf(buf, sizeof(buf), msg);
	fprintf(stderr, "extracted packet: %s\n", buf);

	if (memcmp(msg->data + sizeof(struct rtp_hdr),
		   rtp_pkt + sizeof(struct rtp_hdr),
		   sizeof(rtp_pkt) - sizeof(struct rtp_hdr)) != 0) {
		fprintf(stdout, "payload mismatch!\n");
		exit(EXIT_FAILURE);
	}

	if (rtph->marker)
		mark_pkts--;
	rtp_pkts--;
	msgb_free(msg);
}

static struct osmux_out_handle h_output;

static void osmux_deliver(struct msgb *batch_msg, void *data)
{
	char buf[1024];
	struct osmux_hdr *osmuxh;
	LLIST_HEAD(list);

	osmux_snprintf(buf, sizeof(buf), batch_msg);
	fprintf(stderr, "OSMUX message (len=%d) %s\n", batch_msg->len, buf);

	/* For each OSMUX message, extract the RTP messages and put them
	 * in a list. Then, reconstruct transmission timing.
	 */
	while((osmuxh = osmux_xfrm_output_pull(batch_msg)) != NULL) {
		osmux_xfrm_output(osmuxh, &h_output, &list);
		osmux_tx_sched(&list, tx_cb, NULL);
	}
	msgb_free(batch_msg);
}

struct osmux_in_handle h_input = {
	.osmux_seq	= 0, /* sequence number to start OSmux message from */
	.batch_factor	= 4, /* batch up to 4 RTP messages */
	.deliver	= osmux_deliver,
};

static void sigalarm_handler(int foo)
{
	printf("FAIL: test did not run successfully\n");
	exit(EXIT_FAILURE);
}

static void osmux_test_marker(int ccid) {
	struct msgb *msg;
	struct rtp_hdr *rtph = (struct rtp_hdr *)rtp_pkt;
	struct rtp_hdr *cpy_rtph;
	uint16_t seq;
	int i, j;

	for (i = 0; i < 64; i++) {

		seq = ntohs(rtph->sequence);
		seq++;
		rtph->sequence = htons(seq);

		for (j=0; j<4; j++) {
			msg = msgb_alloc(1500, "test");
			if (!msg)
				exit(EXIT_FAILURE);

			memcpy(msg->data, rtp_pkt, sizeof(rtp_pkt));
			cpy_rtph = (struct rtp_hdr *) msgb_put(msg, sizeof(rtp_pkt));

			if ((i+j) % 7 == 0) {
				cpy_rtph->marker = 1;
				mark_pkts++;
			}

			rtp_pkts++;
			while (osmux_xfrm_input(&h_input, msg, j + ccid) > 0) {
				osmux_xfrm_input_deliver(&h_input);
			}
		}
#if !OSMUX_TEST_USE_TIMING
		osmo_gettimeofday_override_add(0, PKT_TIME_USEC);
#endif
	}

	while (rtp_pkts) {
#if !OSMUX_TEST_USE_TIMING
		osmo_gettimeofday_override_add(1, 0);
#endif
		osmo_select_main(0);
	}

	if (mark_pkts) {
		fprintf(stdout, "RTP M bit (marker) mismatch! %d\n", mark_pkts);
		exit(EXIT_FAILURE);
	}
}

static void osmux_test_loop(int ccid)
{
	struct msgb *msg;
	char buf[1024];
	struct rtp_hdr *rtph = (struct rtp_hdr *)rtp_pkt;
	uint16_t seq;
	int i, j, k = 0;

	for (i = 1; i < 65; i++) {
		msg = msgb_alloc(1500, "test");
		if (!msg)
			exit(EXIT_FAILURE);

		memcpy(msg->data, rtp_pkt, sizeof(rtp_pkt));
		msgb_put(msg, sizeof(rtp_pkt));

		seq = ntohs(rtph->sequence);
		seq++;
		rtph->sequence = htons(seq);

		osmo_rtp_snprintf(buf, sizeof(buf), msg);
		fprintf(stderr, "adding to ccid=%u %s\n", (i % 2) + ccid, buf);
		rtp_pkts++;

		k++;
		/* Fan out RTP packets between two circuit IDs to test
		 * multi-batch support. Mind that this approach implicitly add
		 * gaps between two messages to test the osmux replaying
		 * feature.
		 */
		osmux_xfrm_input(&h_input, msg, (i % 2) + ccid);

		if (i % 4 == 0) {
#if OSMUX_TEST_USE_TIMING
			osmo_gettimeofday(&last, NULL);
#endif

			/* After four RTP messages, squash them into the OSMUX
			 * batch and call the routine to deliver it.
			 */
			osmux_xfrm_input_deliver(&h_input);

			/* The first two RTP message (one per circuit ID batch)
			 * are delivered immediately, wait until the three RTP
			 * messages that are extracted from OSMUX has been
			 * delivered.
			 */
			for (j = 0; j < k-2; j++) {
				osmo_select_main(0);
#if !OSMUX_TEST_USE_TIMING
				osmo_gettimeofday_override_add(0, PKT_TIME_USEC);
#endif
			}

			k = 0;
		}
	}

	if (mark_pkts) {
		fprintf(stdout, "RTP M bit (marker) mismatch! %d\n", mark_pkts);
		exit(EXIT_FAILURE);
	}
}

int main(void)
{
	int i;

	if (signal(SIGALRM, sigalarm_handler) == SIG_ERR) {
		perror("signal");
		exit(EXIT_FAILURE);
	}

#if !OSMUX_TEST_USE_TIMING
	/* This test uses fake time to speedup the run, unless we want to manually
	 * test time specific stuff */
	osmo_gettimeofday_override = true;
#endif

	/* This test doesn't use it, but osmux requires it internally. */
	osmo_init_logging(&osmux_test_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);

	osmux_xfrm_output_init(&h_output, 0x7000000);

	/* If the test takes longer than 10 seconds, abort it */
	alarm(10);

#if !OSMUX_TEST_USE_TIMING
	/* Check if marker bit features work correctly */
	osmux_xfrm_input_init(&h_input);
	for (i = 0; i < 4; i++)
		osmux_xfrm_input_open_circuit(&h_input, i, 0);
	osmux_test_marker(0);
	for (i = 0; i < 4; i++)
		osmux_xfrm_input_close_circuit(&h_input, i);
	osmux_xfrm_input_fini(&h_input);
#endif

	osmux_xfrm_input_init(&h_input);

	for (i = 0; i < 2; i++)
		osmux_xfrm_input_open_circuit(&h_input, i, 0);

	/* Add two circuits with dummy padding */
	osmux_xfrm_input_open_circuit(&h_input, 2, 1);
	osmux_xfrm_input_open_circuit(&h_input, 3, 1);

	/* Wait 10 times to make sure dummy padding timer works fine */
	for (i = 0; i < 10; i++)
		osmo_select_main(0);

	/* Start pushing voice data to circuits 0 and 1 */
	osmux_test_loop(0);
	/* ... now start pushing voice data to circuits 2 and 3. This circuits
	 * comes with dummy padding enabled.
	 */
	osmux_test_loop(2);

	for (i = 0; i < 4; i++)
		osmux_xfrm_input_close_circuit(&h_input, i);

	/* Reopen with two circuits and retest */
	osmux_xfrm_input_open_circuit(&h_input, 0, 0);
	osmux_xfrm_input_open_circuit(&h_input, 1, 1);
	osmux_test_loop(0);
	osmux_xfrm_input_close_circuit(&h_input, 0);
	osmux_xfrm_input_close_circuit(&h_input, 1);

	osmux_xfrm_input_fini(&h_input);

	fprintf(stdout, "OK: Test passed\n");
	return EXIT_SUCCESS;
}
