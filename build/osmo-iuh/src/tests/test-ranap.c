/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/vty/logging.h>

#include "asn1helpers.h"
#include <osmocom/ranap/iu_helpers.h>

#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>
#include <osmocom/ranap/RANAP_MaxBitrate.h>
#include <osmocom/ranap/RANAP_CauseMisc.h>

#include "test_common.h"

#include <osmocom/iuh/hnbgw.h>

int asn1_xer_print = 1;

extern void *tall_msgb_ctx;

static void test_aper_int(uint32_t inp)
{
	RANAP_MaxBitrate_t mbr = inp;
	asn_enc_rval_t rv;
	uint8_t buf[32];

	memset(buf, 0, sizeof(buf));

	rv = aper_encode_to_buffer(&asn_DEF_RANAP_MaxBitrate, &mbr, buf, sizeof(buf));
	if (rv.encoded == -1) {
		fprintf(stderr, "Failed\n");
		return;
	}
	printf("Encoded MaxBitRate %u to %s\n", mbr, osmo_hexdump(buf, rv.encoded/8));
}

static void test_aper_causemisc(uint32_t inp, uint8_t exp_enc)
{
	RANAP_Cause_t c = { .present = RANAP_Cause_PR_misc, .choice.misc = inp };
	RANAP_Cause_t *c_dec = NULL;
	asn_enc_rval_t rv;
	uint8_t buf[32];

	memset(buf, 0, sizeof(buf));

	rv = aper_encode_to_buffer(&asn_DEF_RANAP_Cause, &c, buf, sizeof(buf));
	if (rv.encoded == -1) {
		fprintf(stderr, "Failed\n");
		return;
	}
	/* test encoding */
	printf("Encoded Cause Misc=%u to %s\n", inp, osmo_hexdump(buf, rv.encoded/8));
	OSMO_ASSERT(buf[0] == exp_enc);
	OSMO_ASSERT(rv.encoded == 8);

	/* test re-decoding */
	aper_decode(NULL, &asn_DEF_RANAP_Cause, &c_dec, buf, 1, 0, 0);
	printf("Decoded Cause Misc=%u\n", c_dec->choice.misc);
	OSMO_ASSERT(c_dec->present == RANAP_Cause_PR_misc);
	OSMO_ASSERT(c_dec->choice.misc == inp);
	ASN_STRUCT_FREE(asn_DEF_RANAP_Cause, c_dec);
}

int main(int argc, char **argv)
{
	uint8_t nas_buf[] = { 0xaa, 0xbb, 0xcc };
	struct msgb *msg;
	const char *imsi = "901700123456789";
	uint32_t tmsi = 0x01234567;
	uint32_t rtp_ip = 0x0a0b0c0d;
	uint16_t rtp_port = 2342;
	uint32_t gtp_ip = 0x1a1b1c1d;
	uint32_t gtp_tei = 0x11223344;
	uint8_t ik[16] = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
	uint8_t ck[16] = { 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2 };
	int i, rc;

	//asn_debug = 1;

	test_common_init();

	test_aper_int(1);
	test_aper_int(2);
	test_aper_int(3);
	test_aper_int(255);
	test_aper_int(256);
	test_aper_int(257);
	test_aper_int(64000);
	test_aper_int(0xffff);
	test_aper_int(0xffff+1);
	test_aper_int(0xffff+2);
	test_aper_int(16000000);
	test_aper_causemisc(RANAP_CauseMisc_unspecified_failure, 0x42);

	for (i = 0; i < 1; i++) {
		printf("\n==> DIRECT TRANSFER\n");
		msg = ranap_new_msg_dt(0, nas_buf, sizeof(nas_buf));
		if (msg)
			printf("%s\n", msgb_hexdump(msg));
		msgb_free(msg);

		printf("\n==> SECURITY MODE COMMAND\n");
		msg = ranap_new_msg_sec_mod_cmd(ik, ck, RANAP_KeyStatus_new);
		if (msg)
			printf("%s\n", msgb_hexdump(msg));
		msgb_free(msg);

		printf("\n==> COMMON ID\n");
		msg = ranap_new_msg_common_id(imsi);
		if (msg)
			printf("%s\n", msgb_hexdump(msg));
		msgb_free(msg);

		printf("\n==> IU RELEASE CMD\n");
		RANAP_Cause_t cause = { .present = RANAP_Cause_PR_radioNetwork,
					.choice.radioNetwork = RANAP_CauseRadioNetwork_radio_connection_with_UE_Lost };
		msg = ranap_new_msg_iu_rel_cmd(&cause);
		if (msg)
			printf("%s\n", msgb_hexdump(msg));
		msgb_free(msg);

		printf("\n==> PAGING CMD\n");
		msg = ranap_new_msg_paging_cmd(imsi, &tmsi, 0, RANAP_PagingCause_terminating_conversational_call);
		if (msg)
			printf("%s\n", msgb_hexdump(msg));
		msgb_free(msg);

		printf("\n==> RAB ASSIGNMENT COMMAND (VOICE)\n");
		msg = ranap_new_msg_rab_assign_voice(1, rtp_ip, rtp_port, 1);
		if (msg)
			printf("%s\n", msgb_hexdump(msg));
		msgb_free(msg);

		printf("\n==> RAB ASSIGNMENT COMMAND (DATA)\n");
		msg = ranap_new_msg_rab_assign_data(2, gtp_ip, gtp_tei, 1);
		if (msg)
			printf("%s\n", msgb_hexdump(msg));
		msgb_free(msg);

		printf("\n==> RESET CMD\n");
		msg = ranap_new_msg_reset(RANAP_CN_DomainIndicator_cs_domain, &cause);
		if (msg)
			printf("%s\n", msgb_hexdump(msg));
		msgb_free(msg);

		printf("\n==> RESET ACK\n");
		uint8_t plmn_id[] = { 0x09, 0x01, 0x99 };
		RANAP_GlobalRNC_ID_t rnc_id;
		rnc_id.pLMNidentity.buf = plmn_id;
		rnc_id.pLMNidentity.size = sizeof(plmn_id);
		rnc_id.rNC_ID = 2342;
		msg = ranap_new_msg_reset_ack(RANAP_CN_DomainIndicator_cs_domain, &rnc_id);
		if (msg)
			printf("%s\n", msgb_hexdump(msg));
		msgb_free(msg);

		printf("\n==> INITIAL UE\n");
		msg = ranap_new_msg_initial_ue(23, 0, &rnc_id, nas_buf, sizeof(nas_buf));
		if (msg)
			printf("%s\n", msgb_hexdump(msg));
		msgb_free(msg);

		printf("\n==> IU RELEASE REQ\n");
		msg = ranap_new_msg_iu_rel_req(&cause);
		if (msg)
			printf("%s\n", msgb_hexdump(msg));
		msgb_free(msg);

		printf("\n==> RAB RELEASE REQ\n");
		msg = ranap_new_msg_rab_rel_req(23, &cause);
		if (msg)
			printf("%s\n", msgb_hexdump(msg));
		msgb_free(msg);
	}

	printf("report\n");
	talloc_report(talloc_asn1_ctx, stdout);
	talloc_report(tall_msgb_ctx, stdout);
	//talloc_report(NULL, stdout);
	printf("exit\n");
	exit(0);
}
