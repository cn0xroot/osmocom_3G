/* Test de-/encoding of HBNAP messages */

/* (C) 2015 by Daniel Willmann <dwillmann@sysmocom.de>
 * (C) 2015 by sysmocom s.f.m.c GmbH
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

#include <osmocom/ranap/iu_helpers.h>
#include "asn1helpers.h"

#include <osmocom/hnbap/hnbap_common.h>
#include <osmocom/hnbap/hnbap_ies_defs.h>
#include "test_common.h"

#include <assert.h>
#define ASSERT(x)	assert(x)

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

static const unsigned char hnbap_reg_req[] = {
0x00, 0x01,
0x00, 0x57, 0x00, 0x00, 0x07, 0x00, 0x03, 0x00,
0x15, 0x04, 0x80, 0x31, 0x30, 0x30, 0x30, 0x35,
0x42, 0x39, 0x2d, 0x30, 0x30, 0x31, 0x30, 0x39,
0x34, 0x32, 0x30, 0x35, 0x30, 0x40, 0x00, 0x08,
0x00, 0x17, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00,
0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x11, 0x00, 0x05, 0x00, 0xc0, 0xa8, 0x00,
0x32, 0x00, 0x09, 0x00, 0x03, 0x09, 0xf1, 0x99,
0x00, 0x0b, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
0x00, 0x06, 0x00, 0x02, 0x40, 0x20, 0x00, 0x07,
0x00, 0x01, 0x64, 0x00, 0x0a, 0x00, 0x02, 0x00,
0x01
};

static const unsigned char hnbap_reg_acc[] = {
0x20, 0x01,
0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x0e, 0x00,
0x02, 0x00, 0x00
};

static const unsigned char hnbap_ue_reg_req[] = {
0x00, 0x03,
0x00, 0x1a, 0x00, 0x00, 0x03, 0x00, 0x05, 0x00,
0x09, 0x0a, 0x62, 0x02, 0x11, 0x32, 0x54, 0x76,
0x98, 0xf0, 0x00, 0x0c, 0x40, 0x01, 0x40, 0x00,
0x0d, 0x00, 0x01, 0x0d
};

static const unsigned char hnbap_ue_reg_acc[] = {
0x20, 0x03,
0x00, 0x17, 0x00, 0x00, 0x02, 0x00, 0x05, 0x00,
0x09, 0x0a, 0x62, 0x02, 0x11, 0x32, 0x54, 0x76,
0x98, 0xf0, 0x00, 0x04, 0x00, 0x03, 0x17, 0x00,
0x00
};

void test_asn1_decoding(void)
{
	int rc;

	HNBAP_PDU_t _pdu, *pdu = &_pdu;
	InitiatingMessage_t *im;
	SuccessfulOutcome_t *so;
	UERegisterRequestIEs_t ue_req_ies;
	UERegisterAcceptIEs_t ue_acc_ies;
	HNBRegisterRequestIEs_t hnb_ies;

	char imsi[16];

	asn_dec_rval_t dec_ret;

	memset(pdu, 0, sizeof(*pdu));
	printf("Testing asn.1 HNBAP decoding\n");

	dec_ret = aper_decode(NULL, &asn_DEF_HNBAP_PDU, (void **) &pdu,
			hnbap_reg_req, sizeof(hnbap_reg_req), 0, 0);


	ASSERT(dec_ret.code == RC_OK);
	ASSERT(pdu->present == HNBAP_PDU_PR_initiatingMessage);

	im = &pdu->choice.initiatingMessage;

	ASSERT(im->procedureCode == ProcedureCode_id_HNBRegister);

	rc = hnbap_decode_hnbregisterrequesties(&hnb_ies, &im->value);
	ASSERT(rc >= 0);

	uint16_t lac, sac;
	uint8_t rac;
	uint32_t cid;

	lac = asn1str_to_u16(&hnb_ies.lac);
	sac = asn1str_to_u16(&hnb_ies.sac);
	rac = asn1str_to_u8(&hnb_ies.rac);
	cid = asn1bitstr_to_u32(&hnb_ies.cellIdentity);

	ASSERT(lac == 0x4020);
	ASSERT(sac == 0x0001);
	ASSERT(rac == 0x64);
	ASSERT(cid == 0x0000000);

	ASSERT(!strcmp((char *) hnb_ies.hnB_Identity.hNB_Identity_Info.buf, "10005B9-0010942050@"));

	printf("HNBAP register request for HNB %s\n", (char *) hnb_ies.hnB_Identity.hNB_Identity_Info.buf);
	hnbap_free_hnbregisterrequesties(&hnb_ies);

	dec_ret = aper_decode(NULL, &asn_DEF_HNBAP_PDU, (void **) &pdu,
			hnbap_ue_reg_req, sizeof(hnbap_ue_reg_req), 0, 0);


	ASSERT(dec_ret.code == RC_OK);
	ASSERT(pdu->present == HNBAP_PDU_PR_initiatingMessage);

	im = &pdu->choice.initiatingMessage;
	ASSERT(im->procedureCode == ProcedureCode_id_UERegister);

	rc = hnbap_decode_ueregisterrequesties(&ue_req_ies, &im->value);
	ASSERT(rc >= 0);

	ASSERT(ue_req_ies.uE_Identity.present == UE_Identity_PR_iMSI);
	ranap_bcd_decode(imsi, sizeof(imsi), ue_req_ies.uE_Identity.choice.iMSI.buf,
			ue_req_ies.uE_Identity.choice.iMSI.size);

	printf("HNBAP UE Register request from IMSI %s\n", imsi);
	hnbap_free_ueregisterrequesties(&ue_req_ies);

	memset(pdu, 0, sizeof(*pdu));
	dec_ret = aper_decode(NULL, &asn_DEF_HNBAP_PDU, (void **) &pdu,
			hnbap_ue_reg_acc, sizeof(hnbap_ue_reg_acc), 0, 0);


	ASSERT(dec_ret.code == RC_OK);
	ASSERT(pdu->present == HNBAP_PDU_PR_successfulOutcome);

	so = &pdu->choice.successfulOutcome;
	ASSERT(so->procedureCode == ProcedureCode_id_UERegister);

	rc = hnbap_decode_ueregisteraccepties(&ue_acc_ies, &so->value);
	ASSERT(rc >= 0);

	ASSERT(ue_acc_ies.uE_Identity.present == UE_Identity_PR_iMSI);
	ranap_bcd_decode(imsi, sizeof(imsi), ue_acc_ies.uE_Identity.choice.iMSI.buf,
			ue_acc_ies.uE_Identity.choice.iMSI.size);

	printf("HNBAP UE Register accept to IMSI %s\n", imsi);
	hnbap_free_ueregisteraccepties(&ue_acc_ies);

}

int main(int argc, char **argv)
{
	int rc;

	test_common_init();
	log_set_log_level(osmo_stderr_target, LOGL_INFO);


	test_asn1_decoding();

	return 0;
}

