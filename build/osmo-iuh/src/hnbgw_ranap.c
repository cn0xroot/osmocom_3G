/* hnb-gw specific code for RANAP */

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



#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "asn1helpers.h"

#include <osmocom/iuh/hnbgw.h>
#include <osmocom/iuh/hnbgw_rua.h>
#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>

static int ranap_tx_reset_ack(struct hnb_context *hnb,
				RANAP_CN_DomainIndicator_t domain)
{
	struct msgb *msg;
	int rc;

	msg = ranap_new_msg_reset_ack(domain, NULL);
	if (!msg)
		return -1;

	rc = rua_tx_udt(hnb, msg->data, msgb_length(msg));

	msgb_free(msg);

	return rc;
}

static int ranap_rx_init_reset(struct hnb_context *hnb, ANY_t *in)
{
	RANAP_ResetIEs_t ies;
	int rc, is_ps = 0;

	rc = ranap_decode_reseties(&ies, in);
	if (rc < 0)
		return rc;

	if (ies.cN_DomainIndicator == RANAP_CN_DomainIndicator_ps_domain)
		is_ps=1;

	LOGP(DRANAP, LOGL_INFO, "Rx RESET.req(%s,%s)\n", is_ps ? "ps" : "cs",
		ranap_cause_str(&ies.cause));

	/* FIXME: Actually we have to wait for some guard time? */
	/* FIXME: Reset all resources related to this HNB/RNC */
	ranap_tx_reset_ack(hnb, ies.cN_DomainIndicator);

	return 0;
}

static int ranap_rx_error_ind(struct hnb_context *hnb, ANY_t *in)
{
	RANAP_ErrorIndicationIEs_t ies;
	int rc, is_ps = 0;

	rc = ranap_decode_errorindicationies(&ies, in);
	if (rc < 0)
		return rc;

	if (ies.presenceMask & ERRORINDICATIONIES_RANAP_CAUSE_PRESENT) {
		LOGP(DRANAP, LOGL_ERROR, "Rx ERROR.ind(%s)\n",
			ranap_cause_str(&ies.cause));
	} else
		LOGP(DRANAP, LOGL_ERROR, "Rx ERROR.ind\n");

	return 0;
}

static int ranap_rx_dt(struct hnb_context *hnb, ANY_t *in)
{
	RANAP_DirectTransferIEs_t ies;
	int sapi = 0;
	int rc;

	rc = ranap_decode_directtransferies(&ies, in);
	if (rc < 0)
		return rc;

	if (ies.presenceMask & DIRECTTRANSFERIES_RANAP_SAPI_PRESENT)
		sapi = ies.sapi;

	if (ies.presenceMask & DIRECTTRANSFERIES_RANAP_LAI_PRESENT) {
		/* FIXME: Update LAI associated with UE */
	}

	if (ies.presenceMask & DIRECTTRANSFERIES_RANAP_RAC_PRESENT) {
		/* FIXME: Update RAC associated with UE */
	}

	DEBUGP(DRANAP, "DirectTransfer: %s\n",
		osmo_hexdump(ies.nas_pdu.buf, ies.nas_pdu.size));
	/* FIXME: hand NAS PDU into MSC */
}

static int ranap_rx_initiating_msg(struct hnb_context *hnb, RANAP_InitiatingMessage_t *imsg)
{
	int rc;

	/* according tot the spec, we can primarily receive Overload,
	 * Reset, Reset ACK, Error Indication, reset Resource, Reset
	 * Resurce Acknowledge as connecitonless RANAP.  There are some
	 * more messages regarding Information Transfer, Direct
	 * Information Transfer and Uplink Information Trnansfer that we
	 * can ignore.  In either case, it is RANAP that we need to
	 * decode... */
	switch (imsg->procedureCode) {
	case RANAP_ProcedureCode_id_Reset:
		/* Reset request */
		rc = ranap_rx_init_reset(hnb, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_OverloadControl: /* Overload ind */
		break;
	case RANAP_ProcedureCode_id_ErrorIndication: /* Error ind */
		rc = ranap_rx_error_ind(hnb, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_ResetResource: /* request */
	case RANAP_ProcedureCode_id_InformationTransfer:
	case RANAP_ProcedureCode_id_DirectInformationTransfer:
	case RANAP_ProcedureCode_id_UplinkInformationExchange:
		LOGP(DRANAP, LOGL_NOTICE, "Received unsupported RANAP "
		     "Procedure %u from HNB, ignoring\n", imsg->procedureCode);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "Procedure %u from HNB, ignoring\n", imsg->procedureCode);
		break;
	}
}

static int ranap_rx_successful_msg(struct hnb_context *hnb, RANAP_SuccessfulOutcome_t *imsg)
{
	int rc;

	/* according tot the spec, we can primarily receive Overload,
	 * Reset, Reset ACK, Error Indication, reset Resource, Reset
	 * Resurce Acknowledge as connecitonless RANAP.  There are some
	 * more messages regarding Information Transfer, Direct
	 * Information Transfer and Uplink Information Trnansfer that we
	 * can ignore.  In either case, it is RANAP that we need to
	 * decode... */
	switch (imsg->procedureCode) {
	case RANAP_ProcedureCode_id_Reset: /* Reset acknowledge */
		break;
	case RANAP_ProcedureCode_id_ResetResource: /* response */
	case RANAP_ProcedureCode_id_InformationTransfer:
	case RANAP_ProcedureCode_id_DirectInformationTransfer:
	case RANAP_ProcedureCode_id_UplinkInformationExchange:
		LOGP(DRANAP, LOGL_NOTICE, "Received unsupported RANAP "
		     "Procedure %u from HNB, ignoring\n", imsg->procedureCode);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "Procedure %u from HNB, ignoring\n", imsg->procedureCode);
		break;
	}
}



static int _hnbgw_ranap_rx(struct hnb_context *hnb, RANAP_RANAP_PDU_t *pdu)
{
	int rc;

	switch (pdu->present) {
	case RANAP_RANAP_PDU_PR_initiatingMessage:
		rc = ranap_rx_initiating_msg(hnb, &pdu->choice.initiatingMessage);
		break;
	case RANAP_RANAP_PDU_PR_successfulOutcome:
		rc = ranap_rx_successful_msg(hnb, &pdu->choice.successfulOutcome);
		break;
	case RANAP_RANAP_PDU_PR_unsuccessfulOutcome:
		LOGP(DRANAP, LOGL_NOTICE, "Received unsupported RANAP "
		     "unsuccessful outcome procedure %u from HNB, ignoring\n",
		     pdu->choice.unsuccessfulOutcome.procedureCode);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "presence %u from HNB, ignoring\n", pdu->present);
		break;
	}
}


int hnbgw_ranap_rx(struct msgb *msg, uint8_t *data, size_t len)
{
	RANAP_RANAP_PDU_t _pdu, *pdu = &_pdu;
	asn_dec_rval_t dec_ret;
	int rc;

	memset(pdu, 0, sizeof(*pdu));
	dec_ret = aper_decode(NULL,&asn_DEF_RANAP_RANAP_PDU, (void **) &pdu,
			      data, len, 0, 0);
	if (dec_ret.code != RC_OK) {
		LOGP(DRANAP, LOGL_ERROR, "Error in RANAP ASN.1 decode\n");
		return -1;
	}

	rc = _hnbgw_ranap_rx(msg->dst, pdu);

	return rc;
}

int hnbgw_ranap_init(void)
{

}
