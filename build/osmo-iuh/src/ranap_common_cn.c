/* RANAP interface for a core-network node */

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

#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/ranap_common_cn.h>
#include <osmocom/ranap/ranap_ies_defs.h>

#include <osmocom/iuh/hnbgw.h>

static int cn_ranap_rx_initiating_msg_co(void *ctx, RANAP_InitiatingMessage_t *imsg,
					 ranap_message *message)
{
	int rc = 0;

	message->procedureCode = imsg->procedureCode;
	message->criticality = imsg->criticality;

	DEBUGP(DRANAP, "Rx CO IM (%s)\n",
		get_value_string(ranap_procedure_code_vals, imsg->procedureCode));

	switch (imsg->procedureCode) {
	case RANAP_ProcedureCode_id_InitialUE_Message:
		rc = ranap_decode_initialue_messageies(&message->msg.initialUE_MessageIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_DirectTransfer:
		rc = ranap_decode_directtransferies(&message->msg.directTransferIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_RAB_ReleaseRequest:
		/* RNC requests the release of RAB */
		rc = ranap_decode_rab_releaserequesties(&message->msg.raB_ReleaseRequestIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_Iu_ReleaseRequest:
		/* RNC requests the release of Iu */
		rc = ranap_decode_iu_releaserequesties(&message->msg.iu_ReleaseRequestIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_ErrorIndication:
		rc = ranap_decode_errorindicationies(&message->msg.errorIndicationIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_RAB_ModifyRequest:
		rc = ranap_decode_rab_modifyrequesties(&message->msg.raB_ModifyRequestIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_SecurityModeControl:
		/* FIXME this is not a message received by CN (used by hnb-test) */
		/* Only an RNC will receive a Security Mode Control as
		 * Initiating Message, in other words: only hnb-test. */
		rc = ranap_decode_securitymodecommandies(&message->msg.securityModeCommandIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_Iu_Release:
		/* FIXME this is not a message received by CN (used by hnb-test) */
		rc = ranap_decode_iu_releasecommandies(&message->msg.iu_ReleaseCommandIEs, &imsg->value);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "Procedure %s (CO, IM) from RNC, ignoring\n",
		     get_value_string(ranap_procedure_code_vals, imsg->procedureCode));
		rc = -1;
		break;
	}

	return rc;
}

static void cn_ranap_free_initiating_msg_co(ranap_message *message)
{
	switch (message->procedureCode) {
	case RANAP_ProcedureCode_id_InitialUE_Message:
		ranap_free_initialue_messageies(&message->msg.initialUE_MessageIEs);
		break;
	case RANAP_ProcedureCode_id_DirectTransfer:
		ranap_free_directtransferies(&message->msg.directTransferIEs);
		break;
	case RANAP_ProcedureCode_id_RAB_ReleaseRequest:
		/* RNC requests the release of RAB */
		ranap_free_rab_releaserequesties(&message->msg.raB_ReleaseRequestIEs);
		break;
	case RANAP_ProcedureCode_id_Iu_ReleaseRequest:
		/* RNC requests the release of Iu */
		ranap_free_iu_releaserequesties(&message->msg.iu_ReleaseRequestIEs);
		break;
	case RANAP_ProcedureCode_id_ErrorIndication:
		ranap_free_errorindicationies(&message->msg.errorIndicationIEs);
		break;
	case RANAP_ProcedureCode_id_RAB_ModifyRequest:
		ranap_free_rab_modifyrequesties(&message->msg.raB_ModifyRequestIEs);
		break;
	case RANAP_ProcedureCode_id_SecurityModeControl:
		/* FIXME this is not a message received by CN (used by hnb-test) */
		/* Only an RNC will receive a Security Mode Control as
		 * Initiating Message, in other words: only hnb-test. */
		ranap_free_securitymodecommandies(&message->msg.securityModeCommandIEs);
		break;
	case RANAP_ProcedureCode_id_Iu_Release:
		/* FIXME this is not a message received by CN (used by hnb-test) */
		ranap_free_iu_releasecommandies(&message->msg.iu_ReleaseCommandIEs);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Not freeing suspicious RANAP "
		     "Procedure %s (CO, IM) from RNC\n",
		     get_value_string(ranap_procedure_code_vals, message->procedureCode));
		break;
	}
}

static int cn_ranap_rx_successful_msg_co(void *ctx, RANAP_SuccessfulOutcome_t *imsg,
					 ranap_message *message)
{
	int rc = 0;

	message->procedureCode = imsg->procedureCode;
	message->criticality = imsg->criticality;

	DEBUGP(DRANAP, "Rx CO SO (%s)\n",
		get_value_string(ranap_procedure_code_vals, imsg->procedureCode));

	switch (imsg->procedureCode) {
	case RANAP_ProcedureCode_id_RAB_Assignment:
		/* RAB assignment response */
		rc = ranap_decode_rab_assignmentresponseies(&message->msg.raB_AssignmentResponseIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_SecurityModeControl:
		/* Security Mode Complete */
		rc = ranap_decode_securitymodecompleteies(&message->msg.securityModeCompleteIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_Iu_Release:
		/* Iu release Complete; confirmation of CN-initiated release */
		rc = ranap_decode_iu_releasecompleteies(&message->msg.iu_ReleaseCompleteIEs, &imsg->value);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "Procedure %s (SO) from RNC, ignoring\n",
		     get_value_string(ranap_procedure_code_vals, imsg->procedureCode));
		rc = -1;
		break;
	}

	return rc;
}

static void cn_ranap_free_successful_msg_co(ranap_message *message)
{
	switch (message->procedureCode) {
	case RANAP_ProcedureCode_id_RAB_Assignment:
		/* RAB assignment response */
		ranap_free_rab_assignmentresponseies(&message->msg.raB_AssignmentResponseIEs);
		break;
	case RANAP_ProcedureCode_id_SecurityModeControl:
		/* Security Mode Complete */
		ranap_free_securitymodecompleteies(&message->msg.securityModeCompleteIEs);
		break;
	case RANAP_ProcedureCode_id_Iu_Release:
		/* Iu release Complete; confirmation of CN-initiated release */
		ranap_free_iu_releasecompleteies(&message->msg.iu_ReleaseCompleteIEs);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Not freeing suspicious RANAP "
		     "Procedure %s (SO) from RNC\n",
		     get_value_string(ranap_procedure_code_vals, message->procedureCode));
		break;
	}
}

static int cn_ranap_rx_outcome_msg_co(void *ctx, RANAP_Outcome_t *imsg,
					ranap_message *message)
{
	int rc = 0;

	message->procedureCode = imsg->procedureCode;
	message->criticality = imsg->criticality;

	DEBUGP(DRANAP, "Rx CO O (%s)\n",
		get_value_string(ranap_procedure_code_vals, imsg->procedureCode));

	switch (imsg->procedureCode) {
	case RANAP_ProcedureCode_id_RAB_Assignment:
		/* RAB assignment response */
		rc = ranap_decode_rab_assignmentresponseies(&message->msg.raB_AssignmentResponseIEs, &imsg->value);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "Procedure %s (O) from RNC, ignoring\n",
		     get_value_string(ranap_procedure_code_vals, imsg->procedureCode));
		rc = -1;
		break;
	}

	return rc;
}

static void cn_ranap_free_outcome_msg_co(ranap_message *message)
{
	switch (message->procedureCode) {
	case RANAP_ProcedureCode_id_RAB_Assignment:
		/* RAB assignment response */
		ranap_free_rab_assignmentresponseies(&message->msg.raB_AssignmentResponseIEs);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Not freeing suspicious RANAP "
		     "Procedure %s (O) from RNC\n",
		     get_value_string(ranap_procedure_code_vals, message->procedureCode));
		break;
	}
}

static int _cn_ranap_rx_co(void *ctx, RANAP_RANAP_PDU_t *pdu, ranap_message *message)
{
	int rc = 0;

	switch (pdu->present) {
	case RANAP_RANAP_PDU_PR_initiatingMessage:
		rc = cn_ranap_rx_initiating_msg_co(ctx, &pdu->choice.initiatingMessage, message);
		break;
	case RANAP_RANAP_PDU_PR_successfulOutcome:
		rc = cn_ranap_rx_successful_msg_co(ctx, &pdu->choice.successfulOutcome, message);
		break;
	case RANAP_RANAP_PDU_PR_unsuccessfulOutcome:
		LOGP(DRANAP, LOGL_NOTICE, "Received unsupported RANAP "
		     "unsuccessful outcome procedure %s (CO) from RNC, ignoring\n",
		     get_value_string(ranap_procedure_code_vals,
			     	      pdu->choice.unsuccessfulOutcome.procedureCode));
		rc = -1;
		break;
	case RANAP_RANAP_PDU_PR_outcome:
		rc = cn_ranap_rx_outcome_msg_co(ctx, &pdu->choice.outcome, message);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "presence %s (CO) from RNC, ignoring\n",
		     get_value_string(ranap_presence_vals, pdu->present));
		rc = -1;
		break;
	}

	return rc;
}

static void _cn_ranap_free_co(ranap_message *message)
{
	switch (message->direction) {
	case RANAP_RANAP_PDU_PR_initiatingMessage:
		cn_ranap_free_initiating_msg_co(message);
		break;
	case RANAP_RANAP_PDU_PR_successfulOutcome:
		cn_ranap_free_successful_msg_co(message);
		break;
	case RANAP_RANAP_PDU_PR_unsuccessfulOutcome:
		LOGP(DRANAP, LOGL_NOTICE, "Not freeing unsupported RANAP "
		     "unsuccessful outcome procedure (CO) from RNC\n");
		break;
	case RANAP_RANAP_PDU_PR_outcome:
		cn_ranap_free_outcome_msg_co(message);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "presence %s (CO) from RNC, ignoring\n",
		     get_value_string(ranap_presence_vals, message->direction));
		break;
	}
}

/* receive a connection-oriented RANAP message and call
 * cn_ranap_handle_co() with the resulting ranap_message struct */
int ranap_cn_rx_co(ranap_handle_cb cb, void *ctx, uint8_t *data, size_t len)
{
	RANAP_RANAP_PDU_t *pdu = NULL;
	ranap_message message;
	asn_dec_rval_t dec_ret;
	int rc;

	memset(&message, 0, sizeof(message));

	dec_ret = aper_decode(NULL,&asn_DEF_RANAP_RANAP_PDU, (void **) &pdu,
			      data, len, 0, 0);
	if (dec_ret.code != RC_OK) {
		LOGP(DRANAP, LOGL_ERROR, "Error in RANAP ASN.1 decode\n");
		return -1;
	}

	message.direction = pdu->present;

	rc = _cn_ranap_rx_co(ctx, pdu, &message);

	if (rc == 0)
		(*cb)(ctx, &message);
	else
		LOGP(DRANAP, LOGL_ERROR, "Not calling cn_ranap_handle_co() due to rc=%d\n", rc);

	/* Free the asn1 structs in message */
	_cn_ranap_free_co(&message);

	ASN_STRUCT_FREE(asn_DEF_RANAP_RANAP_PDU, pdu);

	return rc;
}

static int cn_ranap_rx_initiating_msg_cl(void *ctx, RANAP_InitiatingMessage_t *imsg,
					 ranap_message *message)
{
	int rc;

	message->procedureCode = imsg->procedureCode;
	message->criticality = imsg->criticality;

	DEBUGP(DRANAP, "Rx CL IM (%s)\n",
		get_value_string(ranap_procedure_code_vals, imsg->procedureCode));

	switch (imsg->procedureCode) {
	case RANAP_ProcedureCode_id_Reset:
		/* Reset request */
		rc = ranap_decode_reseties(&message->msg.resetIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_OverloadControl: /* Overload ind */
		rc = ranap_decode_overloadies(&message->msg.overloadIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_ErrorIndication: /* Error ind */
		rc = ranap_decode_errorindicationies(&message->msg.errorIndicationIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_ResetResource: /* request */
		rc = ranap_decode_resetresourceies(&message->msg.resetResourceIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_InformationTransfer:
		rc = ranap_decode_informationtransferindicationies(&message->msg.informationTransferIndicationIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_DirectInformationTransfer:
		rc = ranap_decode_directinformationtransferies(&message->msg.directInformationTransferIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_UplinkInformationExchange:
		rc = ranap_decode_uplinkinformationexchangerequesties(&message->msg.uplinkInformationExchangeRequestIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_Paging:
		/* FIXME this is not a message received by CN (used by hnb-test) */
		rc = ranap_decode_pagingies(&message->msg.pagingIEs, &imsg->value);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "Procedure %s (CL, IM) from RNC, ignoring\n",
		     get_value_string(ranap_procedure_code_vals, imsg->procedureCode));
		break;
	}
}

static void cn_ranap_free_initiating_msg_cl(ranap_message *message)
{

	switch (message->procedureCode) {
	case RANAP_ProcedureCode_id_Reset:
		/* Reset request */
		ranap_free_reseties(&message->msg.resetIEs);
		break;
	case RANAP_ProcedureCode_id_OverloadControl: /* Overload ind */
		ranap_free_overloadies(&message->msg.overloadIEs);
		break;
	case RANAP_ProcedureCode_id_ErrorIndication: /* Error ind */
		ranap_free_errorindicationies(&message->msg.errorIndicationIEs);
		break;
	case RANAP_ProcedureCode_id_ResetResource: /* request */
		ranap_free_resetresourceies(&message->msg.resetResourceIEs);
		break;
	case RANAP_ProcedureCode_id_InformationTransfer:
		ranap_free_informationtransferindicationies(&message->msg.informationTransferIndicationIEs);
		break;
	case RANAP_ProcedureCode_id_DirectInformationTransfer:
		ranap_free_directinformationtransferies(&message->msg.directInformationTransferIEs);
		break;
	case RANAP_ProcedureCode_id_UplinkInformationExchange:
		ranap_free_uplinkinformationexchangerequesties(&message->msg.uplinkInformationExchangeRequestIEs);
		break;
	case RANAP_ProcedureCode_id_Paging:
		/* FIXME this is not a message received by CN (used by hnb-test) */
		ranap_free_pagingies(&message->msg.pagingIEs);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Not freeing suspicious RANAP "
		     "Procedure %s (CL, IM)\n",
		     get_value_string(ranap_procedure_code_vals, message->procedureCode));
		break;
	}
}

static int cn_ranap_rx_successful_msg_cl(void *ctx, RANAP_SuccessfulOutcome_t *imsg,
					 ranap_message *message)
{
	int rc;

	message->procedureCode = imsg->procedureCode;
	message->criticality = imsg->criticality;

	DEBUGP(DRANAP, "Rx CL SO (%s)\n",
		get_value_string(ranap_procedure_code_vals, imsg->procedureCode));

	switch (imsg->procedureCode) {
	case RANAP_ProcedureCode_id_Reset: /* Reset acknowledge */
		rc = ranap_decode_resetacknowledgeies(&message->msg.resetAcknowledgeIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_ResetResource: /* response */
		rc = ranap_decode_resetresourceacknowledgeies(&message->msg.resetResourceAcknowledgeIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_InformationTransfer:
		rc = ranap_decode_resetresourceacknowledgeies(&message->msg.resetResourceAcknowledgeIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_DirectInformationTransfer:
		rc = ranap_decode_informationtransferconfirmationies(&message->msg.informationTransferConfirmationIEs, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_UplinkInformationExchange:
		rc = ranap_decode_uplinkinformationexchangeresponseies(&message->msg.uplinkInformationExchangeResponseIEs, &imsg->value);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "Procedure %s (CL, SO) from RNC, ignoring\n",
		     get_value_string(ranap_procedure_code_vals, imsg->procedureCode));
		break;
	}
}

static void cn_ranap_free_successful_msg_cl(ranap_message *message)
{
	switch (message->procedureCode) {
	case RANAP_ProcedureCode_id_Reset: /* Reset acknowledge */
		ranap_free_resetacknowledgeies(&message->msg.resetAcknowledgeIEs);
		break;
	case RANAP_ProcedureCode_id_ResetResource: /* response */
		ranap_free_resetresourceacknowledgeies(&message->msg.resetResourceAcknowledgeIEs);
		break;
	case RANAP_ProcedureCode_id_InformationTransfer:
		ranap_free_resetresourceacknowledgeies(&message->msg.resetResourceAcknowledgeIEs);
		break;
	case RANAP_ProcedureCode_id_DirectInformationTransfer:
		ranap_free_informationtransferconfirmationies(&message->msg.informationTransferConfirmationIEs);
		break;
	case RANAP_ProcedureCode_id_UplinkInformationExchange:
		ranap_free_uplinkinformationexchangeresponseies(&message->msg.uplinkInformationExchangeResponseIEs);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Not freeing suspicious RANAP "
		     "Procedure %s (CL, SO)\n",
		     get_value_string(ranap_procedure_code_vals, message->procedureCode));
		break;
	}
}

static int _cn_ranap_rx_cl(void *ctx, RANAP_RANAP_PDU_t *pdu, ranap_message *message)
{
	int rc;

	/* Extend _cn_ranap_free_cl as well when extending this function */

	switch (pdu->present) {
	case RANAP_RANAP_PDU_PR_initiatingMessage:
		rc = cn_ranap_rx_initiating_msg_cl(ctx, &pdu->choice.initiatingMessage,
						   message);
		break;
	case RANAP_RANAP_PDU_PR_successfulOutcome:
		rc = cn_ranap_rx_successful_msg_cl(ctx, &pdu->choice.successfulOutcome,
						   message);
		break;
	case RANAP_RANAP_PDU_PR_unsuccessfulOutcome:
		LOGP(DRANAP, LOGL_NOTICE, "Received unsupported RANAP "
		     "unsuccessful outcome procedure %s (CL) from RNC, ignoring\n",
		     get_value_string(ranap_procedure_code_vals,
			     	      pdu->choice.unsuccessfulOutcome.procedureCode));
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "presence %s (CL) from RNC, ignoring\n",
		     get_value_string(ranap_presence_vals, pdu->present));
		break;
	}
}

static void _cn_ranap_free_cl(ranap_message *message)
{
	switch (message->direction) {
	case RANAP_RANAP_PDU_PR_initiatingMessage:
		cn_ranap_free_initiating_msg_cl(message);
		break;
	case RANAP_RANAP_PDU_PR_successfulOutcome:
		cn_ranap_free_successful_msg_cl(message);
		break;
	case RANAP_RANAP_PDU_PR_unsuccessfulOutcome:
		LOGP(DRANAP, LOGL_NOTICE, "Not freeing unsupported RANAP "
		     "unsuccessful outcome procedure from RNC\n");
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Suspicious RANAP "
		     "presence %s (CL) from RNC, ignoring\n", message->direction);
		break;
	}
}

/* receive a connection-less RANAP message and call
 * cn_ranap_handle_co() with the resulting ranap_message struct */
int ranap_cn_rx_cl(ranap_handle_cb cb, void *ctx, uint8_t *data, size_t len)
{
	RANAP_RANAP_PDU_t *pdu = NULL;
	ranap_message message;
	asn_dec_rval_t dec_ret;
	int rc;

	memset(&message, 0, sizeof(message));

	dec_ret = aper_decode(NULL,&asn_DEF_RANAP_RANAP_PDU, (void **) &pdu,
			      data, len, 0, 0);
	if (dec_ret.code != RC_OK) {
		LOGP(DRANAP, LOGL_ERROR, "Error in RANAP ASN.1 decode\n");
		return -1;
	}

	message.direction = pdu->present;

	rc = _cn_ranap_rx_cl(ctx, pdu, &message);

	if (rc == 0)
		(*cb)(ctx, &message);
	else
		LOGP(DRANAP, LOGL_ERROR, "Not calling cn_ranap_handle_cl() due to rc=%d\n", rc);

	/* Free the asn1 structs in message */
	_cn_ranap_free_cl(&message);

	ASN_STRUCT_FREE(asn_DEF_RANAP_RANAP_PDU, pdu);

	return rc;
}
