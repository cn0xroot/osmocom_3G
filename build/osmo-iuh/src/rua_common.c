/* common RUA (RANAP User Adaption) Code */

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


#include <stdint.h>

#include <osmocom/core/msgb.h>

#include <osmocom/rua/rua_common.h>
#include <osmocom/iuh/hnbgw.h>

extern int asn1_xer_print;

static const struct value_string rua_cause_radio_vals[] = {
	{ RUA_CauseRadioNetwork_normal,		 "normal" },
	{ RUA_CauseRadioNetwork_connect_failed,	 "connect failed" },
	{ RUA_CauseRadioNetwork_network_release, "network release" },
	{ RUA_CauseRadioNetwork_unspecified,	 "unspecified" },
	{ 0, NULL }
};

static const struct value_string rua_cause_transp_vals[] = {
	{ RUA_CauseTransport_transport_resource_unavailable, "resource unavailable" },
	{ RUA_CauseTransport_unspecified, "unspecified" },
	{ 0, NULL }
};

static const struct value_string rua_cause_prot_vals[] = {
	{ RUA_CauseProtocol_transfer_syntax_error, "syntax error" },
	{ RUA_CauseProtocol_abstract_syntax_error_reject,
		"abstract syntax error; reject" },
	{ RUA_CauseProtocol_abstract_syntax_error_ignore_and_notify,
		"abstract syntax error; ignore and notify" },
	{ RUA_CauseProtocol_message_not_compatible_with_receiver_state,
		"message not compatible with receiver state" },
	{ RUA_CauseProtocol_semantic_error, "semantic error" },
	{ RUA_CauseProtocol_unspecified, "unspecified" },
	{ RUA_CauseProtocol_abstract_syntax_error_falsely_constructed_message,
		"falsely constructed message" },
	{ 0, NULL }
};

static const struct value_string rua_cause_misc_vals[] = {
	{ RUA_CauseMisc_processing_overload,	"processing overload" },
	{ RUA_CauseMisc_hardware_failure,	"hardware failure" },
	{ RUA_CauseMisc_o_and_m_intervention,	"OAM intervention" },
	{ RUA_CauseMisc_unspecified, 		"unspecified" },
	{ 0, NULL }
};

char *rua_cause_str(RUA_Cause_t *cause)
{
	static char buf[32];

	switch (cause->present) {
	case RUA_Cause_PR_radioNetwork:
		snprintf(buf, sizeof(buf), "radio(%s)",
			 get_value_string(rua_cause_radio_vals,
					 cause->choice.radioNetwork));
		break;
	case RUA_Cause_PR_transport:
		snprintf(buf, sizeof(buf), "transport(%s)",
			get_value_string(rua_cause_transp_vals,
					cause->choice.transport));
		break;
	case RUA_Cause_PR_protocol:
		snprintf(buf, sizeof(buf), "protocol(%s)",
			get_value_string(rua_cause_prot_vals,
					cause->choice.protocol));
		break;
	case RUA_Cause_PR_misc:
		snprintf(buf, sizeof(buf), "misc(%s)",
			get_value_string(rua_cause_misc_vals,
					cause->choice.misc));
		break;
	default:
		strcpy(buf, "unknown");
		break;
	}
	return buf;
}


static struct msgb *rua_msgb_alloc(void)
{
	return msgb_alloc(1024, "RUA Tx");
}

static struct msgb *_rua_gen_msg(RUA_RUA_PDU_t *pdu)
{
	struct msgb *msg = rua_msgb_alloc();
	asn_enc_rval_t rval;

	if (!msg)
		return NULL;

	rval = aper_encode_to_buffer(&asn_DEF_RUA_RUA_PDU, pdu,
				       msg->data, msgb_tailroom(msg));
	if (rval.encoded < 0) {
		LOGP(DRUA, LOGL_ERROR, "Error encoding type: %s\n",
				rval.failed_type->name);

	}

	msgb_put(msg, rval.encoded/8);

	return msg;
}


struct msgb *rua_generate_initiating_message(
					e_RUA_ProcedureCode procedureCode,
					RUA_Criticality_t criticality,
					asn_TYPE_descriptor_t * td, void *sptr)
{
	RUA_RUA_PDU_t pdu;
	int rc;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RUA_RUA_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = procedureCode;
	pdu.choice.initiatingMessage.criticality = criticality;
	rc = ANY_fromType_aper(&pdu.choice.initiatingMessage.value, td, sptr);
	if (rc < 0) {
		LOGP(DRUA, LOGL_ERROR, "Error in ANY_fromType_aper\n");
		return NULL;
	}

	return _rua_gen_msg(&pdu);
}

struct msgb *rua_generate_successful_outcome(
					   e_RUA_ProcedureCode procedureCode,
					   RUA_Criticality_t criticality,
					   asn_TYPE_descriptor_t * td,
					   void *sptr)
{
	RUA_RUA_PDU_t pdu;
	int rc;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RUA_RUA_PDU_PR_successfulOutcome;
	pdu.choice.successfulOutcome.procedureCode = procedureCode;
	pdu.choice.successfulOutcome.criticality = criticality;
	rc = ANY_fromType_aper(&pdu.choice.successfulOutcome.value, td, sptr);
	if (rc < 0) {
		LOGP(DRUA, LOGL_ERROR, "Error in ANY_fromType_aper\n");
		return NULL;
	}

	return _rua_gen_msg(&pdu);
}

struct msgb *rua_generate_unsuccessful_outcome(
					   e_RUA_ProcedureCode procedureCode,
					   RUA_Criticality_t criticality,
					   asn_TYPE_descriptor_t * td,
					   void *sptr)
{
	RUA_RUA_PDU_t pdu;
	int rc;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RUA_RUA_PDU_PR_unsuccessfulOutcome;
	pdu.choice.unsuccessfulOutcome.procedureCode = procedureCode;
	pdu.choice.unsuccessfulOutcome.criticality = criticality;
	rc = ANY_fromType_aper(&pdu.choice.unsuccessfulOutcome.value, td, sptr);
	if (rc < 0) {
		LOGP(DRUA, LOGL_ERROR, "Error in ANY_fromType_aper\n");
		return NULL;
	}

	return _rua_gen_msg(&pdu);
}

RUA_IE_t *rua_new_ie(RUA_ProtocolIE_ID_t id,
		     RUA_Criticality_t criticality,
		     asn_TYPE_descriptor_t * type, void *sptr)
{

	RUA_IE_t *buff;
	int rc;

	if ((buff = CALLOC(1, sizeof(*buff))) == NULL) {
		// Possible error on malloc
		return NULL;
	}

	buff->id = id;
	buff->criticality = criticality;

	rc = ANY_fromType_aper(&buff->value, type, sptr);
	if (rc < 0) {
		LOGP(DRUA, LOGL_ERROR, "Error in ANY_fromType_aper\n");
		FREEMEM(buff);
		return NULL;
	}

	if (asn1_xer_print)
		if (xer_fprint(stdout, &asn_DEF_RUA_IE, buff) < 0) {
			FREEMEM(buff);
			return NULL;
		}

	return buff;
}
