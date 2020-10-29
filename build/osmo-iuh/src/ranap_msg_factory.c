/* high-level RANAP messsage generation code */

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

#include "asn1helpers.h"
#include <osmocom/ranap/iu_helpers.h>

#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>

#define DRANAP _ranap_DRANAP

/*! \brief allocate a new long and assing a value to it */
static long *new_long(long in)
{
	long *out = CALLOC(1, sizeof(long));
	*out = in;
	return out;
}

/*! \brief generate RANAP RESET message */
struct msgb *ranap_new_msg_reset(RANAP_CN_DomainIndicator_t domain,
				 const RANAP_Cause_t *cause)
{
	RANAP_ResetIEs_t ies;
	RANAP_Reset_t out;
	struct msgb *msg;
	int rc;

	memset(&ies, 0, sizeof(ies));
	ies.cN_DomainIndicator = domain;
	if (cause)
		memcpy(&ies.cause, cause, sizeof(ies.cause));

	memset(&out, 0, sizeof(out));
	rc = ranap_encode_reseties(&out, &ies);
	if (rc < 0) {
		LOGP(DRANAP, LOGL_ERROR, "error encoding reset IEs: %d\n", rc);
		return NULL;
	}

	msg = ranap_generate_initiating_message(RANAP_ProcedureCode_id_Reset,
						RANAP_Criticality_reject,
						&asn_DEF_RANAP_Reset,
						&out);

	/* release dynamic allocations attached to dt */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_Reset, &out);

	return msg;
}

/*! \brief generate RANAP RESET ACK message */
struct msgb *ranap_new_msg_reset_ack(RANAP_CN_DomainIndicator_t domain,
				     RANAP_GlobalRNC_ID_t *rnc_id)
{
	RANAP_ResetAcknowledgeIEs_t ies;
	RANAP_ResetAcknowledge_t out;
	struct msgb *msg;
	int rc;

	memset(&ies, 0, sizeof(ies));
	ies.cN_DomainIndicator = domain;

	/* The RNC shall include the globalRNC_ID in the RESET
	 * ACKNOWLEDGE message to the CN */
	if (rnc_id) {
		ies.presenceMask = RESETACKNOWLEDGEIES_RANAP_GLOBALRNC_ID_PRESENT;
		OCTET_STRING_noalloc(&ies.globalRNC_ID.pLMNidentity,
				     rnc_id->pLMNidentity.buf,
				     rnc_id->pLMNidentity.size);
		ies.globalRNC_ID.rNC_ID = rnc_id->rNC_ID;
	}

	/* FIXME: Do we need criticalityDiagnostics */

	memset(&out, 0, sizeof(out));
	rc = ranap_encode_resetacknowledgeies(&out, &ies);
	if (rc < 0) {
		LOGP(DRANAP, LOGL_ERROR, "error encoding reset ack IEs: %d\n", rc);
		return NULL;
	}

	msg = ranap_generate_successful_outcome(RANAP_ProcedureCode_id_Reset,
						RANAP_Criticality_reject,
						&asn_DEF_RANAP_ResetAcknowledge,
						&out);

	/* release dynamic allocations attached to dt */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_ResetAcknowledge, &out);

	return msg;
}

/*! \brief generate RANAP INITIAL UE message */
struct msgb *ranap_new_msg_initial_ue(uint32_t conn_id, int is_ps,
				     RANAP_GlobalRNC_ID_t *rnc_id,
				     uint8_t *nas_pdu, unsigned int nas_len)
{
	RANAP_InitialUE_MessageIEs_t ies;
	RANAP_InitialUE_Message_t out;
	struct msgb *msg;
	uint32_t ctxidbuf;
	int rc;
	uint16_t buf0 = 0x2342;

	memset(&ies, 0, sizeof(ies));
	if (is_ps)
		ies.cN_DomainIndicator = RANAP_CN_DomainIndicator_ps_domain;
	else
		ies.cN_DomainIndicator = RANAP_CN_DomainIndicator_cs_domain;

	OCTET_STRING_noalloc(&ies.lai.pLMNidentity, rnc_id->pLMNidentity.buf, rnc_id->pLMNidentity.size);
	OCTET_STRING_noalloc(&ies.lai.lAC, (uint8_t *)&buf0, sizeof(buf0));

	OCTET_STRING_noalloc(&ies.sai.pLMNidentity, rnc_id->pLMNidentity.buf, rnc_id->pLMNidentity.size);
	OCTET_STRING_noalloc(&ies.sai.lAC, (uint8_t *)&buf0, sizeof(buf0));
	OCTET_STRING_noalloc(&ies.sai.sAC, (uint8_t *)&buf0, sizeof(buf0));

	OCTET_STRING_noalloc(&ies.nas_pdu, nas_pdu, nas_len);
	asn1_u24_to_bitstring(&ies.iuSigConId, &ctxidbuf, conn_id);
	OCTET_STRING_noalloc(&ies.globalRNC_ID.pLMNidentity, rnc_id->pLMNidentity.buf, rnc_id->pLMNidentity.size);
	ies.globalRNC_ID.rNC_ID = rnc_id->rNC_ID;

	memset(&out, 0, sizeof(out));
	rc = ranap_encode_initialue_messageies(&out, &ies);
	if (rc < 0) {
		LOGP(DRANAP, LOGL_ERROR, "error encoding initial UE IEs: %d\n", rc);
		return NULL;
	}

	msg = ranap_generate_initiating_message(RANAP_ProcedureCode_id_InitialUE_Message,
						RANAP_Criticality_reject,
						&asn_DEF_RANAP_InitialUE_Message,
						&out);

	/* release dynamic allocations attached to dt */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_InitialUE_Message, &out);

	return msg;
}


/*! \brief generate RANAP DIRECT TRANSFER message */
struct msgb *ranap_new_msg_dt(uint8_t sapi, const uint8_t *nas, unsigned int nas_len)
{
	RANAP_DirectTransferIEs_t ies;
	RANAP_DirectTransfer_t dt;
	struct msgb *msg;
	int rc;

	memset(&ies, 0, sizeof(ies));
	memset(&dt, 0, sizeof(dt));

	/* only SAPI optional field shall be present for CN->RNC */
	ies.presenceMask = DIRECTTRANSFERIES_RANAP_SAPI_PRESENT;

	if (sapi == 3)
		ies.sapi = RANAP_SAPI_sapi_3;
	else
		ies.sapi = RANAP_SAPI_sapi_0;

	/* Avoid copying + later freeing of OCTET STRING */
	OCTET_STRING_noalloc(&ies.nas_pdu, nas, nas_len);

	/* ies -> dt */
	rc = ranap_encode_directtransferies(&dt, &ies);

	/* dt -> msg */
	msg = ranap_generate_initiating_message(RANAP_ProcedureCode_id_DirectTransfer,
						RANAP_Criticality_reject,
						&asn_DEF_RANAP_DirectTransfer,
						&dt);

	/* release dynamic allocations attached to dt */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_DirectTransfer, &dt);

	return msg;
}

static const enum RANAP_IntegrityProtectionAlgorithm ip_alg[2] = {
	RANAP_IntegrityProtectionAlgorithm_standard_UMTS_integrity_algorithm_UIA1,
	RANAP_IntegrityProtectionAlgorithm_standard_UMTS_integrity_algorithm_UIA2,
};

static const RANAP_EncryptionAlgorithm_t enc_alg[2] = {
	RANAP_EncryptionAlgorithm_standard_UMTS_encryption_algorith_UEA1,
	RANAP_EncryptionAlgorithm_standard_UMTS_encryption_algorithm_UEA2,
};

/*! \brief generate RANAP SECURITY MODE COMMAND message */
struct msgb *ranap_new_msg_sec_mod_cmd(const uint8_t *ik, const uint8_t *ck, enum RANAP_KeyStatus status)
{
	RANAP_SecurityModeCommandIEs_t ies;
	RANAP_SecurityModeCommand_t out;
	struct msgb *msg;
	int i, rc;

	memset(&ies, 0, sizeof(ies));
	memset(&out, 0, sizeof(out));

	for (i = 0; i < ARRAY_SIZE(ip_alg); i++) {
		/* needs to be dynamically allocated, as
		 * SET_OF_free() will call FREEMEM() on it */
		RANAP_IntegrityProtectionAlgorithm_t *alg = CALLOC(1, sizeof(*alg));
		*alg = ip_alg[i];
		ASN_SEQUENCE_ADD(&ies.integrityProtectionInformation.permittedAlgorithms, alg);
	}

	BIT_STRING_fromBuf(&ies.integrityProtectionInformation.key, ik, 16*8);

	if (ck) {
		ies.presenceMask = SECURITYMODECOMMANDIES_RANAP_ENCRYPTIONINFORMATION_PRESENT;
		for (i = 0; i < ARRAY_SIZE(ip_alg); i++) {
			/* needs to be dynamically allocated, as
			 * SET_OF_free() will call FREEMEM() on it */
			RANAP_EncryptionAlgorithm_t *alg = CALLOC(1, sizeof(*alg));
			*alg = enc_alg[i];
			ASN_SEQUENCE_ADD(&ies.encryptionInformation.permittedAlgorithms, alg);
		}
		BIT_STRING_fromBuf(&ies.encryptionInformation.key, ck, 16*8);
	}

	ies.keyStatus = status;

	/* ies -> out */
	rc = ranap_encode_securitymodecommandies(&out, &ies);

	/* release dynamic allocations attached to ies */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_IntegrityProtectionInformation, &ies.integrityProtectionInformation);
	if (ck)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_EncryptionInformation, &ies.encryptionInformation);

	/* out -> msg */
	msg = ranap_generate_initiating_message(RANAP_ProcedureCode_id_SecurityModeControl,
						RANAP_Criticality_reject,
						&asn_DEF_RANAP_SecurityModeCommand,
						&out);

	/* release dynamic allocations attached to out */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_SecurityModeCommand, &out);

	return msg;
}

/*! \brief generate RANAP SECURITY MODE COMPLETE message */
struct msgb *ranap_new_msg_sec_mod_compl(
	RANAP_ChosenIntegrityProtectionAlgorithm_t chosen_ip_alg,
	RANAP_ChosenEncryptionAlgorithm_t chosen_enc_alg)
{
	RANAP_SecurityModeCompleteIEs_t ies;
	RANAP_SecurityModeComplete_t out;
	struct msgb *msg;
	int i, rc;

	memset(&ies, 0, sizeof(ies));
	memset(&out, 0, sizeof(out));

	ies.presenceMask = SECURITYMODECOMPLETEIES_RANAP_CHOSENENCRYPTIONALGORITHM_PRESENT;
	ies.chosenIntegrityProtectionAlgorithm = chosen_ip_alg;
	ies.chosenEncryptionAlgorithm = chosen_enc_alg;

	/* ies -> out */
	rc = ranap_encode_securitymodecompleteies(&out, &ies);

	/* out -> msg */
	msg = ranap_generate_successful_outcome(RANAP_ProcedureCode_id_SecurityModeControl,
						RANAP_Criticality_reject,
						&asn_DEF_RANAP_SecurityModeComplete,
						&out);

	/* release dynamic allocations attached to out */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_SecurityModeComplete, &out);

	return msg;
}

/*! \brief generate RANAP COMMON ID message */
struct msgb *ranap_new_msg_common_id(const char *imsi)
{
	RANAP_CommonID_IEs_t ies;
	RANAP_CommonID_t out;
	struct msgb *msg;
	int rc;

	memset(&ies, 0, sizeof(ies));
	memset(&out, 0, sizeof(out));

	if (imsi) {
		uint8_t *imsi_buf = CALLOC(1, 16);
		rc = ranap_imsi_encode(imsi_buf, 16, imsi);
		ies.permanentNAS_UE_ID.present = RANAP_PermanentNAS_UE_ID_PR_iMSI;
		ies.permanentNAS_UE_ID.choice.iMSI.buf = imsi_buf;
		ies.permanentNAS_UE_ID.choice.iMSI.size = rc;
	} else
		ies.permanentNAS_UE_ID.present = RANAP_PermanentNAS_UE_ID_PR_NOTHING;

	/* ies -> out */
	rc = ranap_encode_commonid_ies(&out, &ies);
	/* release dynamic allocations attached to ies */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_PermanentNAS_UE_ID, &ies.permanentNAS_UE_ID);
	if (rc < 0)
		return NULL;

	/* out -> msg */
	msg = ranap_generate_initiating_message(RANAP_ProcedureCode_id_CommonID,
						RANAP_Criticality_ignore,
						&asn_DEF_RANAP_CommonID,
						&out);

	/* release dynamic allocations attached to out */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_CommonID, &out);

	return msg;
}

/*! \brief generate RANAP IU RELEASE COMMAND message */
struct msgb *ranap_new_msg_iu_rel_cmd(const RANAP_Cause_t *cause_in)
{
	RANAP_Iu_ReleaseCommandIEs_t ies;
	RANAP_Iu_ReleaseCommand_t out;
	struct msgb *msg;
	int rc;

	memset(&ies, 0, sizeof(ies));
	memset(&out, 0, sizeof(out));

	memcpy(&ies.cause, cause_in, sizeof(ies.cause));

	/* ies -> out */
	rc = ranap_encode_iu_releasecommandies(&out, &ies);
	if (rc < 0)
		return NULL;

	/* out -> msg */
	msg = ranap_generate_initiating_message(RANAP_ProcedureCode_id_Iu_Release,
						RANAP_Criticality_reject,
						&asn_DEF_RANAP_Iu_ReleaseCommand,
						&out);

	/* release dynamic allocations attached to out */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_Iu_ReleaseCommand, &out);

	return msg;
}

/*! \brief generate RAPAP IU RELEASE COMPLETE message */
struct msgb *ranap_new_msg_iu_rel_compl(void)
{
	RANAP_Iu_ReleaseCompleteIEs_t ies;
	RANAP_Iu_ReleaseComplete_t out;
	struct msgb *msg;
	int rc;

	memset(&ies, 0, sizeof(ies));
	memset(&out, 0, sizeof(out));

	/* ies -> out */
	rc = ranap_encode_iu_releasecompleteies(&out, &ies);
	if (rc < 0)
		return NULL;

	/* out -> msg */
	msg = ranap_generate_successful_outcome(RANAP_ProcedureCode_id_Iu_Release,
						RANAP_Criticality_reject,
						&asn_DEF_RANAP_Iu_ReleaseComplete,
						&out);

	/* release dynamic allocations attached to out */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_Iu_ReleaseComplete, &out);

	return msg;
}

/*! \brief generate RANAP PAGING COMMAND message */
struct msgb *ranap_new_msg_paging_cmd(const char *imsi, const uint32_t *tmsi, int is_ps, uint32_t cause)
{
	RANAP_PagingIEs_t ies;
	RANAP_Paging_t out;
	struct msgb *msg;
	uint8_t *imsi_buf = CALLOC(1, 16);
	int rc;

	memset(&ies, 0, sizeof(ies));
	memset(&out, 0, sizeof(out));

	/* put together the 'ies' */
	if (is_ps)
		ies.cN_DomainIndicator = RANAP_CN_DomainIndicator_ps_domain;
	else
		ies.cN_DomainIndicator = RANAP_CN_DomainIndicator_cs_domain;

	rc = ranap_imsi_encode(imsi_buf, 16, imsi);
	ies.permanentNAS_UE_ID.present = RANAP_PermanentNAS_UE_ID_PR_iMSI;
	ies.permanentNAS_UE_ID.choice.iMSI.buf = imsi_buf;
	ies.permanentNAS_UE_ID.choice.iMSI.size = rc;

	if (tmsi) {
		uint32_t *tmsi_buf = CALLOC(1, sizeof(*tmsi_buf));
		ies.presenceMask |= PAGINGIES_RANAP_TEMPORARYUE_ID_PRESENT;
		if (is_ps) {
			ies.temporaryUE_ID.present = RANAP_TemporaryUE_ID_PR_p_TMSI;
			asn1_u32_to_str(&ies.temporaryUE_ID.choice.tMSI, tmsi_buf, *tmsi);
		} else {
			ies.temporaryUE_ID.present = RANAP_TemporaryUE_ID_PR_tMSI;
			asn1_u32_to_str(&ies.temporaryUE_ID.choice.p_TMSI, tmsi_buf, *tmsi);
		}
	}

	if (cause) {
		ies.presenceMask |= PAGINGIES_RANAP_PAGINGCAUSE_PRESENT;
		ies.pagingCause = cause;
	}

	/* ies -> out */
	rc = ranap_encode_pagingies(&out, &ies);
	/* release dynamic allocation attached to ies */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_PermanentNAS_UE_ID, &ies.permanentNAS_UE_ID);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_TemporaryUE_ID, &ies.temporaryUE_ID);
	if (rc < 0)
		return NULL;

	/* out -> msg */
	msg = ranap_generate_initiating_message(RANAP_ProcedureCode_id_Paging,
						RANAP_Criticality_reject,
						&asn_DEF_RANAP_Paging,
						&out);

	/* release dynamic allocations attached to out */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_Paging, &out);

	return msg;
}

static RANAP_SDU_ErrorRatio_t *new_sdu_error_ratio(long mantissa, long exponent)
{
	RANAP_SDU_ErrorRatio_t *err = CALLOC(1, sizeof(*err));

	err->mantissa = mantissa;
	err->exponent = exponent;

	return err;
}


static RANAP_SDU_FormatInformationParameterItem_t *
new_format_info_pars(long sdu_size)
{
	RANAP_SDU_FormatInformationParameterItem_t *fmti = CALLOC(1, sizeof(*fmti));
	fmti->subflowSDU_Size = new_long(sdu_size);
	return fmti;
}

enum sdu_par_profile {
	SDUPAR_P_VOICE0,
	SDUPAR_P_VOICE1,
	SDUPAR_P_VOICE2,
	SDUPAR_P_DATA,
};

/* See Chapter 5 of TS 26.102 */
static RANAP_SDU_ParameterItem_t *new_sdu_par_item(enum sdu_par_profile profile)
{
	RANAP_SDU_ParameterItem_t *sdui = CALLOC(1, sizeof(*sdui));
	RANAP_SDU_FormatInformationParameters_t *fmtip = CALLOC(1, sizeof(*fmtip));
	RANAP_SDU_FormatInformationParameterItem_t *fmti;

	switch (profile) {
	case SDUPAR_P_VOICE0:
		sdui->sDU_ErrorRatio = new_sdu_error_ratio(1, 5);
		sdui->residualBitErrorRatio.mantissa = 1;
		sdui->residualBitErrorRatio.exponent = 6;
		sdui->deliveryOfErroneousSDU = RANAP_DeliveryOfErroneousSDU_yes;
		sdui->sDU_FormatInformationParameters = fmtip;
		fmti = new_format_info_pars(81);
		ASN_SEQUENCE_ADD(fmtip, fmti);
		fmti = new_format_info_pars(39);
		ASN_SEQUENCE_ADD(fmtip, fmti);
		/* FIXME: could be 10 SDU descriptors for AMR! */
		break;
	case SDUPAR_P_VOICE1:
		sdui->residualBitErrorRatio.mantissa = 1;
		sdui->residualBitErrorRatio.exponent = 3;
		sdui->deliveryOfErroneousSDU = RANAP_DeliveryOfErroneousSDU_no_error_detection_consideration;
		sdui->sDU_FormatInformationParameters = fmtip;
		fmti = new_format_info_pars(103);
		ASN_SEQUENCE_ADD(fmtip, fmti);
		fmti = new_format_info_pars(0);
		ASN_SEQUENCE_ADD(fmtip, fmti);
		/* FIXME: could be 10 SDU descriptors for AMR! */
		break;
	case SDUPAR_P_VOICE2:
		sdui->residualBitErrorRatio.mantissa = 5;
		sdui->residualBitErrorRatio.exponent = 3;
		sdui->deliveryOfErroneousSDU = RANAP_DeliveryOfErroneousSDU_no_error_detection_consideration;
		sdui->sDU_FormatInformationParameters = fmtip;
		fmti = new_format_info_pars(60);
		ASN_SEQUENCE_ADD(fmtip, fmti);
		fmti = new_format_info_pars(0);
		ASN_SEQUENCE_ADD(fmtip, fmti);
		/* FIXME: could be 10 SDU descriptors for AMR! */
		break;
	case SDUPAR_P_DATA:
		sdui->sDU_ErrorRatio = new_sdu_error_ratio(1, 4);
		sdui->residualBitErrorRatio.mantissa = 1;
		sdui->residualBitErrorRatio.exponent = 5;
		sdui->deliveryOfErroneousSDU = RANAP_DeliveryOfErroneousSDU_no;
		FREEMEM(fmtip);
		break;
	}

	return sdui;
}

static RANAP_AllocationOrRetentionPriority_t *
new_alloc_ret_prio(RANAP_PriorityLevel_t level, int capability, int vulnerability,
		   int queueing_allowed)
{
	RANAP_AllocationOrRetentionPriority_t *arp = CALLOC(1, sizeof(*arp));

	arp->priorityLevel = level;

	if (capability)
		arp->pre_emptionCapability = RANAP_Pre_emptionCapability_may_trigger_pre_emption;
	else
		arp->pre_emptionCapability = RANAP_Pre_emptionCapability_shall_not_trigger_pre_emption;

	if (vulnerability)
		arp->pre_emptionVulnerability = RANAP_Pre_emptionVulnerability_pre_emptable;
	else
		arp->pre_emptionVulnerability = RANAP_Pre_emptionVulnerability_not_pre_emptable;

	if (queueing_allowed)
		arp->queuingAllowed = RANAP_QueuingAllowed_queueing_allowed;
	else
		arp->queuingAllowed = RANAP_QueuingAllowed_queueing_not_allowed;

	return arp;
}

/* See Chapter 5 of TS 26.102 */
static RANAP_RAB_Parameters_t *new_rab_par_voice(long bitrate_guaranteed,
						 long bitrate_max)
{
	RANAP_RAB_Parameters_t *rab = CALLOC(1, sizeof(*rab));
	RANAP_SDU_ParameterItem_t *sdui;

	rab->trafficClass = RANAP_TrafficClass_conversational;
	rab->rAB_AsymmetryIndicator = RANAP_RAB_AsymmetryIndicator_symmetric_bidirectional;

	ASN_SEQUENCE_ADD(&rab->maxBitrate.list, new_long(bitrate_max));
	rab->guaranteedBitRate = CALLOC(1, sizeof(*rab->guaranteedBitRate));
	ASN_SEQUENCE_ADD(rab->guaranteedBitRate, new_long(bitrate_guaranteed));
	rab->deliveryOrder = RANAP_DeliveryOrder_delivery_order_requested;
	rab->maxSDU_Size = 244;

	sdui = new_sdu_par_item(SDUPAR_P_VOICE0);
	ASN_SEQUENCE_ADD(&rab->sDU_Parameters, sdui);
	sdui = new_sdu_par_item(SDUPAR_P_VOICE1);
	ASN_SEQUENCE_ADD(&rab->sDU_Parameters, sdui);
	sdui = new_sdu_par_item(SDUPAR_P_VOICE2);
	ASN_SEQUENCE_ADD(&rab->sDU_Parameters, sdui);

	rab->transferDelay = new_long(80);
	rab->allocationOrRetentionPriority = new_alloc_ret_prio(RANAP_PriorityLevel_no_priority, 0, 1, 0);

	rab->sourceStatisticsDescriptor = new_long(RANAP_SourceStatisticsDescriptor_speech);

	return rab;
}

static RANAP_NAS_SynchronisationIndicator_t *new_rab_nas_sync_ind(int val)
{
	uint8_t val_buf = (val / 10) << 4;
	RANAP_NAS_SynchronisationIndicator_t *nsi = CALLOC(1, sizeof(*nsi));
	BIT_STRING_fromBuf(nsi, &val_buf, 4);
	return nsi;
}

static RANAP_RAB_Parameters_t *new_rab_par_data(uint32_t dl_max_bitrate, uint32_t ul_max_bitrate)
{
	RANAP_RAB_Parameters_t *rab = CALLOC(1, sizeof(*rab));
	RANAP_SDU_ParameterItem_t *sdui;

	rab->trafficClass = RANAP_TrafficClass_background;
	rab->rAB_AsymmetryIndicator = RANAP_RAB_AsymmetryIndicator_asymmetric_bidirectional;

	ASN_SEQUENCE_ADD(&rab->maxBitrate.list, new_long(dl_max_bitrate));
	ASN_SEQUENCE_ADD(&rab->maxBitrate.list, new_long(ul_max_bitrate));
	rab->deliveryOrder = RANAP_DeliveryOrder_delivery_order_requested;
	rab->maxSDU_Size = 8000;

	sdui = new_sdu_par_item(SDUPAR_P_DATA);
	ASN_SEQUENCE_ADD(&rab->sDU_Parameters, sdui);

	rab->allocationOrRetentionPriority = new_alloc_ret_prio(RANAP_PriorityLevel_no_priority, 0, 0, 0);

	RANAP_ProtocolExtensionField_t *pxf = CALLOC(1, sizeof(*pxf));
	pxf->id = RANAP_ProtocolIE_ID_id_RAB_Parameter_ExtendedMaxBitrateList;
	pxf->criticality = RANAP_Criticality_ignore;

	RANAP_RAB_Parameter_ExtendedMaxBitrateList_t *rab_mbrlist = CALLOC(1, sizeof(*rab_mbrlist));
	RANAP_ExtendedMaxBitrate_t *xmbr = CALLOC(1, sizeof(*xmbr));
	*xmbr = 42000000;
	ASN_SEQUENCE_ADD(&rab_mbrlist->list, xmbr);

	ANY_fromType_aper(&pxf->value, &asn_DEF_RANAP_RAB_Parameter_ExtendedMaxBitrateList, rab_mbrlist);

	ASN_STRUCT_FREE(asn_DEF_RANAP_RAB_Parameter_ExtendedMaxBitrateList, rab_mbrlist);

	rab->iE_Extensions = CALLOC(1, sizeof(*rab->iE_Extensions));
	ASN_SEQUENCE_ADD(&rab->iE_Extensions->list, pxf);

	return rab;
}

static void new_transp_layer_addr(BIT_STRING_t *out, uint32_t ip, bool use_x213_nsap)
{
	uint8_t *buf;
	unsigned int len;

	if (use_x213_nsap) {
		len = 160/8;
		buf = CALLOC(len, sizeof(uint8_t));
		buf[0] = 0x35;	/* AFI For IANA ICP */
		buf[1] = 0x00;	/* See A.5.2.1.2.7 of X.213 */
		buf[2] = 0x01;
		*(uint32_t *)&buf[3] = ntohl(ip);
	} else {
		len = 4;
		buf = CALLOC(len, sizeof(uint8_t));
		*(uint32_t *)buf = ntohl(ip);
	}
	out->buf = buf;
	out->size = len;
	out->bits_unused = 0;
}

static RANAP_TransportLayerInformation_t *new_transp_info_rtp(uint32_t ip, uint16_t port,
							      bool use_x213_nsap)
{
	RANAP_TransportLayerInformation_t *tli = CALLOC(1, sizeof(*tli));
	uint8_t binding_id[4];

	binding_id[0] = port >> 8;
	binding_id[1] = port & 0xff;
	binding_id[2] = binding_id[3] = 0;

	new_transp_layer_addr(&tli->transportLayerAddress, ip, use_x213_nsap);
	tli->iuTransportAssociation.present = RANAP_IuTransportAssociation_PR_bindingID;
	OCTET_STRING_fromBuf(&tli->iuTransportAssociation.choice.bindingID,
				(const char *) binding_id, sizeof(binding_id));

	return tli;
}

static RANAP_TransportLayerInformation_t *new_transp_info_gtp(uint32_t ip, uint32_t tei,
							      bool use_x213_nsap)
{
	RANAP_TransportLayerInformation_t *tli = CALLOC(1, sizeof(*tli));
	uint32_t binding_buf = htonl(tei);

	new_transp_layer_addr(&tli->transportLayerAddress, ip, use_x213_nsap);
	tli->iuTransportAssociation.present = RANAP_IuTransportAssociation_PR_gTP_TEI;
	OCTET_STRING_fromBuf(&tli->iuTransportAssociation.choice.gTP_TEI,
			     (const char *) &binding_buf, sizeof(binding_buf));

	return tli;
}

static RANAP_UserPlaneInformation_t *new_upi(long mode, uint8_t mode_versions)
{
	RANAP_UserPlaneInformation_t *upi = CALLOC(1, sizeof(*upi));
	uint16_t *buf = CALLOC(1, sizeof(*buf));

	*buf = ntohs(mode_versions);

	upi->userPlaneMode = mode;
	upi->uP_ModeVersions.buf = (uint8_t *) buf;
	upi->uP_ModeVersions.size = sizeof(*buf);
	upi->uP_ModeVersions.bits_unused = 0;

	return upi;
}


static void assign_new_ra_id(RANAP_RAB_ID_t *id, uint8_t rab_id)
{
	uint8_t *buf = CALLOC(1, sizeof(*buf));
	*buf = rab_id;

	id->buf = buf;
	id->size = 1;
	id->bits_unused = 0;
}

/*! \brief generate RANAP RAB ASSIGNMENT REQUEST message for CS (voice).
 * See 3GPP TS 25.413 8.2.
 * RAB ID: 3GPP TS 25.413 9.2.1.2
 */
struct msgb *ranap_new_msg_rab_assign_voice(uint8_t rab_id, uint32_t rtp_ip,
					    uint16_t rtp_port,
					    bool use_x213_nsap)
{
	RANAP_ProtocolIE_FieldPair_t *pair;
	RANAP_RAB_AssignmentRequestIEs_t ies;
	RANAP_RAB_AssignmentRequest_t out;
	struct msgb *msg;
	int rc;

	memset(&ies, 0, sizeof(ies));
	memset(&out, 0, sizeof(out));

	/* only assingnment is present, no release */
	ies.presenceMask = RAB_ASSIGNMENTREQUESTIES_RANAP_RAB_SETUPORMODIFYLIST_PRESENT;

	/* put together the 'First' part */
	RANAP_RAB_SetupOrModifyItemFirst_t first;
	memset(&first, 0, sizeof(first));
	assign_new_ra_id(&first.rAB_ID, rab_id);
	first.nAS_SynchronisationIndicator = new_rab_nas_sync_ind(60);
	first.rAB_Parameters = new_rab_par_voice(6700, 12200);
	first.userPlaneInformation = new_upi(RANAP_UserPlaneMode_support_mode_for_predefined_SDU_sizes, 1); /* 2? */
	first.transportLayerInformation = new_transp_info_rtp(rtp_ip, rtp_port,
							      use_x213_nsap);

	/* put together the 'Second' part */
	RANAP_RAB_SetupOrModifyItemSecond_t second;
	memset(&second, 0, sizeof(second));

	/* Build an IE Pair out of first and second part:
	 * (first, second) -> pair */
	pair = ranap_new_ie_pair(RANAP_ProtocolIE_ID_id_RAB_SetupOrModifyItem,
				 RANAP_Criticality_reject,
				 &asn_DEF_RANAP_RAB_SetupOrModifyItemFirst, &first,
				 RANAP_Criticality_ignore,
				 &asn_DEF_RANAP_RAB_SetupOrModifyItemSecond, &second);

	/* the pair has been made, we can release any of its elements */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifyItemFirst, &first);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifyItemSecond, &second);

	RANAP_ProtocolIE_ContainerPair_t *container_pair = CALLOC(1, sizeof(*container_pair));
	/* Add the pair to the list of IEs of the RAB ass.req */
	ASN_SEQUENCE_ADD(container_pair, pair);
	ASN_SEQUENCE_ADD(&ies.raB_SetupOrModifyList.list, container_pair);

	/* encode the IEs into the actual assignment request:
	 * ies -> out */
	rc = ranap_encode_rab_assignmentrequesties(&out, &ies);
	/* 'out' has been generated, we can now release the input */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifyList,
				      &ies.raB_SetupOrModifyList);
	if (rc < 0)
		return NULL;

	/* generate an Initiating Mesasage: out -> msg */
	msg = ranap_generate_initiating_message(RANAP_ProcedureCode_id_RAB_Assignment,
						RANAP_Criticality_reject,
						&asn_DEF_RANAP_RAB_AssignmentRequest, &out);

	/* 'msg' has been generated, we cann now release the input 'out' */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_AssignmentRequest, &out);

	return msg;
}

/*! \brief generate RANAP RAB ASSIGNMENT REQUEST message for PS (data) */
struct msgb *ranap_new_msg_rab_assign_data(uint8_t rab_id, uint32_t gtp_ip,
					   uint32_t gtp_tei, bool use_x213_nsap)
{
	RANAP_ProtocolIE_FieldPair_t *pair;
	RANAP_RAB_AssignmentRequestIEs_t ies;
	RANAP_RAB_AssignmentRequest_t out;
	RANAP_DataVolumeReportingIndication_t *dat_vol_ind;
	struct msgb *msg;
	int rc;

	memset(&ies, 0, sizeof(ies));
	memset(&out, 0, sizeof(out));

	/* only assingnment is present, no release */
	ies.presenceMask = RAB_ASSIGNMENTREQUESTIES_RANAP_RAB_SETUPORMODIFYLIST_PRESENT;

	/* put together the 'First' part */
	RANAP_RAB_SetupOrModifyItemFirst_t first;
	memset(&first, 0, sizeof(first));
	assign_new_ra_id(&first.rAB_ID, rab_id);
	//first.nAS_SynchronisationIndicator = FIXME;

	first.rAB_Parameters = new_rab_par_data(1600000, 800000);
	first.userPlaneInformation = new_upi(RANAP_UserPlaneMode_transparent_mode, 1);
	first.transportLayerInformation = new_transp_info_gtp(gtp_ip, gtp_tei,
							      use_x213_nsap);

	/* put together the 'Second' part */
	RANAP_RAB_SetupOrModifyItemSecond_t second;
	memset(&second, 0, sizeof(second));
	second.pDP_TypeInformation = CALLOC(1, sizeof(*second.pDP_TypeInformation));
	ASN_SEQUENCE_ADD(second.pDP_TypeInformation, new_long(RANAP_PDP_Type_ipv4));
	dat_vol_ind = CALLOC(1, sizeof(*dat_vol_ind));
	*dat_vol_ind = RANAP_DataVolumeReportingIndication_do_not_report;
	second.dataVolumeReportingIndication = dat_vol_ind;
	second.dl_GTP_PDU_SequenceNumber = new_long(0);
	second.ul_GTP_PDU_SequenceNumber = new_long(0);

	/* Build an IE Pair out of first and second part:
	 * (first, second) -> pair */
	pair = ranap_new_ie_pair(RANAP_ProtocolIE_ID_id_RAB_SetupOrModifyItem,
				 RANAP_Criticality_reject,
				 &asn_DEF_RANAP_RAB_SetupOrModifyItemFirst,
				 &first, RANAP_Criticality_ignore,
				 &asn_DEF_RANAP_RAB_SetupOrModifyItemSecond,
				 &second);

	/* the pair has been made, we can release any of its elements */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifyItemFirst, &first);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifyItemSecond, &second);

	RANAP_ProtocolIE_ContainerPair_t *container_pair = CALLOC(1, sizeof(*container_pair));
	/* Add the pair to the list of IEs of the RAB ass.req */
	ASN_SEQUENCE_ADD(&container_pair->list, pair);
	/* Add the pair to the list of IEs of the RAB ass.req */
	ASN_SEQUENCE_ADD(&ies.raB_SetupOrModifyList.list, container_pair);

	/* encode the IEs into the actual assignment request:
	 * ies -> out */
	rc = ranap_encode_rab_assignmentrequesties(&out, &ies);
	/* 'out' has been generated, we can now release the input */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifyList,
				      &ies.raB_SetupOrModifyList);
	if (rc < 0)
		return NULL;

	/* generate an Initiating Mesasage: out -> msg */
	msg = ranap_generate_initiating_message(RANAP_ProcedureCode_id_RAB_Assignment,
						RANAP_Criticality_reject,
						&asn_DEF_RANAP_RAB_AssignmentRequest, &out);

	/* 'msg' has been generated, we cann now release the input 'out' */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_AssignmentRequest, &out);

	return msg;
}

struct msgb *ranap_new_msg_iu_rel_req(const RANAP_Cause_t *cause)
{
	RANAP_Iu_ReleaseRequestIEs_t ies;
	RANAP_Iu_ReleaseRequest_t out;
	struct msgb *msg;
	int rc;

	memset(&ies, 0, sizeof(ies));
	memset(&out, 0, sizeof(out));

	memcpy(&ies.cause, cause, sizeof(ies.cause));

	rc = ranap_encode_iu_releaserequesties(&out, &ies);
	if (rc < 0)
		return NULL;

	/* encode the output into the msgb */
	msg = ranap_generate_initiating_message(RANAP_ProcedureCode_id_Iu_ReleaseRequest,
						RANAP_Criticality_reject,
						&asn_DEF_RANAP_Iu_ReleaseRequest, &out);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_Iu_ReleaseRequest, &out);

	return msg;
}

struct msgb *ranap_new_msg_rab_rel_req(uint8_t rab_id, const RANAP_Cause_t *cause)
{
	RANAP_RAB_ReleaseItemIEs_t item_ies;
	RANAP_RAB_ReleaseRequestIEs_t ies;
	RANAP_RAB_ReleaseRequest_t out;
	struct msgb *msg;
	int rc;

	memset(&item_ies, 0, sizeof(item_ies));
	memset(&ies, 0, sizeof(ies));
	memset(&out, 0, sizeof(out));

	/* put together the ReleaseItem */
	assign_new_ra_id(&item_ies.raB_ReleaseItem.rAB_ID, rab_id);
	memcpy(&item_ies.raB_ReleaseItem.cause, cause, sizeof(item_ies.raB_ReleaseItem.cause));

	/* add to the list */
	rc = ranap_encode_rab_releaseitemies(&ies.raB_ReleaseList, &item_ies);
	if (rc < 0)
		return NULL;
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_ReleaseItem, &item_ies.raB_ReleaseItem);

	/* encoe the list IEs into the output */
	rc = ranap_encode_rab_releaserequesties(&out, &ies);
	if (rc < 0)
		return NULL;
	/* 'out' has been generated, we can release the input */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_ReleaseList, &ies.raB_ReleaseList);

	/* encode the output into the msgb */
	msg = ranap_generate_initiating_message(RANAP_ProcedureCode_id_RAB_ReleaseRequest,
						RANAP_Criticality_reject,
						&asn_DEF_RANAP_RAB_ReleaseRequest, &out);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_ReleaseRequest, &out);

	return msg;
}
