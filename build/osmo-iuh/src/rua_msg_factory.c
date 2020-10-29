#include <stdint.h>
#include <osmocom/netif/stream.h>

#include <osmocom/rua/rua_common.h>
#include <osmocom/rua/rua_ies_defs.h>
#include <osmocom/rua/rua_msg_factory.h>
#include "asn1helpers.h"
#include <osmocom/iuh/hnbgw.h>


struct msgb *rua_new_udt(struct msgb *inmsg)
{
	RUA_ConnectionlessTransfer_t out;
	RUA_ConnectionlessTransferIEs_t ies;
	struct msgb *msg;
	int rc;

	memset(&ies, 0, sizeof(ies));
	OCTET_STRING_fromBuf(&ies.ranaP_Message, inmsg->data, msgb_length(inmsg));
	msgb_free(inmsg);

	memset(&out, 0, sizeof(out));
	rc = rua_encode_connectionlesstransferies(&out, &ies);
	if (rc < 0)
		return NULL;

	msg = rua_generate_initiating_message(RUA_ProcedureCode_id_ConnectionlessTransfer,
					      RUA_Criticality_reject,
					      &asn_DEF_RUA_ConnectionlessTransfer,
					      &out);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_ConnectionlessTransfer, &out);

	DEBUGP(DMAIN, "transmitting RUA payload of %u bytes\n", msgb_length(msg));

	msgb_sctp_ppid(msg) = IUH_PPI_RUA;

	return msg;
}

struct msgb *rua_new_conn(int is_ps, uint32_t context_id, struct msgb *inmsg)
{
	RUA_Connect_t out;
	RUA_ConnectIEs_t ies;
	struct msgb *msg;
	uint32_t ctxidbuf;
	int rc;

	memset(&ies, 0, sizeof(ies));
	if (is_ps)
		ies.cN_DomainIndicator = RUA_CN_DomainIndicator_ps_domain;
	else
		ies.cN_DomainIndicator = RUA_CN_DomainIndicator_cs_domain;
	asn1_u24_to_bitstring(&ies.context_ID, &ctxidbuf, context_id);
	ies.establishment_Cause = RUA_Establishment_Cause_normal_call;
	OCTET_STRING_fromBuf(&ies.ranaP_Message, inmsg->data, msgb_length(inmsg));
	msgb_free(inmsg);

	memset(&out, 0, sizeof(out));
	rc = rua_encode_connecties(&out, &ies);
	if (rc < 0)
		return NULL;

	msg = rua_generate_initiating_message(RUA_ProcedureCode_id_Connect,
					      RUA_Criticality_reject,
					      &asn_DEF_RUA_Connect,
					      &out);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_Connect, &out);

	DEBUGP(DMAIN, "transmitting RUA payload of %u bytes\n", msgb_length(msg));

	msgb_sctp_ppid(msg) = IUH_PPI_RUA;

	return msg;
}

struct msgb *rua_new_dt(int is_ps, uint32_t context_id, struct msgb *inmsg)
{
	RUA_DirectTransfer_t out;
	RUA_DirectTransferIEs_t ies;
	struct msgb *msg;
	uint32_t ctxidbuf;
	int rc;

	memset(&ies, 0, sizeof(ies));
	if (is_ps)
		ies.cN_DomainIndicator = RUA_CN_DomainIndicator_ps_domain;
	else
		ies.cN_DomainIndicator = RUA_CN_DomainIndicator_cs_domain;
	asn1_u24_to_bitstring(&ies.context_ID, &ctxidbuf, context_id);
	OCTET_STRING_fromBuf(&ies.ranaP_Message, inmsg->data, msgb_length(inmsg));
	msgb_free(inmsg);

	memset(&out, 0, sizeof(out));
	rc = rua_encode_directtransferies(&out, &ies);
	if (rc < 0)
		return NULL;

	msg = rua_generate_initiating_message(RUA_ProcedureCode_id_DirectTransfer,
					      RUA_Criticality_reject,
					      &asn_DEF_RUA_DirectTransfer,
					      &out);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_DirectTransfer, &out);

	DEBUGP(DMAIN, "transmitting RUA payload of %u bytes\n", msgb_length(msg));

	msgb_sctp_ppid(msg) = IUH_PPI_RUA;

	return msg;
}

struct msgb *rua_new_disc(int is_ps, uint32_t context_id, struct msgb *inmsg)
{
	RUA_Disconnect_t out;
	RUA_DisconnectIEs_t ies;
	struct msgb *msg;
	uint32_t ctxidbuf;
	int rc;

	memset(&ies, 0, sizeof(ies));
	if (is_ps)
		ies.cN_DomainIndicator = RUA_CN_DomainIndicator_ps_domain;
	else
		ies.cN_DomainIndicator = RUA_CN_DomainIndicator_cs_domain;
	asn1_u24_to_bitstring(&ies.context_ID, &ctxidbuf, context_id);
	/* FIXME: make cause configurable */
	ies.cause.present = RUA_Cause_PR_radioNetwork;
	ies.cause.choice.radioNetwork = RUA_CauseRadioNetwork_normal;
	if (inmsg && inmsg->data&& msgb_length(inmsg)) {
		ies.presenceMask |= DISCONNECTIES_RUA_RANAP_MESSAGE_PRESENT;
		OCTET_STRING_fromBuf(&ies.ranaP_Message, inmsg->data, msgb_length(inmsg));
	}
	msgb_free(inmsg);

	memset(&out, 0, sizeof(out));
	rc = rua_encode_disconnecties(&out, &ies);
	if (rc < 0)
		return NULL;

	msg = rua_generate_initiating_message(RUA_ProcedureCode_id_Disconnect,
					      RUA_Criticality_reject,
					      &asn_DEF_RUA_Disconnect,
					      &out);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_Disconnect, &out);

	DEBUGP(DMAIN, "transmitting RUA payload of %u bytes\n", msgb_length(msg));

	msgb_sctp_ppid(msg) = IUH_PPI_RUA;

	return msg;
}
