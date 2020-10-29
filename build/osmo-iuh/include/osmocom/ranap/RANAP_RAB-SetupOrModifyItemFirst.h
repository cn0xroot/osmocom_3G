/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-PDU"
 * 	found in "../../asn1/ranap/RANAP-PDU.asn"
 */

#ifndef	_RANAP_RAB_SetupOrModifyItemFirst_H_
#define	_RANAP_RAB_SetupOrModifyItemFirst_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_RAB-ID.h>
#include <osmocom/ranap/RANAP_NAS-SynchronisationIndicator.h>
#include <osmocom/ranap/RANAP_RAB-Parameters.h>
#include <osmocom/ranap/RANAP_UserPlaneInformation.h>
#include <osmocom/ranap/RANAP_TransportLayerInformation.h>
#include <osmocom/ranap/RANAP_Service-Handover.h>
#include <osmocom/ranap/RANAP_ProtocolExtensionContainer.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_RAB-SetupOrModifyItemFirst */
typedef struct RANAP_RAB_SetupOrModifyItemFirst {
	RANAP_RAB_ID_t	 rAB_ID;
	RANAP_NAS_SynchronisationIndicator_t	*nAS_SynchronisationIndicator	/* OPTIONAL */;
	RANAP_RAB_Parameters_t	*rAB_Parameters	/* OPTIONAL */;
	RANAP_UserPlaneInformation_t	*userPlaneInformation	/* OPTIONAL */;
	RANAP_TransportLayerInformation_t	*transportLayerInformation	/* OPTIONAL */;
	RANAP_Service_Handover_t	*service_Handover	/* OPTIONAL */;
	RANAP_ProtocolExtensionContainer_t	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_RAB_SetupOrModifyItemFirst_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_RAB_SetupOrModifyItemFirst;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_RAB_SetupOrModifyItemFirst_H_ */
#include <asn_internal.h>