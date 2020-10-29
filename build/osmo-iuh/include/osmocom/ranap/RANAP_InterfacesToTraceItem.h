/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/RANAP-IEs.asn"
 */

#ifndef	_RANAP_InterfacesToTraceItem_H_
#define	_RANAP_InterfacesToTraceItem_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <osmocom/ranap/RANAP_IE-Extensions.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum interface {
	interface_iu_cs	= 0,
	interface_iu_ps	= 1,
	interface_iur	= 2,
	interface_iub	= 3,
	interface_uu	= 4
	/*
	 * Enumeration is extensible
	 */
} e_interface;

/* RANAP_InterfacesToTraceItem */
typedef struct RANAP_InterfacesToTraceItem {
	long	 interface;
	RANAP_IE_Extensions_t	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_InterfacesToTraceItem_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_interface_2;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_InterfacesToTraceItem;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_InterfacesToTraceItem_H_ */
#include <asn_internal.h>