#pragma once

#include "asn_application.h"

#include <ANY.h>
#include <BIT_STRING.h>
#include <INTEGER.h>
#include <NativeEnumerated.h>
#include <NativeInteger.h>
#include <OBJECT_IDENTIFIER.h>
#include <OCTET_STRING.h>

#include <osmocom/hnbap/Access-stratum-release-indicator.h>
#include <osmocom/hnbap/AccessResult.h>
#include <osmocom/hnbap/AdditionalNeighbourInfoList.h>
#include <osmocom/hnbap/AltitudeAndDirection.h>
#include <osmocom/hnbap/BackoffTimer.h>
#include <osmocom/hnbap/BindingID.h>
#include <osmocom/hnbap/CELL-FACHMobilitySupport.h>
#include <osmocom/hnbap/CGI.h>
#include <osmocom/hnbap/CI.h>
#include <osmocom/hnbap/CN-DomainIndicator.h>
#include <osmocom/hnbap/CSG-Capability.h>
#include <osmocom/hnbap/CSG-ID.h>
#include <osmocom/hnbap/CSGMembershipStatus.h>
#include <osmocom/hnbap/CSGMembershipUpdate.h>
#include <osmocom/hnbap/Cause.h>
#include <osmocom/hnbap/CauseMisc.h>
#include <osmocom/hnbap/CauseProtocol.h>
#include <osmocom/hnbap/CauseRadioNetwork.h>
#include <osmocom/hnbap/CauseTransport.h>
#include <osmocom/hnbap/CellIdentity.h>
#include <osmocom/hnbap/ConfigurationInformation.h>
#include <osmocom/hnbap/Context-ID.h>
#include <osmocom/hnbap/Criticality.h>
#include <osmocom/hnbap/CriticalityDiagnostics-IE-List.h>
#include <osmocom/hnbap/CriticalityDiagnostics.h>
#include <osmocom/hnbap/ESN.h>
#include <osmocom/hnbap/ErrorIndication.h>
#include <osmocom/hnbap/GTP-TEI.h>
#include <osmocom/hnbap/GeographicalCoordinates.h>
#include <osmocom/hnbap/GeographicalLocation.h>
#include <osmocom/hnbap/HNB-Cell-Access-Mode.h>
#include <osmocom/hnbap/HNB-Cell-Identifier.h>
#include <osmocom/hnbap/HNB-GWResponse.h>
#include <osmocom/hnbap/HNB-Identity-Info.h>
#include <osmocom/hnbap/HNB-Identity.h>
#include <osmocom/hnbap/HNB-Location-Information.h>
#include <osmocom/hnbap/HNB-RNL-Identity.h>
#include <osmocom/hnbap/HNBAP-PDU.h>
#include <osmocom/hnbap/HNBCapacity.h>
#include <osmocom/hnbap/HNBConfigInfo.h>
#include <osmocom/hnbap/HNBConfigTransferRequest.h>
#include <osmocom/hnbap/HNBConfigTransferResponse.h>
#include <osmocom/hnbap/HNBConfigurationInformationMissing.h>
#include <osmocom/hnbap/HNBConfigurationInformationProvided.h>
#include <osmocom/hnbap/HNBDe-Register.h>
#include <osmocom/hnbap/HNBRegisterAccept.h>
#include <osmocom/hnbap/HNBRegisterReject.h>
#include <osmocom/hnbap/HNBRegisterRequest.h>
#include <osmocom/hnbap/IE-Extensions.h>
#include <osmocom/hnbap/IE.h>
#include <osmocom/hnbap/IMEI.h>
#include <osmocom/hnbap/IMSI.h>
#include <osmocom/hnbap/IMSIDS41.h>
#include <osmocom/hnbap/IMSIESN.h>
#include <osmocom/hnbap/IP-Address.h>
#include <osmocom/hnbap/InitiatingMessage.h>
#include <osmocom/hnbap/Ipv4Address.h>
#include <osmocom/hnbap/Ipv6Address.h>
#include <osmocom/hnbap/Iurh-Signalling-TNL-AddressList.h>
#include <osmocom/hnbap/LAC.h>
#include <osmocom/hnbap/LAI.h>
#include <osmocom/hnbap/MacroCellID.h>
#include <osmocom/hnbap/MacroCoverageInformation.h>
#include <osmocom/hnbap/MuxPortNumber.h>
#include <osmocom/hnbap/NeighbourCellIdentityList.h>
#include <osmocom/hnbap/NeighbourIdentity.h>
#include <osmocom/hnbap/NeighbourInfoList.h>
#include <osmocom/hnbap/NeighbourInfoRequestItem.h>
#include <osmocom/hnbap/NeighbourInfoRequestList.h>
#include <osmocom/hnbap/PLMNidentity.h>
#include <osmocom/hnbap/PSC.h>
#include <osmocom/hnbap/PTMSI.h>
#include <osmocom/hnbap/PTMSIRAI.h>
#include <osmocom/hnbap/Presence.h>
#include <osmocom/hnbap/PrivateIE-ID.h>
#include <osmocom/hnbap/PrivateMessage.h>
#include <osmocom/hnbap/ProcedureCode.h>
#include <osmocom/hnbap/ProtocolIE-ID.h>
#include <osmocom/hnbap/RAB-ID.h>
#include <osmocom/hnbap/RABList.h>
#include <osmocom/hnbap/RABListItem.h>
#include <osmocom/hnbap/RAC.h>
#include <osmocom/hnbap/RAI.h>
#include <osmocom/hnbap/RNC-ID.h>
#include <osmocom/hnbap/Registration-Cause.h>
#include <osmocom/hnbap/RelocationComplete.h>
#include <osmocom/hnbap/S-RNTIPrefix.h>
#include <osmocom/hnbap/SAC.h>
#include <osmocom/hnbap/SuccessfulOutcome.h>
#include <osmocom/hnbap/TMSIDS41.h>
#include <osmocom/hnbap/TMSILAI.h>
#include <osmocom/hnbap/TNLUpdateFailure.h>
#include <osmocom/hnbap/TNLUpdateRequest.h>
#include <osmocom/hnbap/TNLUpdateResponse.h>
#include <osmocom/hnbap/TransportInfo.h>
#include <osmocom/hnbap/TransportLayerAddress.h>
#include <osmocom/hnbap/TriggeringMessage.h>
#include <osmocom/hnbap/Tunnel-Information.h>
#include <osmocom/hnbap/TypeOfError.h>
#include <osmocom/hnbap/U-RNTI.h>
#include <osmocom/hnbap/U-RNTIQueryRequest.h>
#include <osmocom/hnbap/U-RNTIQueryResponse.h>
#include <osmocom/hnbap/UDP-Port-Number.h>
#include <osmocom/hnbap/UE-Capabilities.h>
#include <osmocom/hnbap/UE-Identity.h>
#include <osmocom/hnbap/UEDe-Register.h>
#include <osmocom/hnbap/UERegisterAccept.h>
#include <osmocom/hnbap/UERegisterReject.h>
#include <osmocom/hnbap/UERegisterRequest.h>
#include <osmocom/hnbap/URAIdentity.h>
#include <osmocom/hnbap/URAIdentityList.h>
#include <osmocom/hnbap/UTRANCellID.h>
#include <osmocom/hnbap/UnknownU-RNTIIndication.h>
#include <osmocom/hnbap/UnsuccessfulOutcome.h>
#include <osmocom/hnbap/Update-cause.h>

#if (ASN1C_ENVIRONMENT_VERSION < 924)
# error "You are compiling with the wrong version of ASN1C"
#endif

#include <osmocom/core/logging.h>

#define HNBAP_DEBUG(x, args ...) DEBUGP(1, x, ## args)

extern int asn1_xer_print;

struct msgb *hnbap_generate_initiating_message(
					 e_ProcedureCode procedureCode,
					 Criticality_t criticality,
					 asn_TYPE_descriptor_t * td, void *sptr);

struct msgb *hnbap_generate_successful_outcome(
					   e_ProcedureCode procedureCode,
					   Criticality_t criticality,
					   asn_TYPE_descriptor_t * td,
					   void *sptr);

struct msgb *hnbap_generate_unsuccessful_outcome(
					   e_ProcedureCode procedureCode,
					   Criticality_t criticality,
					   asn_TYPE_descriptor_t * td,
					   void *sptr);

IE_t *hnbap_new_ie(ProtocolIE_ID_t id, Criticality_t criticality,
		  asn_TYPE_descriptor_t *type, void *sptr);

char *hnbap_cause_str(Cause_t *cause);
