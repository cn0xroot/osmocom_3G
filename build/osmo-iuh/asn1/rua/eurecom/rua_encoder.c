/*******************************************************************************

  Eurecom OpenAirInterface
  Copyright(c) 1999 - 2012 Eurecom

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information
  Openair Admin: openair_admin@eurecom.fr
  Openair Tech : openair_tech@eurecom.fr
  Forums       : http://forums.eurecom.fr/openairinterface
  Address      : EURECOM, Campus SophiaTech, 450 Route des Chappes
                 06410 Biot FRANCE

*******************************************************************************/

/*******************************************************************************
 * This file had been created by asn1tostruct.py script v0.5
 * Please do not modify this file but regenerate it via script.
 * Created on: 2015-08-29 14:31:31.110934 by laforge
 * from ['../RUA-CommonDataTypes.asn', '../RUA-Constants.asn', '../RUA-Containers.asn', '../RUA-IEs.asn', '../RUA-PDU-Contents.asn', '../RUA-PDU-Descriptions.asn']
 ******************************************************************************/
#include "rua_common.h"
#include "rua_ies_defs.h"

int rua_encode_connecties(
    Connect_t *connect,
    ConnectIEs_t *connectIEs) {

    IE_t *ie;

    if ((ie = rua_new_ie(ProtocolIE_ID_id_CN_DomainIndicator,
                          Criticality_reject,
                          &asn_DEF_CN_DomainIndicator,
                          &connectIEs->cN_DomainIndicator)) == NULL) {
        return -1;
    }
    ASN_SEQUENCE_ADD(&connect->connect_ies.list, ie);

    if ((ie = rua_new_ie(ProtocolIE_ID_id_Context_ID,
                          Criticality_reject,
                          &asn_DEF_Context_ID,
                          &connectIEs->context_ID)) == NULL) {
        return -1;
    }
    ASN_SEQUENCE_ADD(&connect->connect_ies.list, ie);

    /* Optional field */
    if ((connectIEs->presenceMask & CONNECTIES_INTRADOMAINNASNODESELECTOR_PRESENT)
        == CONNECTIES_INTRADOMAINNASNODESELECTOR_PRESENT) {
        if ((ie = rua_new_ie(ProtocolIE_ID_id_IntraDomainNasNodeSelector,
                              Criticality_ignore,
                              &asn_DEF_IntraDomainNasNodeSelector,
                              &connectIEs->intraDomainNasNodeSelector)) == NULL) {
            return -1;
        }
        ASN_SEQUENCE_ADD(&connect->connect_ies.list, ie);
    }

    if ((ie = rua_new_ie(ProtocolIE_ID_id_Establishment_Cause,
                          Criticality_reject,
                          &asn_DEF_Establishment_Cause,
                          &connectIEs->establishment_Cause)) == NULL) {
        return -1;
    }
    ASN_SEQUENCE_ADD(&connect->connect_ies.list, ie);

    if ((ie = rua_new_ie(ProtocolIE_ID_id_RANAP_Message,
                          Criticality_reject,
                          &asn_DEF_RANAP_Message,
                          &connectIEs->ranaP_Message)) == NULL) {
        return -1;
    }
    ASN_SEQUENCE_ADD(&connect->connect_ies.list, ie);

    return 0;
}

int rua_encode_disconnecties(
    Disconnect_t *disconnect,
    DisconnectIEs_t *disconnectIEs) {

    IE_t *ie;

    if ((ie = rua_new_ie(ProtocolIE_ID_id_CN_DomainIndicator,
                          Criticality_reject,
                          &asn_DEF_CN_DomainIndicator,
                          &disconnectIEs->cN_DomainIndicator)) == NULL) {
        return -1;
    }
    ASN_SEQUENCE_ADD(&disconnect->disconnect_ies.list, ie);

    if ((ie = rua_new_ie(ProtocolIE_ID_id_Context_ID,
                          Criticality_reject,
                          &asn_DEF_Context_ID,
                          &disconnectIEs->context_ID)) == NULL) {
        return -1;
    }
    ASN_SEQUENCE_ADD(&disconnect->disconnect_ies.list, ie);

    if ((ie = rua_new_ie(ProtocolIE_ID_id_Cause,
                          Criticality_reject,
                          &asn_DEF_Cause,
                          &disconnectIEs->cause)) == NULL) {
        return -1;
    }
    ASN_SEQUENCE_ADD(&disconnect->disconnect_ies.list, ie);

    /* Conditional field */
    if ((disconnectIEs->presenceMask & DISCONNECTIES_RANAP_MESSAGE_PRESENT)
        == DISCONNECTIES_RANAP_MESSAGE_PRESENT) {
        if ((ie = rua_new_ie(ProtocolIE_ID_id_RANAP_Message,
                              Criticality_reject,
                              &asn_DEF_RANAP_Message,
                              &disconnectIEs->ranaP_Message)) == NULL) {
            return -1;
        }
        ASN_SEQUENCE_ADD(&disconnect->disconnect_ies.list, ie);
    }

    return 0;
}

int rua_encode_errorindicationies(
    ErrorIndication_t *errorIndication,
    ErrorIndicationIEs_t *errorIndicationIEs) {

    IE_t *ie;

    if ((ie = rua_new_ie(ProtocolIE_ID_id_Cause,
                          Criticality_ignore,
                          &asn_DEF_Cause,
                          &errorIndicationIEs->cause)) == NULL) {
        return -1;
    }
    ASN_SEQUENCE_ADD(&errorIndication->errorIndication_ies.list, ie);

    /* Optional field */
    if ((errorIndicationIEs->presenceMask & ERRORINDICATIONIES_CRITICALITYDIAGNOSTICS_PRESENT)
        == ERRORINDICATIONIES_CRITICALITYDIAGNOSTICS_PRESENT) {
        if ((ie = rua_new_ie(ProtocolIE_ID_id_CriticalityDiagnostics,
                              Criticality_ignore,
                              &asn_DEF_CriticalityDiagnostics,
                              &errorIndicationIEs->criticalityDiagnostics)) == NULL) {
            return -1;
        }
        ASN_SEQUENCE_ADD(&errorIndication->errorIndication_ies.list, ie);
    }

    return 0;
}

int rua_encode_connectionlesstransferies(
    ConnectionlessTransfer_t *connectionlessTransfer,
    ConnectionlessTransferIEs_t *connectionlessTransferIEs) {

    IE_t *ie;

    if ((ie = rua_new_ie(ProtocolIE_ID_id_RANAP_Message,
                          Criticality_reject,
                          &asn_DEF_RANAP_Message,
                          &connectionlessTransferIEs->ranaP_Message)) == NULL) {
        return -1;
    }
    ASN_SEQUENCE_ADD(&connectionlessTransfer->connectionlessTransfer_ies.list, ie);

    return 0;
}

int rua_encode_directtransferies(
    DirectTransfer_t *directTransfer,
    DirectTransferIEs_t *directTransferIEs) {

    IE_t *ie;

    if ((ie = rua_new_ie(ProtocolIE_ID_id_CN_DomainIndicator,
                          Criticality_reject,
                          &asn_DEF_CN_DomainIndicator,
                          &directTransferIEs->cN_DomainIndicator)) == NULL) {
        return -1;
    }
    ASN_SEQUENCE_ADD(&directTransfer->directTransfer_ies.list, ie);

    if ((ie = rua_new_ie(ProtocolIE_ID_id_Context_ID,
                          Criticality_reject,
                          &asn_DEF_Context_ID,
                          &directTransferIEs->context_ID)) == NULL) {
        return -1;
    }
    ASN_SEQUENCE_ADD(&directTransfer->directTransfer_ies.list, ie);

    if ((ie = rua_new_ie(ProtocolIE_ID_id_RANAP_Message,
                          Criticality_reject,
                          &asn_DEF_RANAP_Message,
                          &directTransferIEs->ranaP_Message)) == NULL) {
        return -1;
    }
    ASN_SEQUENCE_ADD(&directTransfer->directTransfer_ies.list, ie);

    return 0;
}

