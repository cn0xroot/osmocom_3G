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
 * Created on: 2015-08-29 14:31:31.109013 by laforge
 * from ['../RUA-CommonDataTypes.asn', '../RUA-Constants.asn', '../RUA-Containers.asn', '../RUA-IEs.asn', '../RUA-PDU-Contents.asn', '../RUA-PDU-Descriptions.asn']
 ******************************************************************************/
#include "rua_common.h"
#include "rua_ies_defs.h"

int rua_decode_connecties(
    ConnectIEs_t *connectIEs,
    ANY_t *any_p) {

    Connect_t  connect;
    Connect_t *connect_p = &connect;
    int i, decoded = 0;
    int tempDecoded = 0;
    assert(any_p != NULL);
    assert(connectIEs != NULL);

    RUA_DEBUG("Decoding message ConnectIEs (%s:%d)\n", __FILE__, __LINE__);

    ANY_to_type_aper(any_p, &asn_DEF_Connect, (void**)&connect_p);

    for (i = 0; i < connect_p->connect_ies.list.count; i++) {
        IE_t *ie_p;
        ie_p = connect_p->connect_ies.list.array[i];
        switch(ie_p->id) {
            case ProtocolIE_ID_id_CN_DomainIndicator:
            {
                CN_DomainIndicator_t  cnDomainIndicator;
                CN_DomainIndicator_t *cnDomainIndicator_p = &cnDomainIndicator;
                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_CN_DomainIndicator, (void**)&cnDomainIndicator_p);
                if (tempDecoded < 0) {
                    RUA_DEBUG("Decoding of IE cN_DomainIndicator failed\n");
                    return -1;
                }
                decoded += tempDecoded;
                if (asn1_xer_print)
                    xer_fprint(stdout, &asn_DEF_CN_DomainIndicator, cnDomainIndicator_p);
                memcpy(&connectIEs->cN_DomainIndicator, cnDomainIndicator_p, sizeof(CN_DomainIndicator_t));
            } break;
            case ProtocolIE_ID_id_Context_ID:
            {
                Context_ID_t  contextID;
                Context_ID_t *contextID_p = &contextID;
                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_Context_ID, (void**)&contextID_p);
                if (tempDecoded < 0) {
                    RUA_DEBUG("Decoding of IE context_ID failed\n");
                    return -1;
                }
                decoded += tempDecoded;
                if (asn1_xer_print)
                    xer_fprint(stdout, &asn_DEF_Context_ID, contextID_p);
                memcpy(&connectIEs->context_ID, contextID_p, sizeof(Context_ID_t));
            } break;
            /* Optional field */
            case ProtocolIE_ID_id_IntraDomainNasNodeSelector:
            {
                IntraDomainNasNodeSelector_t  intraDomainNasNodeSelector;
                IntraDomainNasNodeSelector_t *intraDomainNasNodeSelector_p = &intraDomainNasNodeSelector;
                connectIEs->presenceMask |= CONNECTIES_INTRADOMAINNASNODESELECTOR_PRESENT;
                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_IntraDomainNasNodeSelector, (void**)&intraDomainNasNodeSelector_p);
                if (tempDecoded < 0) {
                    RUA_DEBUG("Decoding of IE intraDomainNasNodeSelector failed\n");
                    return -1;
                }
                decoded += tempDecoded;
                if (asn1_xer_print)
                    xer_fprint(stdout, &asn_DEF_IntraDomainNasNodeSelector, intraDomainNasNodeSelector_p);
                memcpy(&connectIEs->intraDomainNasNodeSelector, intraDomainNasNodeSelector_p, sizeof(IntraDomainNasNodeSelector_t));
            } break;
            case ProtocolIE_ID_id_Establishment_Cause:
            {
                Establishment_Cause_t  establishmentCause;
                Establishment_Cause_t *establishmentCause_p = &establishmentCause;
                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_Establishment_Cause, (void**)&establishmentCause_p);
                if (tempDecoded < 0) {
                    RUA_DEBUG("Decoding of IE establishment_Cause failed\n");
                    return -1;
                }
                decoded += tempDecoded;
                if (asn1_xer_print)
                    xer_fprint(stdout, &asn_DEF_Establishment_Cause, establishmentCause_p);
                memcpy(&connectIEs->establishment_Cause, establishmentCause_p, sizeof(Establishment_Cause_t));
            } break;
            case ProtocolIE_ID_id_RANAP_Message:
            {
                RANAP_Message_t  ranapMessage;
                RANAP_Message_t *ranapMessage_p = &ranapMessage;
                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_RANAP_Message, (void**)&ranapMessage_p);
                if (tempDecoded < 0) {
                    RUA_DEBUG("Decoding of IE ranaP_Message failed\n");
                    return -1;
                }
                decoded += tempDecoded;
                if (asn1_xer_print)
                    xer_fprint(stdout, &asn_DEF_RANAP_Message, ranapMessage_p);
                memcpy(&connectIEs->ranaP_Message, ranapMessage_p, sizeof(RANAP_Message_t));
            } break;
            default:
                RUA_DEBUG("Unknown protocol IE id (%d) for message connecties\n", (int)ie_p->id);
                return -1;
        }
    }
    return decoded;
}

int rua_decode_disconnecties(
    DisconnectIEs_t *disconnectIEs,
    ANY_t *any_p) {

    Disconnect_t  disconnect;
    Disconnect_t *disconnect_p = &disconnect;
    int i, decoded = 0;
    int tempDecoded = 0;
    assert(any_p != NULL);
    assert(disconnectIEs != NULL);

    RUA_DEBUG("Decoding message DisconnectIEs (%s:%d)\n", __FILE__, __LINE__);

    ANY_to_type_aper(any_p, &asn_DEF_Disconnect, (void**)&disconnect_p);

    for (i = 0; i < disconnect_p->disconnect_ies.list.count; i++) {
        IE_t *ie_p;
        ie_p = disconnect_p->disconnect_ies.list.array[i];
        switch(ie_p->id) {
            case ProtocolIE_ID_id_CN_DomainIndicator:
            {
                CN_DomainIndicator_t  cnDomainIndicator;
                CN_DomainIndicator_t *cnDomainIndicator_p = &cnDomainIndicator;
                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_CN_DomainIndicator, (void**)&cnDomainIndicator_p);
                if (tempDecoded < 0) {
                    RUA_DEBUG("Decoding of IE cN_DomainIndicator failed\n");
                    return -1;
                }
                decoded += tempDecoded;
                if (asn1_xer_print)
                    xer_fprint(stdout, &asn_DEF_CN_DomainIndicator, cnDomainIndicator_p);
                memcpy(&disconnectIEs->cN_DomainIndicator, cnDomainIndicator_p, sizeof(CN_DomainIndicator_t));
            } break;
            case ProtocolIE_ID_id_Context_ID:
            {
                Context_ID_t  contextID;
                Context_ID_t *contextID_p = &contextID;
                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_Context_ID, (void**)&contextID_p);
                if (tempDecoded < 0) {
                    RUA_DEBUG("Decoding of IE context_ID failed\n");
                    return -1;
                }
                decoded += tempDecoded;
                if (asn1_xer_print)
                    xer_fprint(stdout, &asn_DEF_Context_ID, contextID_p);
                memcpy(&disconnectIEs->context_ID, contextID_p, sizeof(Context_ID_t));
            } break;
            case ProtocolIE_ID_id_Cause:
            {
                Cause_t  cause;
                Cause_t *cause_p = &cause;
                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_Cause, (void**)&cause_p);
                if (tempDecoded < 0) {
                    RUA_DEBUG("Decoding of IE cause failed\n");
                    return -1;
                }
                decoded += tempDecoded;
                if (asn1_xer_print)
                    xer_fprint(stdout, &asn_DEF_Cause, cause_p);
                memcpy(&disconnectIEs->cause, cause_p, sizeof(Cause_t));
            } break;
            /* Conditional field */
            case ProtocolIE_ID_id_RANAP_Message:
            {
                RANAP_Message_t  ranapMessage;
                RANAP_Message_t *ranapMessage_p = &ranapMessage;
                disconnectIEs->presenceMask |= DISCONNECTIES_RANAP_MESSAGE_PRESENT;
                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_RANAP_Message, (void**)&ranapMessage_p);
                if (tempDecoded < 0) {
                    RUA_DEBUG("Decoding of IE ranaP_Message failed\n");
                    return -1;
                }
                decoded += tempDecoded;
                if (asn1_xer_print)
                    xer_fprint(stdout, &asn_DEF_RANAP_Message, ranapMessage_p);
                memcpy(&disconnectIEs->ranaP_Message, ranapMessage_p, sizeof(RANAP_Message_t));
            } break;
            default:
                RUA_DEBUG("Unknown protocol IE id (%d) for message disconnecties\n", (int)ie_p->id);
                return -1;
        }
    }
    return decoded;
}

int rua_decode_errorindicationies(
    ErrorIndicationIEs_t *errorIndicationIEs,
    ANY_t *any_p) {

    ErrorIndication_t  errorIndication;
    ErrorIndication_t *errorIndication_p = &errorIndication;
    int i, decoded = 0;
    int tempDecoded = 0;
    assert(any_p != NULL);
    assert(errorIndicationIEs != NULL);

    RUA_DEBUG("Decoding message ErrorIndicationIEs (%s:%d)\n", __FILE__, __LINE__);

    ANY_to_type_aper(any_p, &asn_DEF_ErrorIndication, (void**)&errorIndication_p);

    for (i = 0; i < errorIndication_p->errorIndication_ies.list.count; i++) {
        IE_t *ie_p;
        ie_p = errorIndication_p->errorIndication_ies.list.array[i];
        switch(ie_p->id) {
            case ProtocolIE_ID_id_Cause:
            {
                Cause_t  cause;
                Cause_t *cause_p = &cause;
                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_Cause, (void**)&cause_p);
                if (tempDecoded < 0) {
                    RUA_DEBUG("Decoding of IE cause failed\n");
                    return -1;
                }
                decoded += tempDecoded;
                if (asn1_xer_print)
                    xer_fprint(stdout, &asn_DEF_Cause, cause_p);
                memcpy(&errorIndicationIEs->cause, cause_p, sizeof(Cause_t));
            } break;
            /* Optional field */
            case ProtocolIE_ID_id_CriticalityDiagnostics:
            {
                CriticalityDiagnostics_t  criticalityDiagnostics;
                CriticalityDiagnostics_t *criticalityDiagnostics_p = &criticalityDiagnostics;
                errorIndicationIEs->presenceMask |= ERRORINDICATIONIES_CRITICALITYDIAGNOSTICS_PRESENT;
                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_CriticalityDiagnostics, (void**)&criticalityDiagnostics_p);
                if (tempDecoded < 0) {
                    RUA_DEBUG("Decoding of IE criticalityDiagnostics failed\n");
                    return -1;
                }
                decoded += tempDecoded;
                if (asn1_xer_print)
                    xer_fprint(stdout, &asn_DEF_CriticalityDiagnostics, criticalityDiagnostics_p);
                memcpy(&errorIndicationIEs->criticalityDiagnostics, criticalityDiagnostics_p, sizeof(CriticalityDiagnostics_t));
            } break;
            default:
                RUA_DEBUG("Unknown protocol IE id (%d) for message errorindicationies\n", (int)ie_p->id);
                return -1;
        }
    }
    return decoded;
}

int rua_decode_connectionlesstransferies(
    ConnectionlessTransferIEs_t *connectionlessTransferIEs,
    ANY_t *any_p) {

    ConnectionlessTransfer_t  connectionlessTransfer;
    ConnectionlessTransfer_t *connectionlessTransfer_p = &connectionlessTransfer;
    int i, decoded = 0;
    int tempDecoded = 0;
    assert(any_p != NULL);
    assert(connectionlessTransferIEs != NULL);

    RUA_DEBUG("Decoding message ConnectionlessTransferIEs (%s:%d)\n", __FILE__, __LINE__);

    ANY_to_type_aper(any_p, &asn_DEF_ConnectionlessTransfer, (void**)&connectionlessTransfer_p);

    for (i = 0; i < connectionlessTransfer_p->connectionlessTransfer_ies.list.count; i++) {
        IE_t *ie_p;
        ie_p = connectionlessTransfer_p->connectionlessTransfer_ies.list.array[i];
        switch(ie_p->id) {
            case ProtocolIE_ID_id_RANAP_Message:
            {
                RANAP_Message_t  ranapMessage;
                RANAP_Message_t *ranapMessage_p = &ranapMessage;
                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_RANAP_Message, (void**)&ranapMessage_p);
                if (tempDecoded < 0) {
                    RUA_DEBUG("Decoding of IE ranaP_Message failed\n");
                    return -1;
                }
                decoded += tempDecoded;
                if (asn1_xer_print)
                    xer_fprint(stdout, &asn_DEF_RANAP_Message, ranapMessage_p);
                memcpy(&connectionlessTransferIEs->ranaP_Message, ranapMessage_p, sizeof(RANAP_Message_t));
            } break;
            default:
                RUA_DEBUG("Unknown protocol IE id (%d) for message connectionlesstransferies\n", (int)ie_p->id);
                return -1;
        }
    }
    return decoded;
}

int rua_decode_directtransferies(
    DirectTransferIEs_t *directTransferIEs,
    ANY_t *any_p) {

    DirectTransfer_t  directTransfer;
    DirectTransfer_t *directTransfer_p = &directTransfer;
    int i, decoded = 0;
    int tempDecoded = 0;
    assert(any_p != NULL);
    assert(directTransferIEs != NULL);

    RUA_DEBUG("Decoding message DirectTransferIEs (%s:%d)\n", __FILE__, __LINE__);

    ANY_to_type_aper(any_p, &asn_DEF_DirectTransfer, (void**)&directTransfer_p);

    for (i = 0; i < directTransfer_p->directTransfer_ies.list.count; i++) {
        IE_t *ie_p;
        ie_p = directTransfer_p->directTransfer_ies.list.array[i];
        switch(ie_p->id) {
            case ProtocolIE_ID_id_CN_DomainIndicator:
            {
                CN_DomainIndicator_t  cnDomainIndicator;
                CN_DomainIndicator_t *cnDomainIndicator_p = &cnDomainIndicator;
                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_CN_DomainIndicator, (void**)&cnDomainIndicator_p);
                if (tempDecoded < 0) {
                    RUA_DEBUG("Decoding of IE cN_DomainIndicator failed\n");
                    return -1;
                }
                decoded += tempDecoded;
                if (asn1_xer_print)
                    xer_fprint(stdout, &asn_DEF_CN_DomainIndicator, cnDomainIndicator_p);
                memcpy(&directTransferIEs->cN_DomainIndicator, cnDomainIndicator_p, sizeof(CN_DomainIndicator_t));
            } break;
            case ProtocolIE_ID_id_Context_ID:
            {
                Context_ID_t  contextID;
                Context_ID_t *contextID_p = &contextID;
                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_Context_ID, (void**)&contextID_p);
                if (tempDecoded < 0) {
                    RUA_DEBUG("Decoding of IE context_ID failed\n");
                    return -1;
                }
                decoded += tempDecoded;
                if (asn1_xer_print)
                    xer_fprint(stdout, &asn_DEF_Context_ID, contextID_p);
                memcpy(&directTransferIEs->context_ID, contextID_p, sizeof(Context_ID_t));
            } break;
            case ProtocolIE_ID_id_RANAP_Message:
            {
                RANAP_Message_t  ranapMessage;
                RANAP_Message_t *ranapMessage_p = &ranapMessage;
                tempDecoded = ANY_to_type_aper(&ie_p->value, &asn_DEF_RANAP_Message, (void**)&ranapMessage_p);
                if (tempDecoded < 0) {
                    RUA_DEBUG("Decoding of IE ranaP_Message failed\n");
                    return -1;
                }
                decoded += tempDecoded;
                if (asn1_xer_print)
                    xer_fprint(stdout, &asn_DEF_RANAP_Message, ranapMessage_p);
                memcpy(&directTransferIEs->ranaP_Message, ranapMessage_p, sizeof(RANAP_Message_t));
            } break;
            default:
                RUA_DEBUG("Unknown protocol IE id (%d) for message directtransferies\n", (int)ie_p->id);
                return -1;
        }
    }
    return decoded;
}

