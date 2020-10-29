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
 * Created on: 2015-08-29 14:31:31.107080 by laforge
 * from ['../RUA-CommonDataTypes.asn', '../RUA-Constants.asn', '../RUA-Containers.asn', '../RUA-IEs.asn', '../RUA-PDU-Contents.asn', '../RUA-PDU-Descriptions.asn']
 ******************************************************************************/
#include "rua_common.h"

#ifndef RUA_IES_DEFS_H_
#define RUA_IES_DEFS_H_

#define CONNECTIES_INTRADOMAINNASNODESELECTOR_PRESENT (1 << 0)

typedef struct ConnectIEs_s {
    uint16_t                     presenceMask;
    CN_DomainIndicator_t         cN_DomainIndicator;
    Context_ID_t                 context_ID;
    IntraDomainNasNodeSelector_t intraDomainNasNodeSelector; ///< Optional field
    Establishment_Cause_t        establishment_Cause;
    RANAP_Message_t              ranaP_Message;
} ConnectIEs_t;

#define DISCONNECTIES_RANAP_MESSAGE_PRESENT      (1 << 0)

typedef struct DisconnectIEs_s {
    uint16_t             presenceMask;
    CN_DomainIndicator_t cN_DomainIndicator;
    Context_ID_t         context_ID;
    Cause_t              cause;
    RANAP_Message_t      ranaP_Message; ///< Conditional field
} DisconnectIEs_t;

#define ERRORINDICATIONIES_CRITICALITYDIAGNOSTICS_PRESENT (1 << 0)

typedef struct ErrorIndicationIEs_s {
    uint16_t                 presenceMask;
    Cause_t                  cause;
    CriticalityDiagnostics_t criticalityDiagnostics; ///< Optional field
} ErrorIndicationIEs_t;

typedef struct ConnectionlessTransferIEs_s {
    RANAP_Message_t ranaP_Message;
} ConnectionlessTransferIEs_t;

typedef struct DirectTransferIEs_s {
    CN_DomainIndicator_t cN_DomainIndicator;
    Context_ID_t         context_ID;
    RANAP_Message_t      ranaP_Message;
} DirectTransferIEs_t;

typedef struct rua_message_s {
    uint8_t procedureCode;
    uint8_t criticality;
    uint8_t direction;
    union {
        ConnectIEs_t connectIEs;
        ConnectionlessTransferIEs_t connectionlessTransferIEs;
        DirectTransferIEs_t directTransferIEs;
        DisconnectIEs_t disconnectIEs;
        ErrorIndicationIEs_t errorIndicationIEs;
    } msg;
} rua_message;

/** \brief Decode function for ConnectIEs ies.
 * \param connectIEs Pointer to ASN1 structure in which data will be stored
 *  \param any_p Pointer to the ANY value to decode.
 **/
int rua_decode_connecties(
    ConnectIEs_t *connectIEs,
    ANY_t *any_p);

/** \brief Encode function for ConnectIEs ies.
 *  \param connect Pointer to the ASN1 structure.
 *  \param connectIEs Pointer to the IES structure.
 **/
int rua_encode_connecties(
    Connect_t *connect,
    ConnectIEs_t *connectIEs);

/** \brief Decode function for DisconnectIEs ies.
 * \param disconnectIEs Pointer to ASN1 structure in which data will be stored
 *  \param any_p Pointer to the ANY value to decode.
 **/
int rua_decode_disconnecties(
    DisconnectIEs_t *disconnectIEs,
    ANY_t *any_p);

/** \brief Encode function for DisconnectIEs ies.
 *  \param disconnect Pointer to the ASN1 structure.
 *  \param disconnectIEs Pointer to the IES structure.
 **/
int rua_encode_disconnecties(
    Disconnect_t *disconnect,
    DisconnectIEs_t *disconnectIEs);

/** \brief Decode function for ErrorIndicationIEs ies.
 * \param errorIndicationIEs Pointer to ASN1 structure in which data will be stored
 *  \param any_p Pointer to the ANY value to decode.
 **/
int rua_decode_errorindicationies(
    ErrorIndicationIEs_t *errorIndicationIEs,
    ANY_t *any_p);

/** \brief Encode function for ErrorIndicationIEs ies.
 *  \param errorIndication Pointer to the ASN1 structure.
 *  \param errorIndicationIEs Pointer to the IES structure.
 **/
int rua_encode_errorindicationies(
    ErrorIndication_t *errorIndication,
    ErrorIndicationIEs_t *errorIndicationIEs);

/** \brief Decode function for ConnectionlessTransferIEs ies.
 * \param connectionlessTransferIEs Pointer to ASN1 structure in which data will be stored
 *  \param any_p Pointer to the ANY value to decode.
 **/
int rua_decode_connectionlesstransferies(
    ConnectionlessTransferIEs_t *connectionlessTransferIEs,
    ANY_t *any_p);

/** \brief Encode function for ConnectionlessTransferIEs ies.
 *  \param connectionlessTransfer Pointer to the ASN1 structure.
 *  \param connectionlessTransferIEs Pointer to the IES structure.
 **/
int rua_encode_connectionlesstransferies(
    ConnectionlessTransfer_t *connectionlessTransfer,
    ConnectionlessTransferIEs_t *connectionlessTransferIEs);

/** \brief Decode function for DirectTransferIEs ies.
 * \param directTransferIEs Pointer to ASN1 structure in which data will be stored
 *  \param any_p Pointer to the ANY value to decode.
 **/
int rua_decode_directtransferies(
    DirectTransferIEs_t *directTransferIEs,
    ANY_t *any_p);

/** \brief Encode function for DirectTransferIEs ies.
 *  \param directTransfer Pointer to the ASN1 structure.
 *  \param directTransferIEs Pointer to the IES structure.
 **/
int rua_encode_directtransferies(
    DirectTransfer_t *directTransfer,
    DirectTransferIEs_t *directTransferIEs);

#endif /* RUA_IES_DEFS_H_ */

