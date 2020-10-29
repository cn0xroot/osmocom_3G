
/*
 * Copyright (C) 2006 Raul Tremsal
 * File  : smpp.c
 * Author: Raul Tremsal <ultraismo@yahoo.com>
 *
 * This file is part of libsmpp34 (c-open-smpp3.4 library).
 *
 * The libsmpp34 library is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation; either version 2.1 of the 
 * License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public 
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License 
 * along with this library; if not, write to the Free Software Foundation, 
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <stdint.h>

#include "smpp34.h"
#include "smpp34_structs.h"
#include "smpp34_params.h"

#include "esme.h"

extern int  smpp34_errno;
extern char smpp34_strerror[2048];

uint8_t print_buffer[2048];
uint8_t local_buffer[1024];
int  local_buffer_len = 0;
int  ret = 0;
uint32_t tempo = 0;
uint32_t cmd_id = 0;

int unhex(char c) {
  if (c >= '0' && c <= '9')
    return (c - '0');
  if (c >= 'a' && c <= 'f')
    return (c - 'a' + 10);
  if (c >= 'A' && c <= 'F')
    return (c - 'A' + 10);
  return (-1);
}

int hex2bin(char *hex, unsigned char *bin) {
  int i = 0;
  int j = 0;

  /* Trim string if comments present */
  if (strchr(hex, '#') != NULL)
    *strchr(hex, '#') = 0;
  if (strchr(hex, '*') != NULL)
    *strchr(hex, '*') = 0;
  if (strchr(hex, '\'') != NULL)
    *strchr(hex, '\'') = 0;

  for (i = 0; i < strlen(hex); i++) {
    if (hex[i] >= '0' && unhex(hex[i]) < 0){
      printf("Bad hex digit encountered.\n"); 
      return( -1 );
    }
  }

  for (i = 0; i < strlen(hex); i++) {
    if (hex[i] < '0')
      continue;
    if (hex[i] >= '0' && hex[i+1] >= '0') {
      bin[j++] = unhex(hex[i])*16+unhex(hex[i+1]);
      i++;    // skip one
      continue;
    }
    if (hex[i] >= '0') {
      bin[j++] = unhex(hex[i]);
    }
  }
  return (j);
}

int do_smpp_connect( xmlNodePtr p, int sock_tcp )
{
    bind_transmitter_t      req;
    bind_transmitter_resp_t res;
    memset(&req, 0, sizeof(bind_transmitter_t));
    memset(&res, 0, sizeof(bind_transmitter_resp_t));

    /* Init PDU ***********************************************************/
    req.command_length   = 0;
    req.command_id       = BIND_TRANSMITTER;   
    req.command_status   = ESME_ROK;           
    req.sequence_number  = 1;
    GET_PROP_STR( req.system_id, p, "system_id" );
    GET_PROP_STR( req.password, p, "password" );
    GET_PROP_STR( req.system_type, p, "system_type" );
    req.interface_version = SMPP_VERSION;
#if 0 /* if you need add */
    req.addr_ton          = 2;
    req.addr_npi          = 1;
    snprintf( b.address_range, sizeof(b.address_range), "%s", "");
#endif

    /* FIRST STEP: PACK AND SEND */
#include "pack_and_send.inc"
    /* Set a timer (PENDIENTE) ********************************************/
    /* SECOND STEP: READ AND UNPACK Response */
#include "recv_and_unpack.inc"
    destroy_tlv( res.tlv ); /* Por las dudas */

    if( res.command_id != BIND_TRANSMITTER_RESP ||
        res.command_status != ESME_ROK ){
        printf("Error in BIND(BIND_TRANSMITTER)[%d:%d]\n", 
                                       res.command_id, res.command_status);
        return( -1 );
    };
    return( 0 );
};


int do_smpp_send_message( xmlNodePtr p, int sock_tcp )
{

    char message[256];
    tlv_t tlv;
    submit_sm_t      req;
    submit_sm_resp_t res;
    memset(&req, 0, sizeof(submit_sm_t));
    memset(&res, 0, sizeof(submit_sm_resp_t));

    /* Init PDU ***********************************************************/
    req.command_length   = 0;
    req.command_id       = SUBMIT_SM;
    req.command_status   = ESME_ROK;
    req.sequence_number  = 2;
#if 0 /* if you need this */
    snprintf(b.service_type, sizeof(b.service_type), "%s", "SMS");
    b.source_addr_ton  = 2;
    b.source_addr_npi  = 1;
#endif
    GET_PROP_STR( req.source_addr, p, "src" );
#if 0 /* if you need this */
    b.dest_addr_ton    = 2;
    b.dest_addr_npi    = 0;
#endif
    GET_PROP_STR( req.destination_addr, p, "dst" );
#if 0 /* if you need this */
    b.esm_class        = 0;
    b.protocol_id      = 0;
    b.priority_flag    = 0;
    snprintf( b.schedule_delivery_time, TIME_LENGTH, "%s", "");
    snprintf( b.validity_period, TIME_LENGTH, "%s", "");
    b.registered_delivery = 0;
    b.replace_if_present_flag =0;
    b.data_coding         = 0;
    b.sm_default_msg_id   = 0;
#endif
    GET_PROP_STR( message, p, "msg" );

#if 0 /* Message in short_message scope */
    b.sm_length           = strlen(TEXTO);
    memcpy(b.short_message, TEXTO, b.sm_length);
#else /* Message in Payload */
    tlv.tag = TLVID_message_payload;
    tlv.length = strlen(message);
    memcpy(tlv.value.octet, message, tlv.length);
    build_tlv( &(req.tlv), &tlv );
#endif

    /* Add other optional param */
    tlv.tag = TLVID_user_message_reference;
    tlv.length = sizeof(uint16_t);
    tlv.value.val16 = 0x0024;
    build_tlv( &(req.tlv), &tlv );

    /* FIRST STEP: PACK AND SEND */
#include "pack_and_send.inc"
    destroy_tlv( req.tlv ); /* Por las dudas */
    /* Set a timer (PENDIENTE) ********************************************/
    /* SECOND STEP: READ AND UNPACK Response */
#include "recv_and_unpack.inc"

    if( res.command_id != SUBMIT_SM_RESP ||
        res.command_status != ESME_ROK ){
        printf("Error in send(SUBMIT_SM)[%08X:%08X]\n", 
                                       res.command_id, res.command_status);
        return( -1 );
    };
    return( 0 );
};


int do_smpp_send_message2( xmlNodePtr p, int sock_tcp, int sequence )
{

    char message[512];
    submit_sm_t      req;
    submit_sm_resp_t res;
    memset(&req, 0, sizeof(submit_sm_t));
    memset(&res, 0, sizeof(submit_sm_resp_t));

    /* Init PDU ***********************************************************/
    req.command_length   = 0;
    req.command_id       = SUBMIT_SM;
    req.command_status   = ESME_ROK;
    req.sequence_number  = sequence;
    GET_PROP_STR( req.service_type, p, "service_type" );

    GET_PROP_INT( req.source_addr_ton, p, "source_addr_ton" );
    GET_PROP_INT( req.source_addr_npi, p, "source_addr_npi" );
    GET_PROP_STR( req.source_addr, p, "src" );

    GET_PROP_INT( req.dest_addr_ton, p, "dest_addr_ton" );
    GET_PROP_INT( req.dest_addr_npi, p, "dest_addr_npi" );
    GET_PROP_STR( req.destination_addr, p, "dst" );

    GET_PROP_INT( req.esm_class, p, "esm_class" );
    GET_PROP_INT( req.protocol_id, p, "protocol_id" );
    GET_PROP_INT( req.priority_flag, p, "priority_flag" );
    GET_PROP_STR( req.schedule_delivery_time, p, "schedule_delivery_time" );
    GET_PROP_STR( req.validity_period, p, "validity_period" );
    GET_PROP_INT( req.registered_delivery, p, "registered_delivery" );
    GET_PROP_INT( req.replace_if_present_flag, p, "replace_if_present_flag" );
    GET_PROP_INT( req.data_coding, p, "data_coding" );
    GET_PROP_INT( req.sm_default_msg_id, p, "sm_default_msg_id" );
    GET_PROP_STR( message, p, "hex" );
    req.sm_length = hex2bin(message, req.short_message);

    /* FIRST STEP: PACK AND SEND */
#include "pack_and_send.inc"
    destroy_tlv( req.tlv ); /* Por las dudas */
    /* Set a timer (PENDIENTE) ********************************************/
    /* SECOND STEP: READ AND UNPACK Response */
#include "recv_and_unpack.inc"

    if( res.command_id != SUBMIT_SM_RESP ||
        res.command_status != ESME_ROK ){
        printf("Error in send(SUBMIT_SM)[%d:%d]\n", 
                                       res.command_id, res.command_status);
        return( -1 );
    };
    return( 0 );
};


int do_smpp_close( int sock_tcp )
{
    unbind_t      req;
    unbind_resp_t res;
    memset(&req, 0, sizeof(unbind_t));
    memset(&res, 0, sizeof(unbind_resp_t));

    /* Init PDU ***********************************************************/
    req.command_length   = 0;
    req.command_id       = UNBIND;
    req.command_status   = ESME_ROK;
    req.sequence_number  = 3;

    /* FIRST STEP: PACK AND SEND */
#include "pack_and_send.inc"
    /* Set a timer (PENDIENTE) ********************************************/
    /* SECOND STEP: READ AND UNPACK Response */
#include "recv_and_unpack.inc"

    if( res.command_id != UNBIND_RESP ||
        res.command_status != ESME_ROK ){
        printf("Error in send(UNBIND)[%d:%d]\n", 
                                       res.command_id, res.command_status);
        return( -1 );
    };

    return( 0 );
};
