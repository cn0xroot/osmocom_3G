
/*
 * Copyright (C) 2006 Raul Tremsal
 * File  : submit_multi_test.c
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
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <stdint.h>

#include "smpp34.h"
#include "smpp34_structs.h"
#include "smpp34_params.h"
#include "core.h"

#define TEXTO "Raul Antonio Tremsal"

int
main( int argc, char *argv[] )
{

    submit_multi_t a;
    submit_multi_t b;
    tlv_t tlv;
    dad_t dad;

    memset(&a, 0, sizeof(submit_multi_t));
    memset(&b, 0, sizeof(submit_multi_t));
    memset(&tlv, 0, sizeof(tlv_t));
    memset(&dad, 0, sizeof(dad_t));

    /* Init PDU ***********************************************************/
    b.command_length   = 0;
    b.command_id       = SUBMIT_MULTI;
    b.command_status   = ESME_ROK;
    b.sequence_number  = 1;
    snprintf((char*)b.service_type, sizeof(b.service_type), "%s", "SMS");
    b.source_addr_ton  = 2;
    b.source_addr_npi  = 1;
    snprintf((char*)b.source_addr, sizeof(b.source_addr), "%s", 
                                                   "09000011111");
    /* Destination Addresses Definition ***********************************/
    b.number_of_dests  = 3;

    dad.dest_flag = DFID_SME_Address;                      /* in smpp34.h */
    dad.value.sme.dest_addr_ton = 0;
    dad.value.sme.dest_addr_npi = 0;
    snprintf((char*)dad.value.sme.destination_addr, 
                sizeof(dad.value.sme.destination_addr), "%s", "0900002222");
    build_dad( &(b.dest_addr_def), &dad );

    dad.dest_flag = DFID_Distribution_List_Name;           /* in smpp34.h */
    snprintf((char*)dad.value.dl_name, sizeof(dad.value.dl_name),"%s","list_name_01");
    build_dad( &(b.dest_addr_def), &dad );

    dad.dest_flag = DFID_SME_Address;                      /* in smpp34.h */
    dad.value.sme.dest_addr_ton = 2;
    dad.value.sme.dest_addr_npi = 1;
    snprintf((char*)dad.value.sme.destination_addr, 
                sizeof(dad.value.sme.destination_addr), "%s", "1100007777");
    build_dad( &(b.dest_addr_def), &dad );
    /**********************************************************************/

    b.esm_class        = 0;
    b.protocol_id      = 0;
    b.priority_flag    = 0;
    memset(b.schedule_delivery_time,0,sizeof(b.schedule_delivery_time));
    memset(b.validity_period,0,sizeof(b.validity_period));
    b.registered_delivery = 0;
    b.replace_if_present_flag =0;
    b.data_coding         = 0;
    b.sm_default_msg_id   = 0;
    b.sm_length           = strlen(TEXTO);
    memcpy(b.short_message, TEXTO, b.sm_length);

    tlv.tag = TLVID_user_message_reference;
    tlv.length = sizeof(uint16_t);
    tlv.value.val16 = 0x0024;
    build_tlv( &(b.tlv), &tlv );

    tlv.tag = TLVID_message_payload;
    tlv.length = strlen(TEXTO);
    memcpy(tlv.value.octet, TEXTO, tlv.length);
    build_tlv( &(b.tlv), &tlv );

    doTest(SUBMIT_MULTI, &a, &b);
    destroy_tlv( b.tlv );
    destroy_tlv( a.tlv );
    destroy_dad( b.dest_addr_def );
    destroy_dad( a.dest_addr_def );
    return( 0 );
};
