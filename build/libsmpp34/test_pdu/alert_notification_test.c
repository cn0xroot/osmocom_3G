
/*
 * Copyright (C) 2006 Raul Tremsal
 * File  : alert_notification_test.c
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

    alert_notification_t a;
    alert_notification_t b;
    tlv_t tlv;

    memset(&a, 0, sizeof(alert_notification_t));
    memset(&b, 0, sizeof(alert_notification_t));
    memset(&tlv, 0, sizeof(tlv_t));

    /* Init PDU ***********************************************************/
    b.command_length   = 0;
    b.command_id       = ALERT_NOTIFICATION;
    b.command_status   = ESME_ROK;
    b.sequence_number  = 1;
    b.source_addr_ton  = 2;
    b.source_addr_npi  = 1;
    snprintf((char*)b.source_addr, ADDRESS_LENGTH, "%s", "0900001111");
    b.esme_addr_ton    = 2;
    b.esme_addr_npi    = 1;
    snprintf((char*)b.esme_addr, ADDRESS_LENGTH, "%s", "0900001111");

    tlv.tag = TLVID_ms_availability_status;        /* defined in smpp34.h */
    tlv.length = sizeof(uint8_t);
    tlv.value.val08 = 0x24;
    build_tlv( &(b.tlv), &tlv );

    doTest(ALERT_NOTIFICATION, &a, &b);
    destroy_tlv( b.tlv );
    destroy_tlv( a.tlv );

    return( 0 );
};
