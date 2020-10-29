
/*
 * Copyright (C) 2006 Raul Tremsal
 * File  : submit_multi_resp_test.c
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


int
main( int argc, char *argv[] )
{

    submit_multi_resp_t a;
    submit_multi_resp_t b;
    udad_t udad;

    memset(&a, 0, sizeof(submit_multi_resp_t));
    memset(&b, 0, sizeof(submit_multi_resp_t));
    memset(&udad, 0, sizeof( udad_t ));

    /* Init PDU ***********************************************************/
    b.command_length   = 0;
    b.command_id       = SUBMIT_MULTI_RESP;
    b.command_status   = ESME_ROK;
    b.sequence_number  = 1;
    snprintf( (char*)b.message_id, sizeof(b.message_id), "%s", "88898239379");
    b.no_unsuccess  = 3;

    /* Unsuccess submitted list of DAD ************************************/
    udad.dest_addr_ton = 2;
    udad.dest_addr_npi = 1;
    snprintf( (char*)udad.destination_addr, sizeof(udad.destination_addr), 
                                                        "%s", "9911112222");
    udad.error_status_code = ESME_RX_T_APPN;
    build_udad( &(b.unsuccess_smes), &udad );

    udad.dest_addr_ton = 0;
    udad.dest_addr_npi = 0;
    snprintf( (char*)udad.destination_addr, sizeof(udad.destination_addr), 
                                                        "%s", "9922223333");
    udad.error_status_code = ESME_RX_P_APPN;
    build_udad( &(b.unsuccess_smes), &udad );

    udad.dest_addr_ton = 2;
    udad.dest_addr_npi = 1;
    snprintf( (char*)udad.destination_addr, sizeof(udad.destination_addr), 
                                                        "%s", "9933334444");
    udad.error_status_code = ESME_RX_R_APPN;
    build_udad( &(b.unsuccess_smes), &udad );
    /**********************************************************************/

    doTest(SUBMIT_MULTI_RESP, &a, &b);

    destroy_udad( b.unsuccess_smes );
    destroy_udad( a.unsuccess_smes );

    return( 0 );
};
