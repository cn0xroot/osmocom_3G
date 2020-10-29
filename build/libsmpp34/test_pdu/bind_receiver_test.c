
/*
 * Copyright (C) 2006 Raul Tremsal
 * File  : bind_receiver_test.c
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

    bind_receiver_t a;
    bind_receiver_t b;

    memset(&a, 0, sizeof(bind_receiver_t));
    memset(&b, 0, sizeof(bind_receiver_t));

    /* Init PDU ***********************************************************/
    b.command_length   = 0;
    b.command_id       = BIND_RECEIVER;
    b.command_status   = ESME_ROK;
    b.sequence_number  = 1;
    snprintf((char*)b.system_id, sizeof(b.system_id), "%s", "system_id");
    snprintf((char*)b.password, sizeof(b.password), "%s", "pass");
    snprintf((char*)b.system_type, sizeof(b.system_type), "%s", "syste");
    b.addr_ton    = 0x34;
    b.addr_ton    = 2;
    b.addr_npi    = 1;
    snprintf((char*)b.address_range, sizeof(b.address_range), "%s", "address_range");

    doTest(BIND_RECEIVER, &a, &b);
    return( 0 );
};
