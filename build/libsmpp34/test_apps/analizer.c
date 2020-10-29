
/*
 * Copyright (C) 2006 Raul Tremsal
 * File  : esme.c
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
#include <arpa/inet.h>

#include <stdint.h>

#include "smpp34.h"
#include "smpp34_structs.h"
#include "smpp34_params.h"

extern char *optarg;
char file_pdu[256];

int ret = 0;
uint8_t bufPDU[2048];
int bufPDULen = 0;
uint8_t bPrint[2048];

#define HELP_FORMAT " -f file [-h]\n" \
"    -f /path/to/file: binary file path.\n" \
"    -h : Help, show this message.\n"


int work( uint32_t id, void* dst ) 
{

    /* Print Buffer *******************************************************/
    memset(bPrint, 0, sizeof(bPrint));
    ret = smpp34_dumpBuf(bPrint, sizeof(bPrint), bufPDU, bufPDULen);
    if( ret != 0 ){
        printf("Error in smpp34_dumpBuf():%d:\n%s\n", 
                                            smpp34_errno, smpp34_strerror );
        return( -1 );
    };
    printf("parse smpp34_dumpBuf()\n%s\n", smpp34_strerror);
    printf("-----------------------------------------------------------\n");
    printf("%s", bPrint);
    printf("-----------------------------------------------------------\n");

    /* Copy PDU from Buffer ***********************************************/
    ret = smpp34_unpack(id, (void*)dst, bufPDU, bufPDULen); 
    if( ret != 0 ){
        printf("Error in smpp34_unpack():%d:\n%s\n", 
                                             smpp34_errno, smpp34_strerror);
        return( -1 );
    };
    printf("parse smpp34_unpack()\n%s\n", smpp34_strerror);

    /* Print PDU **********************************************************/
    memset(bPrint, 0, sizeof(bPrint));
    ret = smpp34_dumpPdu(id, bPrint, sizeof(bPrint), (void*)dst );
    if( ret != 0){
        printf("Error in smpp34_dumpPdu():%d:\n%s\n", 
                                             smpp34_errno, smpp34_strerror);
        return( -1 );
    };
    printf("parse smpp34_dumpPdu()\n%s\n", smpp34_strerror);
    printf("-----------------------------------------------------------\n");
    printf("%s\n", bPrint);
    printf("-----------------------------------------------------------\n");

    return( 0 );
};

int main( int argc, char **argv )
{
    int co;
    FILE *fd = NULL;
    uint32_t tt, id;
    tt = id = 0;

    while( (co = getopt(argc, argv, "f:h")) != EOF ){
        switch( co ){
        case 'f':
            snprintf(file_pdu, sizeof(file_pdu), "%s", optarg);
            break;
        default:
            printf("Error: unrecognized option\n");
        case 'h':
            printf("usage: %s %s\n", argv[0], HELP_FORMAT);
            return( -1 );
        };
    };

    if( strcmp(file_pdu, "") == 0  ){ printf("Error in parameters\n");
        printf("usage: %s %s\n", argv[0], HELP_FORMAT); return( -1 ); };

    /* Open File **********************************************************/

    if( (fd = fopen(file_pdu, "r")) == NULL ){
        printf("Can't open file %s\n", file_pdu);
        return( -1 );
    };

    memset(bufPDU, 0, sizeof(bufPDU)); bufPDULen = 0;
    /* char *fgets(char *s, int size, FILE *stream); */
    while( !feof( fd ) ){
        *(bufPDU + (bufPDULen++)) = (uint8_t)getc( fd );
    };
    fclose( fd ); bufPDULen--;

    memcpy(&tt, (bufPDU+4), 4); id = ntohl( tt );

    if( id == BIND_TRANSMITTER ){
        bind_transmitter_t t1;
        memset(&t1, 0, sizeof(bind_transmitter_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == BIND_TRANSMITTER_RESP ){
        bind_transmitter_resp_t t1;
        memset(&t1, 0, sizeof(bind_transmitter_resp_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == BIND_RECEIVER ){
        bind_receiver_t t1;
        memset(&t1, 0, sizeof(bind_receiver_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == BIND_RECEIVER_RESP ){
        bind_receiver_resp_t t1;
        memset(&t1, 0, sizeof(bind_receiver_resp_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == BIND_TRANSCEIVER ){
        bind_transceiver_t t1;
        memset(&t1, 0, sizeof(bind_transceiver_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == BIND_TRANSCEIVER_RESP ){
        bind_transceiver_resp_t t1;
        memset(&t1, 0, sizeof(bind_transceiver_resp_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == OUTBIND ){
        outbind_t t1;
        memset(&t1, 0, sizeof(outbind_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == UNBIND ){
        unbind_t t1;
        memset(&t1, 0, sizeof(unbind_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == UNBIND_RESP ){
        unbind_resp_t t1;
        memset(&t1, 0, sizeof(unbind_resp_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == GENERIC_NACK ){
        generic_nack_t t1;
        memset(&t1, 0, sizeof(generic_nack_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == SUBMIT_SM ){
        submit_sm_t t1;
        memset(&t1, 0, sizeof(submit_sm_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == SUBMIT_SM_RESP ){
        submit_sm_resp_t t1;
        memset(&t1, 0, sizeof(submit_sm_resp_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == SUBMIT_MULTI ){
        submit_multi_t t1;
        memset(&t1, 0, sizeof(submit_multi_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == SUBMIT_MULTI_RESP ){
        submit_multi_resp_t t1;
        memset(&t1, 0, sizeof(submit_multi_resp_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == DELIVER_SM ){
        deliver_sm_t t1;
        memset(&t1, 0, sizeof(deliver_sm_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == DELIVER_SM_RESP ){
        deliver_sm_resp_t t1;
        memset(&t1, 0, sizeof(deliver_sm_resp_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == DATA_SM ){
        data_sm_t t1;
        memset(&t1, 0, sizeof(data_sm_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == DATA_SM_RESP ){
        data_sm_resp_t t1;
        memset(&t1, 0, sizeof(data_sm_resp_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == QUERY_SM ){
        query_sm_t t1;
        memset(&t1, 0, sizeof(query_sm_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == QUERY_SM_RESP ){
        query_sm_resp_t t1;
        memset(&t1, 0, sizeof(query_sm_resp_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == CANCEL_SM ){
        cancel_sm_t t1;
        memset(&t1, 0, sizeof(cancel_sm_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == CANCEL_SM_RESP ){
        cancel_sm_resp_t t1;
        memset(&t1, 0, sizeof(cancel_sm_resp_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == REPLACE_SM ){
        replace_sm_t t1;
        memset(&t1, 0, sizeof(replace_sm_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == REPLACE_SM_RESP ){
        replace_sm_resp_t t1;
        memset(&t1, 0, sizeof(replace_sm_resp_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == ENQUIRE_LINK ){
        enquire_link_t t1;
        memset(&t1, 0, sizeof(enquire_link_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == ENQUIRE_LINK_RESP ){
        enquire_link_resp_t t1;
        memset(&t1, 0, sizeof(enquire_link_resp_t));
        return( work( id, (void*)&t1 ) );
    } else if( id == ALERT_NOTIFICATION ){
        alert_notification_t t1;
        memset(&t1, 0, sizeof(alert_notification_t));
        return( work( id, (void*)&t1 ) );
    } else {
        printf("Invalid SMPP PDU [%08X].\n", id);
    };
    return( -1 );

};
