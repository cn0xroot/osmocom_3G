
/*
 * Copyright (C) 2006 Raul Tremsal
 * File  : core.c
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

extern int  smpp34_errno;
extern char smpp34_strerror[2048];


int 
doTest( uint32_t id, void* dst, void* src )
{

    int ret = 0;
    uint8_t bufPDU[2048];
    int bufPDULen = 0;
    uint8_t bPrint[2048];

    /* Linealize PDU to buffer ********************************************/
    memset(&bufPDU, 0, sizeof(bufPDU));
    ret = smpp34_pack(id, bufPDU, sizeof(bufPDU), &bufPDULen, (void*)src);
    if( ret != 0 ){
        printf("Error in smpp34_pack():%d:\n%s\n", 
                                             smpp34_errno, smpp34_strerror);
        return( 0 );
    };
    printf("parse smpp34_pack()\n%s\n", smpp34_strerror);

    /* Print PDU **********************************************************/
    memset(&bPrint, 0, sizeof(bPrint));
    ret = smpp34_dumpPdu(id, bPrint, sizeof(bPrint), (void*)src);
    if( ret != 0){
        printf("Error in smpp34_dumpPdu():%d:\n%s\n", 
                                             smpp34_errno, smpp34_strerror);
        return( -1 );
    };
    printf("parse smpp34_dumpPdu()\n%s\n", smpp34_strerror);
    printf("-----------------------------------------------------------\n");
    printf("%s\n", bPrint);
    printf("-----------------------------------------------------------\n");

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
