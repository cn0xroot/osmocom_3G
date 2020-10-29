/*
 * Copyright (C) 2006 Raul Tremsal
 * File  : smpp34_dumpBuf.c
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
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <stdint.h>

#include "smpp34.h"
#include "smpp34_structs.h"
#include "smpp34_params.h"


/* GLOBALS ********************************************************************/
/* EXTERN *********************************************************************/
extern int smpp34_errno;
extern char smpp34_strerror[2048];
extern char *ptrerror;

/* FUNCTIONS ******************************************************************/
int 
smpp34_dumpBuf(uint8_t *dest, int destL, uint8_t *src, int srcL)
{

    int i;
    int j;
    int size;
    uint8_t ind = 3;
    uint8_t *buffer = NULL;
    int lefterror = 0;

    size   = srcL;
    buffer = src;

    memset(smpp34_strerror, 0, sizeof(smpp34_strerror));
    ptrerror = smpp34_strerror;
    lefterror = sizeof(smpp34_strerror);

    /* dump buffer character by character until size is reached */
    for(i = 0; i < size; i++){
        switch( i % 16 ) {
            case 0:
                dest += sprintf((char*)dest, "%*c%02X ", ind, ' ', (uint8_t)buffer[i]);
                break;

            case 7:
                dest += sprintf((char*)dest, "%02X   ", (uint8_t)buffer[i]);
                break;

            case 15:
                dest += sprintf((char*)dest, "%02X   ", (uint8_t)buffer[i]);
                for(j = (i - 15); j <= i; j++) {
                    if ( (buffer[j] < ' ') || (buffer[j] > '~') )
                        dest += sprintf((char*)dest, ".");
                    else
                        dest += sprintf((char*)dest, "%c", buffer[j]);
                    if ( (j % 16) == 7 )
                        dest += sprintf((char*)dest, " ");
                }
                dest += sprintf((char*)dest, "\n");
                break;

            default:
                dest += sprintf((char*)dest, "%02X ", (uint8_t)buffer[i]);
                break;
        }
    };

    /* if the line is not completed, we have to fill it */
    if ( (size % 16) != 0 ) {
        for (i = (size % 16); i < 16; i++) {
            dest += sprintf((char*)dest, "   ");
            if ( (i % 16) == 7 )
                dest += sprintf((char*)dest, "  ");
        }
        dest += sprintf((char*)dest, "  ");
        for (j = size - (size % 16); j < size; j++) {
            /* check if character is printable */
            if ( (buffer[j] < ' ') || (buffer[j] > '~') )
                dest += sprintf((char*)dest, ".");
            else
                dest += sprintf((char*)dest, "%c", (char) buffer[j]);
            if ( (j % 16) == 7 )
                dest += sprintf((char*)dest, " ");
        }
        dest += sprintf((char*)dest, "\n");
    }

    *dest = '\0';
    return( 0 );
};


