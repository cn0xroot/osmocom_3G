/*
 * Copyright (C) 2006 Raul Tremsal
 * File  : smpp34_pack.c
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
smpp34_pack(uint32_t type, uint8_t *ptrBuf, int ptrSize, int *ptrLen, void* tt)
{

    char dummy_b[SMALL_BUFF];
    uint32_t v = 0;
    uint32_t *dd = (uint32_t*)tt;
    uint8_t *aux = ptrBuf;
    uint8_t *aux2 = ptrBuf;
    int lenval = 0;
    int left = ptrSize;
    int lefterror = 0;

    memset(smpp34_strerror, 0, sizeof(smpp34_strerror));
    ptrerror = smpp34_strerror;
    lefterror = sizeof(smpp34_strerror);

#define instancia t1->

#define U32( inst, par, _str ){\
    uint32_t v32 = htonl(inst par);\
    lenval = sizeof(uint32_t);\
    if( lenval >= left ){\
        PUTLOG("[%s:%08X(%s)]", par, inst par,\
                                      "Value length exceed buffer length");\
        return( -1 );\
    };\
    _str(inst par,dummy_b);\
    if( strcmp("", dummy_b) == 0 ){\
        PUTLOG( "[%s:%08X(%s)]", par, inst par, "Invalid value");\
        return( -1 );\
    }\
    PUTLOG("[%s:%08X(%s)]", par, inst par, "OK");\
    memcpy(aux, &v32, lenval);\
    left -= lenval; aux += lenval;\
};

#define U16( inst, par, _str ) {\
    uint16_t v16 = htons(inst par);\
    lenval = sizeof(uint16_t);\
    if( lenval >= left ){\
        PUTLOG("[%s:%04X(%s)]", par, inst par,\
                                      "Value length exceed buffer length");\
        return( -1 );\
    };\
    _str(inst par,dummy_b);\
    if( strcmp("", dummy_b) == 0 ){\
        PUTLOG( "[%s:%04X(%s)]", par, inst par, "Invalid value");\
        return( -1 );\
    }\
    PUTLOG("[%s:%04X(%s)]", par, inst par, "OK");\
    memcpy(aux, &v16, lenval);\
    left -= lenval; aux += lenval;\
};

#define U08( inst, par, _str ){\
    lenval = sizeof(uint8_t);\
    if( lenval >= left ){\
        PUTLOG("[%s:%02X(%s)]", par, inst par,\
                                      "Value length exceed buffer length");\
        return( -1 );\
    };\
    _str(inst par,dummy_b);\
    if( strcmp("", dummy_b) == 0 ){\
        PUTLOG( "[%s:%02X(%s)]", par, inst par, "Invalid value");\
        return( -1 );\
    }\
    PUTLOG("[%s:%02X(%s)]", par, inst par, "OK");\
    memcpy(aux,&inst par, sizeof(inst par));\
    left -= lenval; aux += lenval;\
};

#define O_C_OCTET( inst, par, sizeval ){\
    if( !(inst command_status) ){\
        C_OCTET( inst, par, sizeval );\
    } else {\
        PUTLOG("[%s:%s(%s)]", par, inst par, "OK");\
    };\
}

#define C_OCTET( inst, par, sizeval ){\
    lenval = strlen((char*)inst par) + 1;\
    if( lenval > left ){\
        PUTLOG("[len(%s):%d(%s)]", par, lenval, \
                                      "Value length exceed buffer length");\
        return( -1 );\
    };\
    if( lenval > sizeval ){\
        memcpy(aux, &inst par, sizeval);\
        *(inst par + sizeval-1) = *(aux+sizeval-1) = '\0';\
        left -= sizeval; aux += sizeval;\
        PUTLOG("[%s:%s(%s)]", par, inst par, \
                                      "Data length is invalid (truncate)");\
    } else {\
        memcpy(aux, &inst par, lenval);\
        left -= lenval; aux += lenval;\
        PUTLOG("[%s:%s(%s)]", par, inst par, "OK");\
    }\
};

#define OCTET8( inst, par, sizeval ){\
    lenval = *((inst par) - 1);\
    if( lenval >= left ){\
        PUTLOG("[leng %s:%d(%s)]", par, lenval,\
                                      "Value length exceed buffer length");\
        return( -1 );\
    };\
    if( lenval >= sizeval ){\
        PUTLOG("[%s:%s(%s)]", par, "<bin>",\
                                      "Data length is invalid (truncate)");\
        return( -1 );\
    };\
    memcpy(aux, &inst par, (lenval > sizeval)?sizeval:lenval);\
    left -= (lenval > sizeval)?sizeval:lenval;\
    aux += (lenval > sizeval)?sizeval:lenval;\
    PUTLOG("[%s:%s(%s)]", par, "<bin>", "OK");\
};

#define OCTET16( inst, par, sizeval ){\
    uint16_t l_lenval = 0;\
    memcpy(&l_lenval, ((inst par) - sizeof(uint16_t)), sizeof(uint16_t));\
    if( l_lenval >= left ){\
        PUTLOG("[leng %s:%d(%s)]", par, l_lenval,\
                                      "Value length exceed buffer length");\
        return( -1 );\
    };\
    if( l_lenval > sizeval ){\
        PUTLOG("[%s:%s(%s)]", par, "<bin>", "Data length is invalid");\
        return( -1 );\
    };\
    memcpy(aux, &inst par, (l_lenval > sizeval)?sizeval:l_lenval);\
    left -= (l_lenval > sizeval)?sizeval:l_lenval;\
    aux += (l_lenval > sizeval)?sizeval:l_lenval;\
    PUTLOG("[%s:%s(%s)]", par, "<bin>", "OK");\
}

#define TLV( inst, tlv2, do_tlv ) {\
    tlv_t *aux_tlv = inst tlv2;\
    while( aux_tlv != NULL ){\
        do_tlv( aux_tlv );\
        aux_tlv = aux_tlv->next;\
    };\
};

#define UDAD( inst, udad2, do_udad ) {\
    udad_t *aux_udad = inst udad2;\
    while( aux_udad != NULL ){\
        do_udad( aux_udad );\
        aux_udad = aux_udad->next;\
    };\
};

#define DAD( inst, dad2, do_dad ) {\
    dad_t *aux_dad = inst dad2;\
    while( aux_dad != NULL ){\
        do_dad( aux_dad );\
        aux_dad = aux_dad->next;\
    };\
};

#include "def_frame/alert_notification.tlv"
#include "def_frame/bind_receiver_resp.tlv"
#include "def_frame/bind_transceiver_resp.tlv"
#include "def_frame/bind_transmitter_resp.tlv"
#include "def_frame/data_sm.tlv"
#include "def_frame/data_sm_resp.tlv"
#include "def_frame/deliver_sm.tlv"
#include "def_frame/submit_multi_resp.udad"
#include "def_frame/submit_multi.dad"
#include "def_frame/submit_multi.tlv"
#include "def_frame/submit_sm.tlv"
#include "def_list/smpp34_protocol.def"

    /* Hace algunas correcciones ******************************************/
    *dd = aux - aux2;                       /* Escribe largo en el source */
    v = htonl(aux - aux2);                  /* Calcula largo del PDU      */
    memcpy(aux2, &v, sizeof(uint32_t));     /* escribe largo en el dest   */
    *ptrLen = (int) (aux - aux2);

#include "def_frame/clean.frame"
    return( 0 );
};


int 
smpp34_pack2(uint8_t *ptrBuf, int ptrSize, int *ptrLen, void* tt)
{
    uint32_t cmdid;
    memcpy(&cmdid, tt+4, sizeof(uint32_t));
    return( smpp34_pack(cmdid, ptrBuf, ptrSize, ptrLen, tt) );
};
