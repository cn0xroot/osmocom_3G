/*
 * Copyright (C) 2006 Raul Tremsal
 * File  : smpp34_unpack.c
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
smpp34_unpack(uint32_t type, void* tt, const uint8_t *ptrBuf, int ptrLen)
{

    char dummy_b[SMALL_BUFF];
    const uint8_t *ini      = ptrBuf;
    const uint8_t *aux      = ptrBuf;
    int lenval = 0;
    int left = ptrLen;
    int lefterror = 0;

    memset(smpp34_strerror, 0, sizeof(smpp34_strerror));
    ptrerror = smpp34_strerror;
    lefterror = sizeof(smpp34_strerror);

#define instancia t1->

#define U32( inst, par, _str ){\
    lenval = sizeof( uint32_t );\
    if( lenval > left ){\
        PUTLOG("[%s:%08X(%s)]", par, inst par,\
                                      "Value length exceed buffer length");\
        return( -1 );\
    };\
    memcpy(&inst par, aux, lenval);\
    left -= lenval; aux += lenval;\
    inst par = ntohl( inst par );\
    _str(inst par, dummy_b);\
    if( strcmp("", dummy_b) == 0 ){\
        PUTLOG( "[%s:%08X(%s)]", par, inst par, "Invalid value");\
        return( -1 );\
    };\
    PUTLOG("[%s:%08X(%s)]", par, inst par, "OK");\
};

#define U16( inst, par, _str ){\
    lenval = sizeof( uint16_t );\
    if( lenval > left ){\
        PUTLOG("[%s:%04X(%s)]", par, inst par,\
                                      "Value length exceed buffer length");\
        return( -1 );\
    }\
    memcpy(&inst par, aux, lenval);\
    left -= lenval; aux += lenval;\
    inst par = ntohs( inst par );\
    _str(inst par, dummy_b);\
    if( strcmp("", dummy_b) == 0 ){\
        PUTLOG("[%s:%04X(%s)]", par, inst par, "Invalid value");\
        return( -1 );\
    };\
    PUTLOG("[%s:%04X(%s)]", par, inst par, "OK");\
};

#define U08( inst, par, _str ){\
    lenval = sizeof( uint8_t );\
    if( lenval > left ){\
        PUTLOG("[%s:%02X(%s)]", par, inst par,\
                                      "Value length exceed buffer length");\
        return( -1 );\
    };\
    memcpy(&inst par, aux, lenval);\
    left -= lenval; aux += lenval;\
    _str(inst par, dummy_b);\
    if( strcmp("", dummy_b) == 0 ){\
        PUTLOG( "[%s:%02X(%s)]", par, inst par, "Invalid value");\
        return( -1 );\
    };\
    PUTLOG("[%s:%02X(%s)]", par, inst par, "OK");\
};

/* NOTA: Importante, Los WARNINGs de los octetos, advierten de una 
 *       inconsistencia de largo en los octets/c_octets recibidos, segun se 
 *       decida el grado de restriccion estos pueden ser errores graves.
 *       La accion a tomar es truncar estos datos a los largos permitidos en la 
 *       especicacion, pero seguir parseando (saltando segun los largos 
 *       invalidos) los datos recibidos.
 */
#define O_C_OCTET( inst, par, sizeval ){\
    if( !(inst command_status) ){\
        C_OCTET( inst, par, sizeval );\
    } else {\
        PUTLOG("[%s:%s(%s)]", par, inst par, "OK");\
    };\
}


#define C_OCTET( inst, par, size ){\
    lenval = strlen( (char*) aux ) + 1;\
    if( lenval > left ){\
        PUTLOG("[len(%s):%d(%s)]", par, lenval, \
                                      "Value length exceed buffer length");\
        return( -1 );\
    };\
    if( lenval > size ){\
        PUTLOG("[%s:%s(%s)]", par, inst par, "Data length is invalid");\
        return( -1 );\
    } else {\
        /*snprintf(inst par, (lenval>size)?size:lenval, "%s", aux); */ \
        memcpy(inst par, aux, lenval);\
        left -= lenval; aux += lenval;\
        PUTLOG("[%s:%s(%s)]", par, inst par, "OK");\
    };\
}

#define OCTET8( inst, par, size ){\
    lenval = *((inst par) - 1);\
    if( lenval > left ){\
        PUTLOG("[leng %s:%d(%s)]", par, lenval,\
                                      "Value length exceed buffer length");\
        return( -1 );\
    };\
    if( lenval > size ){\
        PUTLOG("[%s:%s(%s)]", par, "<bin>",\
                                      "Data length is invalid (truncate)");\
        return( -1 );\
    };\
    memcpy(&inst par, aux, (lenval>size)?size:lenval);\
    left -= lenval; aux += lenval;\
    PUTLOG("[%s:%s(%s)]", par, "<bin>", "OK");\
}

#define OCTET16( inst, par, size ){\
    uint16_t l_lenval = 0; /* VERIFICAR ESTO */\
    memcpy(&l_lenval, (inst par - sizeof(uint16_t)), sizeof(uint16_t));\
    if( l_lenval > left ){\
        PUTLOG("[leng %s:%d(%s)]", par, l_lenval,\
                                      "Value length exceed buffer length");\
        return( -1 );\
    };\
    if( l_lenval > size ){\
        PUTLOG("[%s:%s(%s)]", par, "<bin>", "Data length is invalid");\
        return( -1 );\
    };\
    PUTLOG("[%s:%s(%s)]", par, "<bin>", "OK");\
    memcpy(&(inst par), aux, (l_lenval>size)?size:l_lenval);\
    left -= l_lenval; aux += l_lenval;\
}

#define TLV( inst, tlv3, do_tlv ){\
    tlv_t *aux_tlv = NULL;\
    while( (aux - ini) < t1->command_length ){\
        aux_tlv = (tlv_t *) malloc(sizeof( tlv_t ));\
        memset(aux_tlv, 0, sizeof(tlv_t));\
        do_tlv( aux_tlv );\
        aux_tlv->next = inst tlv3;\
        inst tlv3 = aux_tlv;\
    };\
};

#define UDAD( inst, udad3, do_udad ){\
    udad_t *aux_udad = NULL;\
    int c = 0;\
    while( c < t1->no_unsuccess ){\
        aux_udad = (udad_t *) malloc(sizeof( udad_t ));\
        memset(aux_udad, 0, sizeof(udad_t));\
        do_udad( aux_udad );\
        aux_udad->next = inst udad3;\
        inst udad3 = aux_udad;\
        c++;\
    };\
};

#define DAD( inst, dad3, do_dad ){\
    dad_t *aux_dad = NULL;\
    int c = 0;\
    while( c < t1->number_of_dests ){\
        aux_dad = (dad_t *) malloc(sizeof( dad_t ));\
        memset(aux_dad, 0, sizeof(dad_t));\
        do_dad( aux_dad );\
        aux_dad->next = inst dad3;\
        inst dad3 = aux_dad;\
        c++;\
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

    { /* Hace algunas Verificaciones **************************************/
        uint32_t len_orig;
        uint32_t l;
        memcpy(&len_orig, tt, sizeof(uint32_t));
        l = ntohl( len_orig );
        if( len_orig != (aux - ini) ){
            PUTLOG("[%s:(Error in PDU length %d!=%d)]",PDU,len_orig,(uint32_t)(aux-ini));
            return( -1 );
        };
    };

#include "def_frame/clean.frame"
    return( 0 );
};

int 
smpp34_unpack2(void* tt, const uint8_t *ptrBuf, int ptrLen)
{
    uint32_t cmdid;
    uint32_t tempo;
    memcpy(&tempo, ptrBuf + 4, sizeof(uint32_t)); /* get command_id PDU */
    cmdid = ntohl( tempo );
    return( smpp34_unpack(cmdid, tt, ptrBuf, ptrLen) );
};
