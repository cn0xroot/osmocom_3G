/*
 * Copyright (C) 2006 Raul Tremsal
 * File  : smpp34_structs.h
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
#ifndef _STB_H_
#define _STB_H_

#define SMALL_BUFF      30
/* Identify PDUs ident ********************************************************/
#define MAX_TLV_SIZE         1024
#define MAX_DAD_SIZE         21
#define SERVICE_TYPE_LENGTH  6
#define ADDRESS_LENGTH       21
#define TIME_LENGTH          17
#define SHORT_MESSAGE_LENGTH 255

/* Globals for definitions ****************************************************/
extern int  smpp34_errno;
extern char smpp34_strerror[2048];

/* Define structures **********************************************************/
typedef struct tlv_t tlv_t; 
typedef struct dad_t dad_t; 
typedef struct udad_t udad_t; 
typedef struct bind_transmitter_t bind_transmitter_t; 
typedef struct bind_transmitter_resp_t bind_transmitter_resp_t; 
typedef struct bind_receiver_t bind_receiver_t; 
typedef struct bind_receiver_resp_t bind_receiver_resp_t; 
typedef struct bind_transceiver_t bind_transceiver_t; 
typedef struct bind_transceiver_resp_t bind_transceiver_resp_t; 
typedef struct outbind_t outbind_t; 
typedef struct unbind_t unbind_t; 
typedef struct unbind_resp_t unbind_resp_t; 
typedef struct generic_nack_t generic_nack_t; 
typedef struct submit_sm_t submit_sm_t; 
typedef struct submit_sm_resp_t submit_sm_resp_t; 
typedef struct submit_multi_t submit_multi_t; 
typedef struct submit_multi_resp_t submit_multi_resp_t; 
typedef struct deliver_sm_t deliver_sm_t; 
typedef struct deliver_sm_resp_t deliver_sm_resp_t; 
typedef struct data_sm_t data_sm_t; 
typedef struct data_sm_resp_t data_sm_resp_t; 
typedef struct query_sm_t query_sm_t; 
typedef struct query_sm_resp_t query_sm_resp_t; 
typedef struct cancel_sm_t cancel_sm_t; 
typedef struct cancel_sm_resp_t cancel_sm_resp_t; 
typedef struct replace_sm_t replace_sm_t; 
typedef struct replace_sm_resp_t replace_sm_resp_t; 
typedef struct enquire_link_t enquire_link_t; 
typedef struct alert_notification_t alert_notification_t; 

/* TYPEDEFs structs ***********************************************************/
#define instancia 0
#define U32( inst, par, _str ) uint32_t par;
#define U16( inst, par, _str ) uint16_t par;
#define U08( inst, par, _str ) uint8_t par;

#define O_C_OCTET( inst, par, size ) uint8_t par[ size ];
#define C_OCTET( inst, par, size ) uint8_t par[ size ];
#define OCTET8( inst, par, size ) uint8_t par[ size ];
#define OCTET16( inst, par, size ) uint8_t par[ size ];

#define TLV( inst, par, do_tlv ) tlv_t *par;
#define UUU( inst, par, size ) union { \
        U08( inst, val08, valueDec_08 ); \
        U16( inst, val16, valueDec_16 ); \
        U32( inst, val32, valueDec_32 ); \
    OCTET16( inst, octet, size        ); \
} par;

#define DAD( inst, par, do_dest_address ) dad_t *par;
#define UU2( inst, par, size ) union { \
    struct { \
        U08( instancia, dest_addr_ton, str_addr_ton ); \
        U08( instancia, dest_addr_npi, str_addr_npi ); \
        C_OCTET( instancia, destination_addr, size  ); \
    } sme; \
    C_OCTET( instancia, dl_name, size ); \
} par;

#define UDAD( inst, par, do_dest_address ) udad_t *par;

struct dad_t {
    #include "def_frame/dad.frame"
};

struct udad_t {
    #include "def_frame/udad.frame"
};

struct tlv_t {
    #include "def_frame/tlv.frame"
};

struct bind_transmitter_t {
    #include "def_frame/header.frame"
    #include "def_frame/bind_transmitter.frame"
};

struct bind_transmitter_resp_t {
    #include "def_frame/header.frame"
    #include "def_frame/bind_transmitter_resp.frame"
};

struct bind_receiver_t {
    #include "def_frame/header.frame"
    #include "def_frame/bind_receiver.frame"
};

struct bind_receiver_resp_t {
    #include "def_frame/header.frame"
    #include "def_frame/bind_receiver_resp.frame"
};

struct bind_transceiver_t {
    #include "def_frame/header.frame"
    #include "def_frame/bind_transceiver.frame"
};

struct bind_transceiver_resp_t {
    #include "def_frame/header.frame"
    #include "def_frame/bind_transceiver_resp.frame"
};

struct outbind_t {
    #include "def_frame/header.frame"
    #include "def_frame/outbind.frame"
};

struct unbind_t {
    #include "def_frame/header.frame"
};

struct unbind_resp_t {
    #include "def_frame/header.frame"
};

struct generic_nack_t {
    #include "def_frame/header.frame"
};

struct submit_sm_t {
    #include "def_frame/header.frame"
    #include "def_frame/submit_sm.frame"
};

struct submit_sm_resp_t {
    #include "def_frame/header.frame"
    #include "def_frame/submit_sm_resp.frame"
};

struct submit_multi_t {
    #include "def_frame/header.frame"
    #include "def_frame/submit_multi.frame"
};

struct submit_multi_resp_t {
    #include "def_frame/header.frame"
    #include "def_frame/submit_multi_resp.frame"
};

struct deliver_sm_t {
    #include "def_frame/header.frame"
    #include "def_frame/deliver_sm.frame"
};

struct deliver_sm_resp_t {
    #include "def_frame/header.frame"
    #include "def_frame/deliver_sm_resp.frame"
};

struct data_sm_t {
    #include "def_frame/header.frame"
    #include "def_frame/data_sm.frame"
};

struct data_sm_resp_t {
    #include "def_frame/header.frame"
    #include "def_frame/data_sm_resp.frame"
};

struct query_sm_t {
    #include "def_frame/header.frame"
    #include "def_frame/query_sm.frame"
};

struct query_sm_resp_t {
    #include "def_frame/header.frame"
    #include "def_frame/query_sm_resp.frame"
};

struct cancel_sm_t {
    #include "def_frame/header.frame"
    #include "def_frame/cancel_sm.frame"
};

struct cancel_sm_resp_t {
    #include "def_frame/header.frame"
};

struct replace_sm_t {
    #include "def_frame/header.frame"
    #include "def_frame/replace_sm.frame"
};

struct replace_sm_resp_t {
    #include "def_frame/header.frame"
};

struct enquire_link_t {
    #include "def_frame/header.frame"
};

typedef struct enquire_link_resp_t enquire_link_resp_t; 
struct enquire_link_resp_t {
    #include "def_frame/header.frame"
};

struct alert_notification_t {
    #include "def_frame/header.frame"
    #include "def_frame/alert_notification.frame"
};

#include "def_frame/clean.frame"

#define PUTLOG( format, param, value, parse ){\
    int lenerror = 0;\
    lenerror = snprintf((char*)ptrerror,lefterror,format,#param,value,parse);\
    ptrerror += lenerror; lefterror -= lenerror;\
}

/* Prototypes *****************************************************************/
int smpp34_dumpBuf(uint8_t *dest, int destL, uint8_t *src, int srcL);

int smpp34_dumpPdu(uint32_t type, uint8_t *dest, int size_dest, void* tt);
int smpp34_dumpPdu2(uint8_t *dest, int size_dest, void* tt);

int smpp34_pack(uint32_t type,uint8_t *ptrBuf,int ptrSize,int *ptrLen,void* tt);
int smpp34_pack2(uint8_t *ptrBuf,int ptrSize,int *ptrLen,void* tt);

int smpp34_unpack(uint32_t type, void* tt, const uint8_t *ptrBuf, int ptrLen);
int smpp34_unpack2(void* tt, const uint8_t *ptrBuf, int ptrLen);
#endif /* _STB_H_ */
