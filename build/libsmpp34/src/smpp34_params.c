/*
 * Copyright (C) 2006 Raul Tremsal
 * File  : smpp34_params.c
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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "smpp34.h"
#include "smpp34_structs.h"

int 
build_udad( udad_t **dest, udad_t *source )
{

    /* Build new DAD-Chain ************************************************/
    udad_t *dummy = (udad_t*)malloc(sizeof( udad_t ));
    if( dummy == NULL ){
        printf("Error in malloc()\n" );
        return( -1 );
    };
    memcpy(dummy, source, sizeof( udad_t ));

    dummy->next = (*dest);
    (*dest) = dummy;

    return( 0 );
};

int
destroy_udad( udad_t *sourceList )
{

    udad_t *i = NULL;
    /* Destroy DAD-Chain **************************************************/
    while( sourceList != NULL ){
        i = sourceList->next;
        free((void*)sourceList);
        sourceList = i;
    };

    return( 0 );
};



int 
build_dad( dad_t **dest, dad_t *source )
{

    /* Build new DAD-Chain ************************************************/
    dad_t *dummy = (dad_t*)malloc(sizeof( dad_t ));
    if( dummy == NULL ){
        printf("Error in malloc()\n" );
        return( -1 );
    };
    memcpy(dummy, source, sizeof( dad_t ));

    dummy->next = (*dest);
    (*dest) = dummy;

    return( 0 );
};

int
destroy_dad( dad_t *sourceList )
{

    dad_t *i = NULL;
    /* Destroy DAD-Chain **************************************************/
    while( sourceList != NULL ){
        i = sourceList->next;
        free((void*)sourceList);
        sourceList = i;
    };

    return( 0 );
};


int 
build_tlv( tlv_t **dest, tlv_t *source )
{

    /* Build new TLV-Chain ************************************************/
    tlv_t *dummy = (tlv_t*)malloc(sizeof( tlv_t ));
    if( dummy == NULL ){
        printf("Error in malloc()\n" );
        return( -1 );
    };
    memcpy(dummy, source, sizeof( tlv_t ));

    dummy->next = (*dest);
    (*dest) = dummy;

    return( 0 );
};

int
destroy_tlv( tlv_t *sourceList )
{

    tlv_t *i = NULL;
    /* Destroy TLV-Chain **************************************************/
    while( sourceList != NULL ){
        i = sourceList->next;
        free((void*)sourceList);
        sourceList = i;
    };

    return( 0 );
};


char* str_tlv_id( uint16_t tlv_id, char* buff )
{
    snprintf(buff, SMALL_BUFF, "%s", 
#define OPERACION( p_tlv_id ) (tlv_id == p_tlv_id)?#p_tlv_id:
#include "def_list/tlv_id.list"
            "Reserved"
#undef OPERACION
          );
    return( buff );
};


char* str_command_id( uint32_t command, char* buff )
{
    snprintf(buff, SMALL_BUFF, "%s", 
#define OPERACION( p_command ) (command == p_command)?#p_command:
#include "def_list/command_id.list"
            ""
#undef OPERACION
          );
    return( buff );
};


char* str_addr_ton( uint8_t ton, char* buff )
{
    snprintf(buff, SMALL_BUFF, "%s", 
#define OPERACION( p_command ) (ton == p_command)?#p_command:
#include "def_list/addr_ton.list"
            ""
#undef OPERACION
          );
    return( buff );
};


char* str_addr_npi( uint8_t npi, char* buff )
{
    snprintf(buff, SMALL_BUFF, "%s", 
#define OPERACION( p_command ) (npi == p_command)?#p_command:
#include "def_list/addr_npi.list"
            ""
#undef OPERACION
          );
    return( buff );
};


char* str_command_status( uint32_t command, char* buff )
{
    snprintf(buff, SMALL_BUFF, "%s", 
#define OPERACION( p_command ) (command == p_command)?#p_command:
#include "def_list/command_status.list"
            ""
#undef OPERACION
             );
    return( buff );
};

char *test_interface_version( uint8_t interface_version, char* buff )
{
    snprintf(buff, SMALL_BUFF, "%s", (interface_version==0x34)?"OK":"" );
    return( buff );
};

char *test_dest_flag( uint8_t dest_flag, char* buff )
{
    snprintf(buff, SMALL_BUFF, "%s", 
#define OPERACION( p_command ) (dest_flag == p_command)?#p_command:
#include "def_list/dest_flag.list"
            ""
#undef OPERACION
            );
    return( buff );
};

char *test_sequence_number( uint32_t sequence_number, char* buff )
{
    char numero[20];
    snprintf(numero, sizeof(numero), "%d", sequence_number);
    snprintf(buff, SMALL_BUFF, "%s", (sequence_number>0)?numero:"" );
    return( buff );
};

char *nothing( uint32_t var, char* buff )
{
    snprintf(buff, SMALL_BUFF, "%s", "OK" );
    return( buff );
};

char *valueDec_32( uint32_t var, char *buff )
{
    snprintf(buff, SMALL_BUFF, "%d", var);
    return( buff );
};

char *valueDec_16( uint16_t var, char *buff )
{
    snprintf(buff, SMALL_BUFF, "%d", var);
    return( buff );
};

char *valueDec_08( uint8_t var, char* buff )
{
    snprintf(buff, SMALL_BUFF, "%d", var);
    return( buff );
};


