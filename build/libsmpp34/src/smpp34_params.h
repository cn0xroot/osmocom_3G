/*
 * Copyright (C) 2006 Raul Tremsal
 * File  : smpp34_params.h
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
#ifndef _TEST_PARAM_H_
#define _TEST_PARAM_H_

int destroy_udad( udad_t *sourceList );
int build_udad( udad_t **dest, udad_t *source );

int destroy_dad( dad_t *sourceList );
int build_dad( dad_t **dest, dad_t *source );

int destroy_tlv( tlv_t *sourceList );
int build_tlv( tlv_t **dest, tlv_t *source );

char* str_tlv_id( uint16_t tlv_id, char* buff );
char* str_command_id( uint32_t command, char* buff );
char* str_command_status( uint32_t command, char* buff );
char *test_sequence_number( uint32_t sequence_number, char* buff );
char *test_interface_version( uint8_t interface_version, char* buff );
char *test_dest_flag( uint8_t dest_flag, char* buff );

char* str_addr_ton( uint8_t ton, char *buff);
char* str_addr_npi( uint8_t npi, char *buff);

char *valueDec_32( uint32_t var, char *buff );
char *valueDec_16( uint16_t var, char *buff );
char *valueDec_08( uint8_t var, char *buff );
char *nothing( uint32_t var, char *buff );
#endif
