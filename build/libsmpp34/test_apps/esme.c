
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
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "esme.h"

extern char *optarg;
char file_config[256];
xmlDocPtr  d;          /* document */
xmlNodePtr c;          /* config */
xmlNodePtr conn_tcp;   /* conn_tcp */
xmlNodePtr conn_smpp;  /* conn_smpp */
xmlNodePtr smpp_msg;   /* smpp_msg */

int sock_tcp = 0;


#define HELP_FORMAT " -c file.xml [-h]\n" \
"    -c /path/to/file.xml: config file path.\n" \
"    -h : Help, show this message.\n"

int main( int argc, char **argv )
{
    int co;

    while( (co = getopt(argc, argv, "c:h")) != EOF ){
        switch( co ){
        case 'c':
            snprintf(file_config, sizeof(file_config), "%s", optarg);
            break;
        default:
            printf("Error: unrecognized option\n");
        case 'h':
            printf("usage: %s %s\n", argv[0], HELP_FORMAT);
            return( -1 );
        };
    };

    if( strcmp(file_config, "") == 0  ){ printf("Error in parameters\n");
        printf("usage: %s %s\n", argv[0], HELP_FORMAT); return( -1 ); };
    d = xmlParseFile( file_config );
    if( d == NULL ){ printf("Error in xmlParseFile()\n");
        printf("usage: %s %s\n", argv[0], HELP_FORMAT); return( -1 ); };
    c = xmlDocGetRootElement( d );
    if( c == NULL ){ printf("Error in xmlDocGetRootElement()\n");
        printf("usage: %s %s\n", argv[0], HELP_FORMAT); return( -1 ); };

    XML_IN_NODE(c, "config", c=c->xmlChildrenNode;break;, return(-1); );
    XML_IN_NODE(c, "conn_tcp", conn_tcp=c;break;, return(-1); );
    XML_IN_NODE(c, "conn_smpp", conn_smpp=c;break;, return(-1); );
    XML_IN_NODE(c, "smpp_msg", smpp_msg=c;break;, return(-1); );

    /* do tcp connect */
    if( do_tcp_connect( conn_tcp, &sock_tcp ) ){ 
        printf("Error in tcp connect.\n"); goto lb_free_document; };

    /* do smpp connect */
    if( do_smpp_connect( conn_smpp, sock_tcp ) ){ 
        printf("Error in smpp connect.\n"); goto lb_tcp_close; };

    /* do smpp send message */
    if( do_smpp_send_message( smpp_msg, sock_tcp ) ){ 
        printf("Error in smpp send message.\n"); goto lb_smpp_close; };

    /* That's all folks */
    /* taaa taratatata tatatatatata */
    /* taaa taratatata tatatatatata */
    /* ta aaa ta aaa tatatata */
    /* ta aaa ta aaa tatatata */
    /* taaa taratatata tatatatatata */
    /* :) */

lb_smpp_close: /* do smpp close */
    if( do_smpp_close( sock_tcp ) ) printf("Error in smpp close.\n");

lb_tcp_close: /* do tcp close */
    if( do_tcp_close( sock_tcp ) ) printf("Error in tcp close.\n");

lb_free_document: /* free xml document */
    xmlFreeDoc( d );

    return( 0 );
};
