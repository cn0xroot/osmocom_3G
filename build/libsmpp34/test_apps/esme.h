
/*
 * Copyright (C) 2006 Raul Tremsal
 * File  : esme.h
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

#ifndef _esme_h_
#define _esme_h_

#define GET_PROP_INT( dst, c, src )\
{\
    xmlChar *clave = NULL; dst = 0;\
    if( (clave = xmlGetProp(c, (xmlChar*)src)) != NULL ){\
         dst = strtol((char*)clave, NULL, 10);\
         xmlFree( clave );\
    }\
};

#define GET_PROP_STR( dst, c, src )\
{\
    xmlChar *clave = NULL;\
    memset(dst, 0, sizeof(dst));\
    if( (clave = xmlGetProp(c, (xmlChar*)src)) != NULL ){\
        snprintf((char*)dst, sizeof(dst), "%s", (char*)clave);\
        xmlFree( clave );\
    }\
};



#define _xmlChar( str ) (const xmlChar*) str
#define XML_IN_NODE( c, str, exito, fracaso )\
while( c != NULL ){\
    if( xmlStrcmp(c->name, _xmlChar(str)) == 0 ){\
        exito;\
    };\
    c = c->next;\
};\
if( c == NULL ){\
    printf("Can't find tag <%s>.",  str);\
    fracaso;\
};  
        
int do_tcp_connect( xmlNodePtr p, int *sock_tcp );
int do_tcp_close( int sock_tcp );
int do_smpp_connect( xmlNodePtr p, int sock_tcp );
int do_smpp_send_message( xmlNodePtr p, int sock_tcp );
int do_smpp_close( int sock_tcp );
#endif /* _esme_h_ */
