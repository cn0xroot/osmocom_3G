# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
LIBVERSION=1:0:0

AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include/asn1c
AM_CFLAGS = -fPIC -Wall $(LIBTALLOC_CFLAGS)
if BUILD_DEBUG
AM_CFLAGS += -DEMIT_ASN_DEBUG=1
endif

lib_LTLIBRARIES = libasn1c.la

libasn1c_la_LDFLAGS = $(LIBTALLOC_LIBS)
libasn1c_la_SOURCES = ANY.c              constraints.c         GeneralizedTime.c   NumericString.c      T61String.c asn_codecs_prim.c  constr_CHOICE.c       GeneralString.c     ObjectDescriptor.c   TeletexString.c asn_SEQUENCE_OF.c  constr_SEQUENCE.c     GraphicString.c     OBJECT_IDENTIFIER.c  UniversalString.c asn_SET_OF.c       constr_SEQUENCE_OF.c  IA5String.c         OCTET_STRING.c       UTCTime.c ber_decoder.c      constr_SET.c          INTEGER.c           per_decoder.c        UTF8String.c ber_tlv_length.c   constr_SET_OF.c       ISO646String.c      per_encoder.c        VideotexString.c ber_tlv_tag.c      constr_TYPE.c         NativeEnumerated.c  per_support.c        VisibleString.c BIT_STRING.c       NativeInteger.c     PrintableString.c    xer_decoder.c BMPString.c        der_encoder.c         NativeReal.c        REAL.c               xer_encoder.c BOOLEAN.c          ENUMERATED.c          NULL.c              RELATIVE-OID.c       xer_support.c	per_opentype.c        asn1helpers.c

