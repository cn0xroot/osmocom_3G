SUBDIRS = hnbap rua ranap tests

# Build {hnbap,rua,ranap}_{encoder,decoder}.c using asn1tostruct
ASN1_ROOT = $(top_srcdir)/asn1
ASN1TOSTRUCT = $(ASN1_ROOT)/utils/asn1tostruct.py
BUILT_SOURCES = hnbap_decoder.c hnbap_encoder.c rua_decoder.c rua_encoder.c \
	gen_hnbap.stamp gen_rua.stamp gen_ranap.stamp

gen_hnbap.stamp: $(ASN1_ROOT)/hnbap/HNBAP-PDU-Contents.asn $(ASN1TOSTRUCT)
	$(ASN1TOSTRUCT) -f $<
#	We also need to replace the include in the newly generated .c files:
	sed -i 's,^#include "hnbap_ies_defs.h",#include <osmocom/hnbap/hnbap_ies_defs.h>,' hnbap_encoder.c hnbap_decoder.c
	sed -i 's,^#include "hnbap_common.h",#include <osmocom/hnbap/hnbap_common.h>,' hnbap_encoder.c hnbap_decoder.c hnbap_ies_defs.h
	mv hnbap_ies_defs.h $(top_builddir)/include/osmocom/hnbap/
#	this is ugly ^. hnbap_ies_defs.h is generated from asn1tostruct.py here, but
#	it should live in include/osmocom/hnbap/.
	touch $(top_builddir)/src/$@

hnbap_decoder.c hnbap_encoder.c: gen_hnbap.stamp

gen_rua.stamp: $(ASN1_ROOT)/rua/RUA-PDU-Contents.asn $(ASN1TOSTRUCT)
	$(ASN1TOSTRUCT) -p RUA_ -f $<
#	We also need to replace the include in the newly generated .c files:
	sed -i 's,^#include "rua_ies_defs.h",#include <osmocom/rua/rua_ies_defs.h>,' rua_encoder.c rua_decoder.c
	sed -i 's,^#include "rua_common.h",#include <osmocom/rua/rua_common.h>,' rua_encoder.c rua_decoder.c rua_ies_defs.h
	mv rua_ies_defs.h $(top_builddir)/include/osmocom/rua/
#	this is ugly ^. rua_ies_defs.h is generated from asn1tostruct.py here, but
#	it should live in include/osmocom/rua/.
	touch $(top_builddir)/src/$@

rua_decoder.c rua_encoder.c: gen_rua.stamp

gen_ranap.stamp: $(ASN1_ROOT)/ranap/RANAP-PDU-Contents.asn $(ASN1TOSTRUCT)
	$(ASN1TOSTRUCT) -p RANAP_ -f $<
#	We also need to replace the include in the newly generated .c files:
	sed -i 's,^#include "ranap_ies_defs.h",#include <osmocom/ranap/ranap_ies_defs.h>,' ranap_encoder.c ranap_decoder.c
	sed -i 's,^#include "ranap_common.h",#include <osmocom/ranap/ranap_common.h>,' ranap_encoder.c ranap_decoder.c ranap_ies_defs.h
	mv ranap_ies_defs.h $(top_builddir)/include/osmocom/ranap/
#	this is ugly ^. ranap_ies_defs.h is generated from asn1tostruct.py here, but
#	it should live in include/osmocom/ranap/.
	touch $(top_builddir)/src/$@

ranap_decoder.c ranap_encoder.c: gen_ranap.stamp

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include \
	    $(OSMOCORE_CFLAGS) $(OSMOVTY_CFLAGS) $(OSMOGSM_CFLAGS) \
	    $(OSMONETIF_CFLAGS) $(ASN1C_CFLAGS) $(OSMOSIGTRAN_CFLAGS)
COMMON_LDADD = -lsctp

# build the shared RANAP library
#
RANAP_LIBVERSION=0:0:0
lib_LTLIBRARIES = libosmo-ranap.la
libosmo_ranap_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(RANAP_LIBVERSION)
libosmo_ranap_la_LIBADD = $(OSMOCORE_LIBS) $(OSMOGSM_LIBS) $(ASN1C_LIBS) $(COMMON_LDADD) ranap/libosmo-asn1-ranap.la
libosmo_ranap_la_SOURCES = ranap_common.c ranap_encoder.c ranap_decoder.c ranap_msg_factory.c iu_helpers.c \
			   ranap_common_cn.c

# build the actual HomeNodeB gateway
#
bin_PROGRAMS = osmo-hnbgw

osmo_hnbgw_SOURCES = hnbap_encoder.c hnbap_decoder.c hnbap_common.c \
		     rua_encoder.c rua_decoder.c rua_common.c \
		     rua_msg_factory.c \
		     hnbgw.c hnbgw_hnbap.c hnbgw_rua.c hnbgw_ranap.c \
		     hnbgw_vty.c \
		     context_map.c hnbgw_cn.c

osmo_hnbgw_LDADD = $(OSMOCORE_LIBS) $(OSMOVTY_LIBS) $(OSMOGSM_LIBS) \
		   $(ASN1C_LIBS) $(OSMOSIGTRAN_LIBS) $(COMMON_LDADD) \
		   $(OSMONETIF_LIBS) \
		   hnbap/libosmo-asn1-hnbap.a rua/libosmo-asn1-rua.a \
		   libosmo-ranap.la


regen: regenerate-from-asn1-source

regenerate-from-asn1-source:
	$(MAKE) -C hnbap regen
	$(MAKE) -C ranap regen
	$(MAKE) -C rua regen

DISTCLEANFILES = \
	hnbap_decoder.c \
	hnbap_encoder.c \
	rua_decoder.c \
	rua_encoder.c \
	ranap_decoder.c \
	ranap_encoder.c \
	gen_hnbap.stamp \
	gen_rua.stamp \
	gen_ranap.stamp
