SUBDIRS = binaries def_frame def_list

if HAVE_LIBXML2
SUBDIRS += test_apps
endif

EXTRA_DIST = src/Makefile.am\
             test_pdu/Makefile.am\
             test_apps/Makefile.am \
             test_apps/pack_and_send.inc\
             test_apps/esme.xml\
             test_apps/sendwp.xml\
             test_apps/recv_and_unpack.inc \
             README.md

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsmpp34.pc
