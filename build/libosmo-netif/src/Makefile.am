# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool documentation before making any modification
LIBVERSION=3:0:0

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS= -fPIC -Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS) $(LIBSCTP_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

SUBDIRS = channel

lib_LTLIBRARIES = libosmonetif.la

libosmonetif_la_LIBADD = channel/abis/libosmonetif-abis.la $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBSCTP_LIBS)
libosmonetif_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined

libosmonetif_la_SOURCES = amr.c			\
			  channel.c		\
			  datagram.c		\
			  ipa.c			\
			  ipa_unit.c		\
			  osmux.c		\
			  rs232.c		\
			  rtp.c			\
			  stream.c
