# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool documentation before making any modification
ABIS_LIBVERSION=5:0:0
TRAU_LIBVERSION=1:0:0

AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS= -Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)
COMMONLIBS = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS)

lib_LTLIBRARIES = libosmoabis.la libosmotrau.la

libosmoabis_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(ABIS_LIBVERSION)
libosmoabis_la_LIBADD = $(COMMONLIBS)
libosmoabis_la_SOURCES = init.c \
			 e1_input.c \
			 e1_input_vty.c \
			 ipa_proxy.c \
			 subchan_demux.c \
			 trau_frame.c \
			 input/dahdi.c \
			 input/ipa.c \
			 input/ipaccess.c \
			 input/lapd.c \
			 input/lapd_pcap.c \
			 input/misdn.c \
			 input/rs232.c \
			 input/unixsocket.c

libosmotrau_la_CFLAGS = $(AM_CFLAGS) $(ORTP_CFLAGS)
libosmotrau_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(TRAU_LIBVERSION)
libosmotrau_la_LIBADD = $(COMMONLIBS) $(ORTP_LIBS)
libosmotrau_la_SOURCES = trau/osmo_ortp.c
