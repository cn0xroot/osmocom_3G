AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS=-Wall -g $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

noinst_PROGRAMS = abis_ipa_stream_server	\
		  abis_ipa_stream_client

abis_ipa_stream_server_SOURCES = abis_ipa_stream_server.c
abis_ipa_stream_server_LDADD = $(top_builddir)/src/libosmonetif.la 	\
			       $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

abis_ipa_stream_client_SOURCES = abis_ipa_stream_client.c
abis_ipa_stream_client_LDADD = $(top_builddir)/src/libosmonetif.la 	\
			       $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)
