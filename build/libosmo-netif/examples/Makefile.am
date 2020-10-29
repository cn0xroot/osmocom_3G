AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS=-Wall -g $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

SUBDIRS = channel

noinst_PROGRAMS = ipa-stream-client		\
		  ipa-stream-server		\
		  lapd-over-datagram-user	\
		  lapd-over-datagram-network	\
		  stream-client			\
		  stream-server			\
		  rs232-read			\
		  rs232-write			\
		  rtp-udp-test-client		\
		  rtp-udp-test-server		\
		  osmux-test-input		\
		  osmux-test-output

ipa_stream_client_SOURCES = ipa-stream-client.c
ipa_stream_client_LDADD = $(top_builddir)/src/libosmonetif.la \
			  $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

ipa_stream_server_SOURCES = ipa-stream-server.c
ipa_stream_server_LDADD = $(top_builddir)/src/libosmonetif.la \
			  $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

lapd_over_datagram_user_SOURCES = lapd-over-datagram-user.c
lapd_over_datagram_user_LDADD = $(top_builddir)/src/libosmonetif.la \
				  $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) \
				  $(LIBOSMOABIS_LIBS)

lapd_over_datagram_network_SOURCES = lapd-over-datagram-network.c
lapd_over_datagram_network_LDADD = $(top_builddir)/src/libosmonetif.la \
				  $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) \
				  $(LIBOSMOABIS_LIBS)

stream_client_SOURCES = stream-client.c
stream_client_LDADD = $(top_builddir)/src/libosmonetif.la \
		      $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

stream_server_SOURCES = stream-server.c
stream_server_LDADD = $(top_builddir)/src/libosmonetif.la \
		      $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

rs232_read_SOURCES = rs232-read.c
rs232_read_LDADD = $(top_builddir)/src/libosmonetif.la $(LIBOSMOCORE_LIBS)

rs232_write_SOURCES = rs232-write.c
rs232_write_LDADD = $(top_builddir)/src/libosmonetif.la $(LIBOSMOCORE_LIBS)

rtp_udp_test_client_SOURCES = rtp-udp-test-client.c
rtp_udp_test_client_LDADD = $(top_builddir)/src/libosmonetif.la \
			    $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

rtp_udp_test_server_SOURCES = rtp-udp-test-server.c
rtp_udp_test_server_LDADD = $(top_builddir)/src/libosmonetif.la \
			    $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

osmux_test_input_SOURCES = osmux-test-input.c
osmux_test_input_LDADD = $(top_builddir)/src/libosmonetif.la \
			 $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

osmux_test_output_SOURCES = osmux-test-output.c
osmux_test_output_LDADD = $(top_builddir)/src/libosmonetif.la \
			  $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)
