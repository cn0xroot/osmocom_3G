AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -g $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

check_PROGRAMS = e1inp_ipa_bsc_test	\
		  e1inp_ipa_bts_test	\
		  ipa_proxy_test	\
		  subchan_demux/subchan_demux_test \
		  ipa_recv/ipa_recv_test

e1inp_ipa_bsc_test_SOURCES = e1inp_ipa_bsc_test.c
e1inp_ipa_bsc_test_LDADD = $(top_builddir)/src/libosmoabis.la \
			$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

e1inp_ipa_bts_test_SOURCES = e1inp_ipa_bts_test.c
e1inp_ipa_bts_test_LDADD = $(top_builddir)/src/libosmoabis.la \
			$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

ipa_proxy_test_SOURCES = ipa_proxy_test.c
ipa_proxy_test_LDADD = $(top_builddir)/src/libosmoabis.la \
			$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) \
			$(LIBOSMOVTY_LIBS)

subchan_demux_subchan_demux_test_SOURCES = subchan_demux/subchan_demux_test.c
subchan_demux_subchan_demux_test_LDADD = $(top_builddir)/src/libosmoabis.la \
			$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) \
			$(LIBOSMOVTY_LIBS)

ipa_recv_ipa_recv_test_SOURCES = ipa_recv/ipa_recv_test.c
ipa_recv_ipa_recv_test_LDADD = $(top_builddir)/src/libosmoabis.la \
			$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) \
			$(LIBOSMOVTY_LIBS)

# boilerplate for the tests
# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
               echo '# Signature of the current package.' && \
               echo 'm4_define([AT_PACKAGE_NAME],' && \
               echo '  [$(PACKAGE_NAME)])' && \
               echo 'm4_define([AT_PACKAGE_TARNAME],' && \
               echo '  [$(PACKAGE_TARNAME)])' && \
               echo 'm4_define([AT_PACKAGE_VERSION],' && \
               echo '  [$(PACKAGE_VERSION)])' && \
               echo 'm4_define([AT_PACKAGE_STRING],' && \
               echo '  [$(PACKAGE_STRING)])' && \
               echo 'm4_define([AT_PACKAGE_BUGREPORT],' && \
               echo '  [$(PACKAGE_BUGREPORT)])'; \
               echo 'm4_define([AT_PACKAGE_URL],' && \
               echo '  [$(PACKAGE_URL)])'; \
             } >'$(srcdir)/package.m4'

EXTRA_DIST = testsuite.at $(srcdir)/package.m4 $(TESTSUITE) \
	subchan_demux/subchan_demux_test.ok \
	ipa_recv/ipa_recv_test.ok

TESTSUITE = $(srcdir)/testsuite

DISTCLEANFILES = atconfig

check-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)

installcheck-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
		$(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
		$(SHELL) '$(TESTSUITE)' --clean

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@
