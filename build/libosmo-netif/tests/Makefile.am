AM_CFLAGS = -Wall -I$(top_srcdir)/include $(LIBOSMOCORE_CFLAGS) -g
AM_LDFLAGS = $(LIBOSMOCORE_LDFLAGS)

check_PROGRAMS = osmux/osmux_test

osmux_osmux_test_SOURCES = osmux/osmux_test.c
osmux_osmux_test_LDADD = $(LIBOSMOCORE_LIBS) $(top_builddir)/src/libosmonetif.la

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

EXTRA_DIST = testsuite.at $(srcdir)/package.m4 $(TESTSUITE)		\
	     osmux/osmux_test.ok

DISTCLEANFILES = atconfig

TESTSUITE = $(srcdir)/testsuite

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
