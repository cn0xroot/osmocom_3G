AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/src \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(NULL)

EXTRA_DIST = \
	gsup_server_test.ok \
	gsup_server_test.err \
	$(NULL)

noinst_PROGRAMS = \
	gsup_server_test \
	$(NULL)

gsup_server_test_SOURCES = \
	gsup_server_test.c \
	$(NULL)

gsup_server_test_LDADD = \
	$(top_srcdir)/src/gsup_server.c \
	$(top_srcdir)/src/gsup_router.c \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/gsup_server_test >"$(srcdir)/gsup_server_test.ok" 2>"$(srcdir)/gsup_server_test.err"
