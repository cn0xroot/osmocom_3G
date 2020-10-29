AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOCTRL_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(SQLITE3_CFLAGS) \
	$(NULL)

EXTRA_DIST = \
	populate_hlr_db.pl \
	$(NULL)

noinst_HEADERS = \
	auc.h \
	db.h \
	hlr.h \
	luop.h \
	gsup_router.h \
	gsup_server.h \
	logging.h \
	rand.h \
	ctrl.h \
	hlr_vty.h \
	$(NULL)

bin_PROGRAMS = \
	osmo-hlr \
	$(NULL)

noinst_PROGRAMS = \
	db_test \
	$(NULL)

osmo_hlr_SOURCES = \
	auc.c \
	ctrl.c \
	db.c \
	luop.c \
	db_auc.c \
	db_hlr.c \
	gsup_router.c \
	gsup_server.c \
	hlr.c \
	logging.c \
	rand_urandom.c \
	hlr_vty.c \
	$(NULL)

osmo_hlr_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(SQLITE3_LIBS) \
	$(NULL)

db_test_SOURCES = \
	auc.c \
	db.c \
	db_auc.c \
	db_test.c \
	logging.c \
	rand_fake.c \
	$(NULL)

db_test_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(SQLITE3_LIBS) \
	$(NULL)
