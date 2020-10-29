# test_pdu/Makefile.am #

TESTAPPS_SOURCE_DIR = $(top_srcdir)/test_apps
sendwp_SOURCES = \
    $(TESTAPPS_SOURCE_DIR)/tcp.c\
    $(TESTAPPS_SOURCE_DIR)/smpp.c\
    $(TESTAPPS_SOURCE_DIR)/sendwp.h\
    $(TESTAPPS_SOURCE_DIR)/sendwp.c

sendwp_CPPFLAGS = $(LIBXML2_CFLAGS)
sendwp_LDFLAGS = $(LIBXML2_LIBS)

noinst_DATA = \
     $(TESTAPPS_SOURCE_DIR)/sendwp.xml \
     $(TESTAPPS_SOURCE_DIR)/esme.xml

esme_SOURCES = \
    $(TESTAPPS_SOURCE_DIR)/tcp.c\
    $(TESTAPPS_SOURCE_DIR)/smpp.c\
    $(TESTAPPS_SOURCE_DIR)/esme.h\
    $(TESTAPPS_SOURCE_DIR)/esme.c

esme_CPPFLAGS = $(LIBXML2_CFLAGS)
esme_LDFLAGS = $(LIBXML2_LIBS)

analizer_SOURCES = \
    $(TESTAPPS_SOURCE_DIR)/analizer.c

analizer_CPPFLAGS = 
analizer_LDFLAGS = 
