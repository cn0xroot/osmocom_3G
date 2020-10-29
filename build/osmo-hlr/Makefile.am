AUTOMAKE_OPTIONS = foreign dist-bzip2

SUBDIRS = \
	src \
	sql \
	tests \
	$(NULL)

EXTRA_DIST = \
	.version \
	$(NULL)

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
