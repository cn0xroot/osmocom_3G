AC_INIT([osmo-iuh],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc@lists.osmocom.org])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

LT_INIT

AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip 1.9 tar-ustar])
dnl tar-ustar: some asn1 filenames surpass the 99 char limit of tar, so we need
dnl to make tar allow longer filenames.

AC_CONFIG_TESTDIR(src/tests)

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_CC
AC_PROG_INSTALL

dnl check for pkg-config (explained in detail in libosmocore/configure.ac)
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

PKG_CHECK_MODULES(OSMOCORE, libosmocore)
PKG_CHECK_MODULES(OSMOGSM, libosmogsm)
PKG_CHECK_MODULES(OSMOVTY, libosmovty)
PKG_CHECK_MODULES(OSMONETIF, libosmo-netif)
PKG_CHECK_MODULES(OSMOSIGTRAN, libosmo-sigtran)
PKG_CHECK_MODULES(ASN1C, libasn1c)

AC_CONFIG_MACRO_DIR([m4])

dnl checks for header files
AC_HEADER_STDC

AC_OUTPUT(
	libosmo-ranap.pc
	src/Makefile
	src/hnbap/Makefile
	src/ranap/Makefile
	src/rua/Makefile
	src/tests/Makefile
	Makefile
	include/Makefile
	include/osmocom/Makefile
	include/osmocom/hnbap/Makefile
	include/osmocom/ranap/Makefile
	include/osmocom/rua/Makefile
	include/osmocom/iuh/Makefile
	doc/Makefile
	doc/examples/Makefile
	)
