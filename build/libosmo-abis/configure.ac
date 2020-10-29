AC_INIT([libosmo-abis],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc@lists.osmocom.org])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip 1.6 subdir-objects])
AC_CONFIG_TESTDIR(tests)

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT([pic-only])

dnl check for pkg-config (explained in detail in libosmocore/configure.ac)
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

AC_CONFIG_MACRO_DIR([m4])

# The following test is taken from WebKit's webkit.m4
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fvisibility=hidden "
AC_MSG_CHECKING([if ${CC} supports -fvisibility=hidden])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes])
        SYMBOL_VISIBILITY="-fvisibility=hidden"],
        AC_MSG_RESULT([no]))
CFLAGS="$saved_CFLAGS"
AC_SUBST(SYMBOL_VISIBILITY)

dnl Generate the output
AM_CONFIG_HEADER(config.h)

PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 0.3.0)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty >= 0.3.0)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 0.3.10)
PKG_CHECK_MODULES(ORTP, ortp >= 0.22.0)

AC_CHECK_HEADERS(dahdi/user.h,,AC_MSG_WARN(DAHDI input driver will not be built))

AC_ARG_ENABLE(sanitize,
	[AS_HELP_STRING(
		[--enable-sanitize],
		[Compile with address sanitizer enabled],
	)],
	[sanitize=$enableval], [sanitize="no"])
if test x"$sanitize" = x"yes"
then
	CFLAGS+=" -fsanitize=address -fsanitize=undefined"
	CPPFLAGS+=" -fsanitize=address -fsanitize=undefined"
fi

_cflags_save=$CFLAGS
CFLAGS="$CFLAGS $ORTP_CFLAGS"
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <ortp/ortp.h>]],
		[[ortp_set_log_level_mask(NULL, 0xffff);]]
	)],
	[AC_DEFINE([HAVE_ORTP_LOG_DOMAIN], [1],
		[ortp_set_log_level_mask requires domain parameter])],
	[AC_DEFINE([HAVE_ORTP_LOG_DOMAIN], [0],
		[ortp_set_log_level_mask has no domain parameter])])
CFLAGS=$_cflags_save

AC_OUTPUT(
	libosmoabis.pc
	libosmotrau.pc
	include/Makefile
	src/Makefile
	tests/Makefile
	Makefile)
