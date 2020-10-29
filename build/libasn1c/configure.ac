AC_INIT([libasn1c], [0.9.28],
        [openbsc-devel@lists.openbsc.org])

AM_INIT_AUTOMAKE([dist-bzip2])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT
AC_PROG_LIBTOOL

AC_CONFIG_MACRO_DIR([m4])

PKG_CHECK_MODULES(LIBTALLOC, talloc)

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

AC_ARG_ENABLE([debug], [AS_HELP_STRING([--enable-debug], [Buld the library with EMIT_ASN_DEBUG enabled])],
		[build_debug="$enableval"], [build_debug="no"])
AM_CONDITIONAL(BUILD_DEBUG, test "x$build_debug" = "xyes")

AC_OUTPUT(
        libasn1c.pc
        src/Makefile
        include/Makefile
        include/asn1c/Makefile
        Makefile)

