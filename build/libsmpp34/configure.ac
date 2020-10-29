#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(libsmpp34, 1.10, ultraismo@yahoo.com)
AC_CONFIG_AUX_DIR(aux_config)
AM_INIT_AUTOMAKE([foreign])
AM_CONFIG_HEADER([aux_config/config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
AC_PROG_INSTALL

# check for pkg-config (explained in detail in libosmocore/configure.ac)
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h netinet/in.h stdint.h string.h])

found_libxml2=yes
PKG_CHECK_MODULES(LIBXML2, libxml-2.0, , found_libxml2=no)
AM_CONDITIONAL(HAVE_LIBXML2, test "$found_libxml2" = yes)

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])
AC_OUTPUT([Makefile
           def_frame/Makefile
           def_list/Makefile
           binaries/Makefile
           test_apps/Makefile
	   libsmpp34.pc])
