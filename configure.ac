#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([intcpt],[0.0.1],[handy-sun@foxmail.com])
AM_INIT_AUTOMAKE([foreign 1.11 subdir-objects -Wall -Wno-portability])

# AM_SUBDIR_OBJECTS = yes
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])
AC_LANG([C])

AM_SILENT_RULES([yes])

# AM_GNU_GETTEXT([external])

# Checks for programs.
AC_PROG_CC
if test "$cross_compiling" = no; then
  if test "x$ac_cv_prog_cc_c99" = "xno" || test "x$ac_cv_prog_cc_c99" = "x"; then
  # We might be on RHEL5 with a git checkout and so broken
  # autoconf. Check if CC is gcc and if it bails when given -std=gnu99.
  # If not, use that.  Yuck.
    if test "x$ac_cv_c_compiler_gnu" = "xyes"; then
       CC="$CC -std=gnu99"
       AC_RUN_IFELSE(
          [AC_LANG_PROGRAM([],[[
  return 0;
      ]])],
      [],
      [AC_MSG_ERROR([Could not find a C99 compatible compiler])])
    else
      AC_MSG_ERROR([Could not find a C99 compatible compiler])
    fi
  fi
fi

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T

# Checks for library functions.
AC_CHECK_FUNCS([clock_gettime gettimeofday memset strtol strtoull])

AC_CONFIG_FILES([Makefile src/Makefile])

# Finally produce "configure" script
AC_OUTPUT

