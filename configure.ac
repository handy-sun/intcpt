#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.72])
AC_INIT([intcpt], [0.0.1], [handy-sun@foxmail.com])
AM_INIT_AUTOMAKE([foreign 1.11 subdir-objects -Wall -Wno-portability])

# AM_SUBDIR_OBJECTS = yes
AC_CONFIG_SRCDIR([src/tracer.c])
AC_CONFIG_HEADERS([config.h])
AC_LANG([C])

AC_CONFIG_FILES([Makefile])

AM_SILENT_RULES([yes])

AM_GNU_GETTEXT_VERSION([0.14.1])
AM_GNU_GETTEXT([external])
# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T

# Checks for library functions.
AC_CHECK_FUNCS([clock_gettime gettimeofday memset strtol strtoull])

AC_OUTPUT
# (Makefile)
