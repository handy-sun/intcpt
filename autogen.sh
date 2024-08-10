#!/bin/sh
#
# Helps generate autoconf/automake stuff, when code is checked out from SCM.

SRCDIR=$(dirname ${0})
test -z "${SRCDIR}" && SRCDIR=.

THEDIR=$(pwd)
cd ${SRCDIR}
DIE=0

test -f autogen.sh || {
	echo "You must run this script in the top-level intcpt directory"
	DIE=1
}

(autopoint --version) < /dev/null > /dev/null 2>&1 || {
	echo "You must have autopoint installed to generate intcpt build system."
	echo "The autopoint command is part of the GNU gettext package."
	DIE=1
}

(autoconf --version) < /dev/null > /dev/null || {
	echo "You must have autoconf installed to generate intcpt build system."
	DIE=1
}
(autoheader --version) < /dev/null > /dev/null || {
	echo "You must have autoheader installed to generate intcpt build system."
	echo "The autoheader command is part of the GNU autoconf package."
	DIE=1
}
(automake --version) < /dev/null > /dev/null || {
	echo "You must have automake installed to generate intcpt build system."
	DIE=1
}

# LTVER=$(libtoolize --version | awk '/^libtoolize/ { print $4 }')
# LTVER=${LTVER:-"none"}
# test ${LTVER##2.} = "${LTVER}" && {
# 	echo "You must have libtoolize version >= 2.x.x, but you have ${LTVER}."
# 	DIE=1
# }

if test ${DIE} -ne 0; then
	exit 1
fi

echo "Generate build-system by:"
echo "   autopoint:  $(autopoint --version | head -1)"
echo "   aclocal:    $(aclocal --version | head -1)"
echo "   autoconf:   $(autoconf --version | head -1)"
echo "   autoheader: $(autoheader --version | head -1)"
echo "   automake:   $(automake --version | head -1)"
# echo "   libtoolize: $(libtoolize --version | head -1)"

rm -rf autom4te.cache

set -e

aclocal -I m4
autoconf
autoheader
autoupdate

automake --add-missing

echo
echo "Now execute '${SRCDIR}/configure' and 'make' to compile."

