#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(tcpmkpub, 0.1, rpang@cs.princeton.edu)
AC_CONFIG_SRCDIR([src/Ethernet.cc])
AC_CONFIG_HEADER(config.h)

# Check for the existence of local policy files
AC_CHECK_FILES([local-policy local-policy/topology.anon local-policy/scanner.anon local-policy/special.anon local-policy/filter.anon], 
	[],
 	[AC_MSG_ERROR([Please create site-specific policy files; see README for details and local-policy-sample/ for examples.])])

AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE

AC_DEFINE(_BSD_SOURCE,1,[Trying to use BSDish header files])
AC_DEFINE(__FAVOR_BSD,1,[Trying to use BSD header structs for network])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_MAKE_SET

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_open_live])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h netinet/in.h stdlib.h string.h sys/param.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MEMCMP
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([bzero memset strdup strstr])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
