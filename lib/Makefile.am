moduledir = $(libdir)/cryptsetup

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcryptsetup.pc

if BUILD_LIBGCRYPT
_LIBGCRYPT_LIBADD = @LIBGCRYPT_LIBS@
_LIBGCRYPT_SOURCES = gcrypt.c
_LIBGCRYPT_CFLAGS = -DBUILTIN_GCRYPT
endif
libcrypto_gcrypt_la_SOURCES = gcrypt.c
libcrypto_gcrypt_la_LDFLAGS = -avoid-version -module
libcrypto_gcrypt_la_LIBADD = @LIBGCRYPT_LIBS@
if SHARED_LIBGCRYPT
_LIBGCRYPT_SHLIB = libcrypto_gcrypt.la
endif

if BUILD_OPENSSL
_OPENSSL_LIBADD = @OPENSSL_LIBS@
_OPENSSL_SOURCES = openssl.c
_OPENSSL_CFLAGS = -DBUILTIN_OPENSSL
endif
libcrypto_openssl_la_SOURCES = openssl.c
libcrypto_openssl_la_LDFLAGS = -avoid-version -module
libcrypto_openssl_la_LIBADD = @OPENSSL_LIBS@
if SHARED_OPENSSL
_OPENSSL_SHLIB = libcrypto_openssl.la
endif

INCLUDES = \
	-I$(top_srcdir)				\
	-I$(top_srcdir)/luks			\
	-DDATADIR=\""$(datadir)"\"		\
	-DLIBDIR=\""$(libdir)"\"		\
	-DPREFIX=\""$(prefix)"\"		\
	-DSYSCONFDIR=\""$(sysconfdir)"\"	\
	-DVERSION=\""$(VERSION)"\"		\
	-D_GNU_SOURCE				\
	-D_LARGEFILE64_SOURCE			\
	-D_FILE_OFFSET_BITS=64			\
	@LIBDEVMAPPER_CFLAGS@			\
	$(_LIBDEVMAPPER_CFLAGS)			\
	@LIBGCRYPT_CFLAGS@			\
	$(_LIBGCRYPT_CFLAGS)			\
	@OPENSSL_CFLAGS@			\
	$(_OPENSSL_CFLAGS)

lib_LTLIBRARIES = libcryptsetup.la

module_LTLIBRARIES = \
	$(_LIBDEVMAPPER_SHLIB)			\
	$(_LIBGCRYPT_SHLIB)			\
	$(_OPENSSL_SHLIB)

if STATIC_LIBRARY
_STATIC_LIBRARY = -static
endif

libcryptsetup_la_DEPENDENCIES = libcryptsetup.sym

libcryptsetup_la_LDFLAGS = \
	$(_STATIC_LIBRARY) \
	-Wl,--version-script=$(top_srcdir)/lib/libcryptsetup.sym \
	-version-info @LIBCRYPTSETUP_VERSION_INFO@

libcryptsetup_la_CFLAGS = -Wall

libcryptsetup_la_LIBADD = \
	$(_LIBDEVMAPPER_LIBADD)			\
	$(_LIBGCRYPT_LIBADD)			\
	$(_OPENSSL_LIBADD)			\
	@UUID_LIBS@				\
	@DEVMAPPER_LIBS@			\
	@LIBGCRYPT_LIBS@			\
	../luks/libluks.la

libcryptsetup_la_SOURCES = \
	setup.c					\
	internal.h				\
	nls.h					\
	blockdev.h				\
	libcryptsetup.h				\
	utils.c					\
	utils_debug.c				\
	backends.c				\
	libdevmapper.c				\
	$(_LIBDEVMAPPER_SOURCES)		\
	$(_LIBGCRYPT_SOURCES)			\
	$(_OPENSSL_SOURCES)

include_HEADERS = libcryptsetup.h

EXTRA_DIST = libcryptsetup.pc.in libcryptsetup.sym
