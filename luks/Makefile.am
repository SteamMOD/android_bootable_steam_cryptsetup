moduledir = $(libdir)/cryptsetup

noinst_LTLIBRARIES = libluks.la

libluks_la_CFLAGS = -Wall

if BUILD_LIBGCRYPT
libluks_la_CFLAGS += @LIBGCRYPT_CFLAGS@
_LIBGCRYPT_CFLAGS = -DBUILTIN_GCRYPT
endif

if BUILD_OPENSSL
_OPENSSL_CFLAGS = -DBUILTIN_OPENSSL
endif

libluks_la_SOURCES = \
	af.c \
	pbkdf.c \
	keymanage.c \
	keyencryption.c \
	hexprint.c \
	random.c \
	pbkdf.h \
	random.h \
	af.h \
	luks.h

INCLUDES = -D_GNU_SOURCE			\
	-D_LARGEFILE64_SOURCE                   \
	-D_FILE_OFFSET_BITS=64                  \
	$(_OPENSSL_CFLAGS)			\
	$(_LIBGCRYPT_CFLAGS)			\
        -I$(top_srcdir)/lib

