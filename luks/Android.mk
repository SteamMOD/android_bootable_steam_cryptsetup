LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_CFLAGS := -Os

LOCAL_SRC_FILES := \
	pbkdf.c \
	keymanage.c \
	keyencryption.c \
	hexprint.c \
	random.c \
	af.c 

LOCAL_MODULE := libsteam_luks
LOCAL_MODULE_TAGS := eng

LOCAL_C_INCLUDES := bootable/steam/cryptsetup bootable/steam/cryptsetup/lib bootable/steam/cryptsetup/luks external/openssl/include bootable/steam/jfsutils

LOCAL_CFLAGS := -Os -g -W -Wall \
	-DHAVE_UNISTD_H \
	-DHAVE_ERRNO_H \
	-DHAVE_NETINET_IN_H \
	-DHAVE_SYS_IOCTL_H \
	-DHAVE_SYS_MMAN_H \
	-DHAVE_SYS_MOUNT_H \
	-DHAVE_SYS_PRCTL_H \
	-DHAVE_SYS_RESOURCE_H \
	-DHAVE_SYS_SELECT_H \
	-DHAVE_SYS_STAT_H \
	-DHAVE_SYS_TYPES_H \
	-DHAVE_STDLIB_H \
	-DHAVE_STRDUP \
	-DHAVE_MMAP \
	-DHAVE_UTIME_H \
	-DHAVE_GETPAGESIZE \
	-DHAVE_LSEEK64 \
	-DHAVE_LSEEK64_PROTOTYPE \
	-DHAVE_EXT2_IOCTLS \
	-DHAVE_LINUX_FD_H \
	-DHAVE_TYPE_SSIZE_T \
	-DBUILTIN_OPENSSL

include $(BUILD_STATIC_LIBRARY)

