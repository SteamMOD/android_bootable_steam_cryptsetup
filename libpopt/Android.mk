LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)
LOCAL_CFLAGS := -Os

LOCAL_SRC_FILES:= \
	findme.c \
	popt.c \
	poptconfig.c \
	popthelp.c \
	poptparse.c

LOCAL_CFLAGS += -DHAVE_CONFIG_H

LOCAL_MODULE := libsteam_popt

include $(BUILD_STATIC_LIBRARY)
