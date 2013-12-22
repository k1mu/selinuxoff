LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := selinuxoff
LOCAL_SRC_FILES := selinuxoff.c

include $(BUILD_EXECUTABLE)
