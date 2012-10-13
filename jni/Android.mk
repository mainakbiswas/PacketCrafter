LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE    := rawudp
LOCAL_SRC_FILES := com_iitd_socket_UdpSocketX.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)
