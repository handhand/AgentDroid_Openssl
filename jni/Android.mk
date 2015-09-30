LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE	:= openssl_static
LOCAL_SRC_FILES := libcrypto.a
LOCAL_EXPORT_C_INCLUDES += $(LOCAL_PATH)/include
include $(PREBUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE    := openssltest
LOCAL_SRC_FILES := openssltest.cpp agentdroid.c
# use openssl
LOCAL_LDFLAGS := $(LOCAL_PATH)/libcrypto.a
LOCAL_STATIC_LIBRARIES	:= openssl_static
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_LDLIBS	+= -llog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := agentdroid
LOCAL_SRC_FILES := agentdroid.c com_handhandlab_agentdroid_openssl_OpensslWrapper.cpp 
# use openssl
LOCAL_LDFLAGS := $(LOCAL_PATH)/libcrypto.a
LOCAL_STATIC_LIBRARIES	:= openssl_static
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_LDLIBS	+= -llog
include $(BUILD_SHARED_LIBRARY)