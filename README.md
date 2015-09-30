# AgentDroid_Openssl
Since i don't figure out how to do ndk in Android Studio yet...
Eclipse project to generate the .so file used by AgentDroid. Using Openssl to generate certificates;

* libcrypto.a is compiled by NDK's cross-platform toolchain against armeabi-v7

* just copy the libagentdroid.so to jniLibs folder of the AgentDroid AS project.

* com_handhandlab_agentdroid_openssl_OpensslWrapper.cpp is the JNI interface, and agentdroid.c is the main implementation. Other C/C++ files can be ignored as they are just for testing.
