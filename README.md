This utility will set the SELinux mode to "Permissive"

Building
========

Download the Android Native Development Kit (NDK):
	http://developer.android.com/tools/sdk/ndk/index.html#Downloads

Extract that into a directory and make sure that's on your PATH
	`export PATH=/place/where/unzipped:$PATH`


Build the image using
	ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk

The program will be written to
	./libs/armeabi/selinuxoff

If the phone you're running this on is "known", then this can be run as a
non-root user. Otherwise, it will require root to be able to find the 
necessary kernel address.
