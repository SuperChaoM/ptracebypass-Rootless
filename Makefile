DEBUG=0
FINALPACKAGE=1
GO_EASY_ON_ME=1

#THEOS_PACKAGE_SCHEME = rootless
THEOS_PACKAGE_SCHEME = roothide

TARGET = iphone:14.5:14.5
ARCHS = arm64

THEOS_DEVICE_IP = 127.0.0.1 -p 2222

TARGET := iphone:clang:latest:7.0

include $(THEOS)/makefiles/common.mk

TOOL_NAME = ptraceBypass

ptraceBypass_FILES = patchfinder/libdimentio.c  main.m
ptraceBypass_CFLAGS = -fobjc-arc
ptraceBypass_CODESIGN_FLAGS = -Sentitlements.plist
ptraceBypass_INSTALL_PATH = /usr/local/bin
ptraceBypass_FRAMEWORKS = IOKit

include $(THEOS_MAKE_PATH)/tool.mk
