# RTL8187L USB wireless driver for Mac OS X 10.3.9 - 10.5 (PowerPC).
#
#   make            build the kernel extension, the RTL Wireless application
#                   and the rtlwifi tool (on a Mac)
#   make install    install both (run with sudo)
#   make test       run the driver core's unit tests (any Unix with a C compiler)
#   make test-ppc   the same tests on an emulated big-endian PowerPC (Linux)
#
# The kernel extension is built against the Mac OS X 10.3.9 SDK that ships
# with Xcode 1.5 - 3.1; the result loads on 10.3.9, 10.4 and 10.5.
#   10.3 (Xcode 1.5):  make SDK= KCC=gcc-3.3 KCXX=g++-3.3
#   10.4/10.5:         make            (uses /Developer/SDKs/MacOSX10.3.9.sdk)
# To build against the 10.4 SDK instead (result needs 10.4 or later):
#   make SDK=/Developer/SDKs/MacOSX10.4u.sdk KPI=1

SDK   ?= /Developer/SDKs/MacOSX10.3.9.sdk
KCC   ?= gcc
KCXX  ?= g++
ARCH  ?= ppc
BUILD ?= build

KEXT  = $(BUILD)/RTL8187.kext
TOOL  = $(BUILD)/rtlwifi
APP   = $(BUILD)/RTLWireless.app

CORE_SRC = src/core/rtl8187.c src/core/rtw_sta.c src/core/rtw_aes.c \
           src/core/rtw_sha1.c src/core/rtw_wep.c
CORE_HDR = $(wildcard src/core/*.h)

KERNEL_FW = $(SDK)/System/Library/Frameworks/Kernel.framework
KFLAGS = -arch $(ARCH) -Os -Wall -nostdinc -fno-builtin -fno-common \
         -static -mlong-branch -msoft-float -finline \
         -fno-keep-inline-functions -force_cpusubtype_ALL \
         -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -DAPPLE -DNeXT \
         -I$(KERNEL_FW)/PrivateHeaders -I$(KERNEL_FW)/Headers -Isrc/core
KCXXFLAGS = $(KFLAGS) -fno-rtti -fno-exceptions -fcheck-new -fapple-kext
ifdef KPI
KFLAGS += -DRTW_USE_KPI_MBUF
PLIST = src/kext/Info-kpi.plist
else
PLIST = src/kext/Info.plist
endif

KOBJS = $(patsubst src/core/%.c,$(BUILD)/k_%.o,$(CORE_SRC)) \
        $(BUILD)/k_RTL8187_info.o $(BUILD)/k_RTL8187.o

all: kext tool app

kext: $(KEXT)/Contents/MacOS/RTL8187

$(BUILD)/k_%.o: src/core/%.c $(CORE_HDR)
	@mkdir -p $(BUILD)
	$(KCC) $(KFLAGS) -c $< -o $@

$(BUILD)/k_RTL8187_info.o: src/kext/RTL8187_info.c
	@mkdir -p $(BUILD)
	$(KCC) $(KFLAGS) -c $< -o $@

$(BUILD)/k_RTL8187.o: src/kext/RTL8187.cpp src/kext/RTL8187.h $(CORE_HDR)
	@mkdir -p $(BUILD)
	$(KCXX) $(KCXXFLAGS) -c $< -o $@

$(KEXT)/Contents/MacOS/RTL8187: $(KOBJS) $(PLIST)
	@mkdir -p $(KEXT)/Contents/MacOS
	$(KCXX) -arch $(ARCH) -static -nostdlib -r -L$(SDK)/usr/lib \
	    -lkmodc++ $(KOBJS) -lkmod -lcc_kext -o $@
	cp $(PLIST) $(KEXT)/Contents/Info.plist

tool: $(TOOL)

$(TOOL): src/tool/rtlwifi.c src/core/rtw_sha1.c $(CORE_HDR)
	@mkdir -p $(BUILD)
	$(CC) -Os -Wall -Isrc/core src/tool/rtlwifi.c src/core/rtw_sha1.c \
	    -framework IOKit -framework CoreFoundation -o $@

# The application uses only Mac OS X 10.3 APIs.  With an SDK it is built
# against that SDK so the result runs on 10.3.9 and later.
ifneq ($(strip $(SDK)),)
APP_SDKFLAGS = -isysroot $(SDK)
endif
APP_SRC = src/app/main.m src/app/AppController.m src/app/RTWDriver.m \
          src/core/rtw_sha1.c

app: $(APP)/Contents/MacOS/RTLWireless

$(APP)/Contents/MacOS/RTLWireless: $(APP_SRC) $(wildcard src/app/*.h) \
    src/app/Info.plist $(CORE_HDR)
	@mkdir -p $(APP)/Contents/MacOS
	MACOSX_DEPLOYMENT_TARGET=10.3 $(CC) -arch $(ARCH) -Os -Wall \
	    $(APP_SDKFLAGS) -Isrc/core -Isrc/app $(APP_SRC) \
	    -framework Cocoa -framework IOKit -framework Security -o $@
	cp src/app/Info.plist $(APP)/Contents/Info.plist
	printf 'APPL????' > $(APP)/Contents/PkgInfo

install: all
	rm -rf "/Applications/RTL Wireless.app"
	cp -R $(APP) "/Applications/RTL Wireless.app"
	rm -rf /System/Library/Extensions/RTL8187.kext
	cp -R $(KEXT) /System/Library/Extensions/
	chown -R root:wheel /System/Library/Extensions/RTL8187.kext
	chmod -R go-w /System/Library/Extensions/RTL8187.kext
	mkdir -p /usr/local/bin
	cp $(TOOL) /usr/local/bin/rtlwifi
	rm -f /System/Library/Extensions.kextcache /System/Library/Extensions.mkext
	touch /System/Library/Extensions
	@echo "Installed.  Restart the Mac, then plug in the adapter."

uninstall:
	rm -rf /System/Library/Extensions/RTL8187.kext /usr/local/bin/rtlwifi
	rm -rf "/Applications/RTL Wireless.app"
	rm -f /System/Library/Extensions.kextcache /System/Library/Extensions.mkext
	touch /System/Library/Extensions

# --- tests (portable) ---------------------------------------------------
TEST_SRC = tests/test_core.c $(CORE_SRC)

test: $(TEST_SRC) tests/vectors.h $(CORE_HDR)
	@mkdir -p $(BUILD)
	$(CC) -O2 -Wall $(TEST_CFLAGS) $(TEST_SRC) -o $(BUILD)/test_core
	$(BUILD)/test_core

test-ppc: $(TEST_SRC) tests/vectors.h $(CORE_HDR)
	@mkdir -p $(BUILD)
	powerpc-linux-gnu-gcc -O2 -Wall -static $(TEST_SRC) -o $(BUILD)/test_core_ppc
	qemu-ppc $(BUILD)/test_core_ppc

# Regenerate the expected values from the independent Python model.
vectors:
	python3 tests/gen_vectors.py > tests/vectors.h

clean:
	rm -rf $(BUILD)

.PHONY: all kext tool app install uninstall test test-ppc vectors clean
