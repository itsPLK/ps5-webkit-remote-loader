# PS5 WebKit Remote Loader - Native Installer ELF Makefile

PYTHON := python3
ifndef BUILD_VERSION
BUILD_VERSION := $(shell $(PYTHON) tools/gen_version.py --print)
endif
export BUILD_VERSION
CC     := /opt/ps5-payload-sdk/bin/prospero-clang
STRIP  := /opt/ps5-payload-sdk/bin/prospero-strip

SDK        := /opt/ps5-payload-sdk
TARGET     := $(SDK)/target
INSTALLER_COMMON := installer/common
include $(INSTALLER_COMMON)/common.mk

STAGE_DIR := installer/dist

INCLUDES := -Iinstaller/include -I$(INSTALLER_COMMON) -I$(TARGET)/include -I. -Iinstaller
LIBS     := $(TARGET)/lib/libmicrohttpd.a \
            -L$(TARGET)/lib -lpthread \
            -lSceNetCtl -lSceUserService -lSceSystemService \
            -lSceAppInstUtil

SRCS := installer/src/main.c \
        installer/src/http_server.c \
        $(INSTALLER_COMMON_SRCS)

ELF := installer.elf

FILE_REGISTRY_H := installer/include/file_registry.h
FILE_REGISTRY_C := installer/include/file_registry.c
FILE_REGISTRY_STAMP := installer/include/.file_registry.stamp
VERSION_HEADER := installer/include/wkrli_version.h

ICON0 := installer/assets/icon0.png
ICON_ICO := installer/assets/icon.ico

CFLAGS  := -Os -Wall -ffunction-sections -fdata-sections $(INCLUDES)
LDFLAGS := -Wl,--gc-sections

all: $(ELF)

.PHONY: version icons clean

version:
	$(PYTHON) tools/gen_version.py

icons: $(ICON0) $(ICON_ICO)

$(ICON0) $(ICON_ICO): installer/assets/icon.svg tools/gen_icons.py
	$(PYTHON) tools/gen_icons.py

$(FILE_REGISTRY_H) $(FILE_REGISTRY_C): $(FILE_REGISTRY_STAMP)

$(FILE_REGISTRY_STAMP): version icons
	@echo "Staging Remote Loader into $(STAGE_DIR)..."
	@V="$(BUILD_VERSION)"; \
	rm -rf $(STAGE_DIR) && \
	mkdir -p $(STAGE_DIR)/app/$$V && \
	cp -R installer/frontend/installer-page/. $(STAGE_DIR)/ && \
	cp -R installer/frontend/pointer/. $(STAGE_DIR)/app/ && \
	cp index.html $(STAGE_DIR)/app/$$V/ && \
	cp -R src $(STAGE_DIR)/app/$$V/ && \
	cp -R offsets $(STAGE_DIR)/app/$$V/ && \
	cp -R shared $(STAGE_DIR)/app/$$V/ && \
	if [ -d payloads ]; then cp -R payloads $(STAGE_DIR)/app/$$V/; fi && \
	mkdir -p $(STAGE_DIR)/app/$$V/tools && \
	cp tools/send.py $(STAGE_DIR)/app/$$V/tools/ && \
	echo "$$V" > $(STAGE_DIR)/VERSION
	@echo "Generating file registry from $(STAGE_DIR)..."
	$(PYTHON) tools/gen_installer_registry.py $(STAGE_DIR) $(FILE_REGISTRY_H) $(FILE_REGISTRY_C)
	@touch $(FILE_REGISTRY_STAMP)

$(ELF): $(FILE_REGISTRY_H) $(FILE_REGISTRY_C) $(SRCS) $(ICON0) $(wildcard installer/include/*.h) $(INSTALLER_COMMON_HEADERS)
	@echo "Building $(ELF)..."
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(ELF) $(SRCS) $(FILE_REGISTRY_C) $(LIBS)
	@echo "Stripping $(ELF)..."
	$(STRIP) $(ELF)

clean:
	rm -rf $(STAGE_DIR)
	rm -f $(ELF) $(FILE_REGISTRY_H) $(FILE_REGISTRY_C) $(FILE_REGISTRY_STAMP) $(VERSION_HEADER) installer/assets/param.json installer/assets/icon0.png installer/assets/icon.ico
