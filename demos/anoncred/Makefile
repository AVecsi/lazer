.PHONY: all clean

LAZER_DIR = ../..
SRC_DIR = $(LAZER_DIR)/src

# Platform detection (mirrors the top-level Makefile).
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
UNAME_O := $(shell uname -o 2>/dev/null)

ifneq (,$(filter arm64 aarch64 arm,$(UNAME_M)))
CFLAGS_ARCH = -mcpu=native
else
CFLAGS_ARCH = -march=native -mtune=native
endif

# C++ runtime: libstdc++ (glibc) / libc++ (macOS) / libc++_shared (Termux).
CXXLIB = -lstdc++
ifeq ($(UNAME_S),Darwin)
CXXLIB = -lc++
endif
ifeq ($(UNAME_O),Android)
CXXLIB = -lc++_shared
endif

# HEXL static lib lives under lib/ (macOS) or lib64/ (Linux).
HEXL_LIB = $(shell ls $(LAZER_DIR)/third_party/hexl-development/build/hexl/lib64/libhexl.a 2>/dev/null || ls $(LAZER_DIR)/third_party/hexl-development/build/hexl/lib/libhexl.a 2>/dev/null)

CFLAGS = -Wall -Wextra -O3 -g $(CFLAGS_ARCH) -I$(LAZER_DIR) -I$(SRC_DIR)
LIBS = $(LAZER_DIR)/liblazer.a -lm $(HEXL_LIB) $(CXXLIB) -lmpfr -lgmp

all: anoncred-demo

anoncred-demo: anoncred-demo.c $(SRC_DIR)/anoncred.c $(SRC_DIR)/anoncred.h \
               $(SRC_DIR)/anoncred-params.h $(LAZER_DIR)/liblazer.a
	$(CC) $(CFLAGS) -o $@ anoncred-demo.c $(SRC_DIR)/anoncred.c $(LIBS)

clean:
	rm -f anoncred-demo
