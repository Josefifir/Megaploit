# megaploit/native/kiwi/Makefile
# ================================
# Cross-platform build for megaploit_kiwi.c
#
# Targets
# -------
#   make              → build for current platform (auto-detect)
#   make windows      → cross-compile Windows EXE with MinGW-w64
#   make linux        → build Linux stub (no-op; compile-test only)
#   make clean        → remove build artefacts
#
# Prerequisites
# -------------
#   Windows native:   MinGW-w64 gcc  OR  MSVC cl.exe
#   Windows cross:    x86_64-w64-mingw32-gcc  (on Linux)
#   Linux native:     gcc (produces a no-op stub that prints a message and exits)

SRC      := megaploit_kiwi.c
WIN_OUT  := megaploit_kiwi.exe
LIN_OUT  := megaploit_kiwi

CC_WIN   := x86_64-w64-mingw32-gcc
CC_LIN   := gcc

# Windows: link against all required system libs
WIN_CFLAGS  := -std=c11 -O2 -Wall -Wextra -DWIN32 -D_WIN32 -DUNICODE -D_UNICODE \
               -D_WIN32_WINNT=0x0600
WIN_LDFLAGS := -lntdll -ladvapi32 -lsecur32 -lnetapi32 -lcrypt32 \
               -lkernel32 -lpsapi -luserenv -lws2_32

# Linux stub: no special flags needed
LIN_CFLAGS  := -std=c11 -O2 -Wall -Wextra

# ── Auto-detect platform ──────────────────────────────────────────────────
ifeq ($(OS),Windows_NT)
    # Running on Windows — prefer native MinGW
    CC      := gcc
    OUT     := $(WIN_OUT)
    CFLAGS  := $(WIN_CFLAGS)
    LDFLAGS := $(WIN_LDFLAGS)
else
    # Linux/macOS — detect whether cross-compiler is available
    HAS_MINGW := $(shell command -v $(CC_WIN) 2>/dev/null)
    ifneq ($(HAS_MINGW),)
        # Cross-compile Windows EXE on Linux
        CC      := $(CC_WIN)
        OUT     := $(WIN_OUT)
        CFLAGS  := $(WIN_CFLAGS)
        LDFLAGS := $(WIN_LDFLAGS)
    else
        # Native Linux stub build
        CC      := $(CC_LIN)
        OUT     := $(LIN_OUT)
        CFLAGS  := $(LIN_CFLAGS)
        LDFLAGS :=
    endif
endif

# ── Default target ────────────────────────────────────────────────────────
all: $(OUT)
	@echo "[+] Built: $(OUT)"

$(WIN_OUT): $(SRC)
	$(CC_WIN) $(WIN_CFLAGS) -o $@ $< $(WIN_LDFLAGS)
	@echo "[+] Windows build: $@"

$(LIN_OUT): $(SRC)
	$(CC_LIN) $(LIN_CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "[+] Linux build (stub): $@"

# ── Explicit targets ──────────────────────────────────────────────────────
windows: $(WIN_OUT)

linux: $(LIN_OUT)

# ── MSVC build (Windows native, optional) ────────────────────────────────
msvc:
	cl.exe /Fe:$(WIN_OUT) /std:c11 /O2 /W3 \
	    /D UNICODE /D _UNICODE /D _WIN32_WINNT=0x0600 \
	    $(SRC) \
	    ntdll.lib advapi32.lib secur32.lib netapi32.lib \
	    crypt32.lib kernel32.lib psapi.lib userenv.lib ws2_32.lib

# ── Clean ─────────────────────────────────────────────────────────────────
clean:
	-rm -f $(WIN_OUT) $(LIN_OUT) *.o

.PHONY: all windows linux msvc clean
