# pydump agent — Native LSASS dumper with indirect syscalls
#
# Build requirements:
#   - Visual Studio Build Tools (cl.exe, ml64.exe, link.exe)
#   - Windows SDK
#
# Build:
#   nmake          (from VS Developer Command Prompt)
#
# Or with MinGW cross-compilation from Linux:
#   make cross     (requires x86_64-w64-mingw32-gcc)

# ─── MSVC Build ─────────────────────────────────────────────

CC = cl.exe
ASM = ml64.exe
LINK = link.exe

CFLAGS = /nologo /O1 /GS- /W3 /I include
ASMFLAGS = /nologo /c
LDFLAGS = /nologo /ENTRY:main_entry /SUBSYSTEM:CONSOLE /NODEFAULTLIB

LIBS = kernel32.lib ntdll.lib advapi32.lib

SRC = src/main.c src/syscalls.c src/dump.c src/pipe.c src/registry.c
ASM_SRC = src/syscalls.asm
OBJS = build/main.obj build/syscalls.obj build/dump.obj build/pipe.obj build/registry.obj build/syscalls_asm.obj

OUT = bin/agent.exe

all: dirs $(OUT)

dirs:
	@if not exist build mkdir build
	@if not exist bin mkdir bin

build/main.obj: src/main.c
	$(CC) $(CFLAGS) /c /Fo$@ $**

build/syscalls.obj: src/syscalls.c
	$(CC) $(CFLAGS) /c /Fo$@ $**

build/dump.obj: src/dump.c
	$(CC) $(CFLAGS) /c /Fo$@ $**

build/pipe.obj: src/pipe.c
	$(CC) $(CFLAGS) /c /Fo$@ $**

build/registry.obj: src/registry.c
	$(CC) $(CFLAGS) /c /Fo$@ $**

build/syscalls_asm.obj: src/syscalls.asm
	$(ASM) $(ASMFLAGS) /Fo$@ $**

$(OUT): $(OBJS)
	$(LINK) $(LDFLAGS) /OUT:$@ $** $(LIBS)

clean:
	@if exist build rmdir /s /q build
	@if exist bin rmdir /s /q bin

# ─── MinGW Cross-Compilation (from Linux) ───────────────────

CROSS_CC = x86_64-w64-mingw32-gcc
CROSS_CFLAGS = -O1 -s -nostdlib -Iinclude -Wall
CROSS_LDFLAGS = -nostartfiles -lkernel32 -lntdll -ladvapi32 -e main_entry

cross: dirs_cross
	nasm -f win64 src/syscalls.asm -o build/syscalls_asm.o 2>/dev/null || \
		$(CROSS_CC) -c src/syscalls_gas.S -o build/syscalls_asm.o
	$(CROSS_CC) $(CROSS_CFLAGS) -c src/main.c -o build/main.o
	$(CROSS_CC) $(CROSS_CFLAGS) -c src/syscalls.c -o build/syscalls.o
	$(CROSS_CC) $(CROSS_CFLAGS) -c src/dump.c -o build/dump.o
	$(CROSS_CC) $(CROSS_CFLAGS) -c src/pipe.c -o build/pipe.o
	$(CROSS_CC) $(CROSS_CFLAGS) -c src/registry.c -o build/registry.o
	$(CROSS_CC) -o bin/agent.exe build/main.o build/syscalls.o build/dump.o build/pipe.o build/registry.o build/syscalls_asm.o $(CROSS_LDFLAGS)

dirs_cross:
	@mkdir -p build bin

.PHONY: all clean cross dirs dirs_cross
