/**
 * NT type definitions for syscall wrappers — no CRT, no kernel32/advapi32.
 * Only defines what MinGW's <windows.h> does NOT provide.
 */
#ifndef NTDEFS_H
#define NTDEFS_H

#include <windows.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

/* ── NT types not in MinGW headers ───────────────────────── */

typedef struct _NT_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} NT_UNICODE_STRING, *PNT_UNICODE_STRING;

/* Use our own names to avoid any collision */
#define UNICODE_STRING NT_UNICODE_STRING
#define PUNICODE_STRING PNT_UNICODE_STRING

typedef struct _NT_OBJECT_ATTRIBUTES {
    ULONG            Length;
    HANDLE           RootDirectory;
    PUNICODE_STRING  ObjectName;
    ULONG            Attributes;
    PVOID            SecurityDescriptor;
    PVOID            SecurityQualityOfService;
} NT_OBJECT_ATTRIBUTES, *PNT_OBJECT_ATTRIBUTES;

#define OBJECT_ATTRIBUTES NT_OBJECT_ATTRIBUTES
#define POBJECT_ATTRIBUTES PNT_OBJECT_ATTRIBUTES

typedef struct _NT_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} NT_CLIENT_ID, *PNT_CLIENT_ID;

#define CLIENT_ID NT_CLIENT_ID
#define PCLIENT_ID PNT_CLIENT_ID

typedef struct _NT_IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} NT_IO_STATUS_BLOCK, *PNT_IO_STATUS_BLOCK;

#define IO_STATUS_BLOCK NT_IO_STATUS_BLOCK
#define PIO_STATUS_BLOCK PNT_IO_STATUS_BLOCK

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}
#endif

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040
#endif

/* ── PEB structures ──────────────────────────────────────── */

typedef struct _NT_PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} NT_PEB_LDR_DATA, *PNT_PEB_LDR_DATA;

typedef struct _NT_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG      Flags;
    USHORT     LoadCount;
    USHORT     TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG      TimeDateStamp;
} NT_LDR_DATA_TABLE_ENTRY, *PNT_LDR_DATA_TABLE_ENTRY;

#define PEB_LDR_DATA NT_PEB_LDR_DATA
#define PPEB_LDR_DATA PNT_PEB_LDR_DATA
#define LDR_DATA_TABLE_ENTRY NT_LDR_DATA_TABLE_ENTRY
#define PLDR_DATA_TABLE_ENTRY PNT_LDR_DATA_TABLE_ENTRY

typedef struct _NT_RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} NT_RTL_USER_PROCESS_PARAMETERS, *PNT_RTL_USER_PROCESS_PARAMETERS;

#define RTL_USER_PROCESS_PARAMETERS NT_RTL_USER_PROCESS_PARAMETERS
#define PRTL_USER_PROCESS_PARAMETERS PNT_RTL_USER_PROCESS_PARAMETERS

/*
 * PEB layout for x64:
 *   +0x18: Ldr
 *   +0x20: ProcessParameters
 *   +0x118: OSMajorVersion (ULONG)
 *   +0x11C: OSMinorVersion (ULONG)
 *   +0x120: OSBuildNumber (USHORT)
 */
typedef struct _NT_PEB {
    BYTE                          Reserved1[2];    /* +0x00 */
    BYTE                          BeingDebugged;   /* +0x02 */
    BYTE                          Reserved2[1];    /* +0x03 */
    PVOID                         Reserved3[2];    /* +0x08 */
    PPEB_LDR_DATA                 Ldr;             /* +0x18 */
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters; /* +0x20 */
    BYTE                          Reserved4[0xF0]; /* padding to 0x118 */
    ULONG                         OSMajorVersion;  /* +0x118 */
    ULONG                         OSMinorVersion;  /* +0x11C */
    USHORT                        OSBuildNumber;   /* +0x120 */
} NT_PEB, *PNT_PEB;

#define PEB NT_PEB
#define PPEB PNT_PEB

/* ── Process information ─────────────────────────────────── */

typedef struct _NT_PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PPEB      PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    HANDLE    UniqueProcessId;
    HANDLE    InheritedFromUniqueProcessId;
} NT_PROCESS_BASIC_INFORMATION;

#define PROCESS_BASIC_INFORMATION NT_PROCESS_BASIC_INFORMATION

#define ProcessBasicInformation 0

/* ── Constants (guarded to avoid redefinition) ───────────── */

#ifndef MEM_COMMIT
#define MEM_COMMIT  0x1000
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE 0x2000
#endif
#ifndef MEM_RELEASE
#define MEM_RELEASE 0x8000
#endif
#ifndef PAGE_GUARD
#define PAGE_GUARD  0x100
#endif
#ifndef PAGE_READWRITE
#define PAGE_READWRITE 0x04
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif

/* ── File information classes ────────────────────────────── */

#define FileStandardInformation     5
#define FileDispositionInformation 13
#define FileRenameInformation      10

/* ── File/pipe constants (guarded) ───────────────────────── */

#ifndef FILE_OPEN
#define FILE_OPEN            1
#endif
#ifndef FILE_CREATE
#define FILE_CREATE          2
#endif
#ifndef FILE_OPEN_IF
#define FILE_OPEN_IF         3
#endif
#ifndef FILE_OVERWRITE_IF
#define FILE_OVERWRITE_IF    5
#endif

#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT   0x00000020
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE        0x00000040
#endif
#ifndef FILE_DELETE_ON_CLOSE
#define FILE_DELETE_ON_CLOSE            0x00001000
#endif

#ifndef FILE_SHARE_READ
#define FILE_SHARE_READ    0x00000001
#endif
#ifndef FILE_SHARE_WRITE
#define FILE_SHARE_WRITE   0x00000002
#endif
#ifndef FILE_SHARE_DELETE
#define FILE_SHARE_DELETE   0x00000004
#endif

#ifndef FILE_ATTRIBUTE_NORMAL
#define FILE_ATTRIBUTE_NORMAL 0x00000080
#endif

#define FSCTL_PIPE_LISTEN 0x00110008

/* ── Registry constants ──────────────────────────────────── */

#ifndef KEY_READ
#define KEY_READ 0x20019
#endif

/* ── Token / privilege constants ─────────────────────────── */

#ifndef SE_PRIVILEGE_ENABLED
#define SE_PRIVILEGE_ENABLED 0x00000002
#endif
#ifndef TOKEN_ADJUST_PRIVILEGES
#define TOKEN_ADJUST_PRIVILEGES 0x0020
#endif
#ifndef TOKEN_QUERY
#define TOKEN_QUERY 0x0008
#endif

/* SeBackupPrivilege LUID = {17, 0} */
#define SE_BACKUP_PRIVILEGE_LUID_LOW  17
#define SE_BACKUP_PRIVILEGE_LUID_HIGH 0

/* ── Security descriptor helpers (use MinGW's SD struct) ─── */

#ifndef SE_DACL_PRESENT
#define SE_DACL_PRESENT 0x0004
#endif
#ifndef SECURITY_DESCRIPTOR_REVISION
#define SECURITY_DESCRIPTOR_REVISION 1
#endif

/* ── File info structures (not in MinGW) ─────────────────── */

typedef struct _NT_FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} NT_FILE_STANDARD_INFORMATION;

#define FILE_STANDARD_INFORMATION NT_FILE_STANDARD_INFORMATION

typedef struct _NT_FILE_DISPOSITION_INFORMATION {
    BOOLEAN DeleteFile;
} NT_FILE_DISPOSITION_INFORMATION;

#define FILE_DISPOSITION_INFORMATION NT_FILE_DISPOSITION_INFORMATION

typedef struct _NT_FILE_RENAME_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE  RootDirectory;
    ULONG   FileNameLength;
    WCHAR   FileName[1];
} NT_FILE_RENAME_INFORMATION;

#define FILE_RENAME_INFORMATION NT_FILE_RENAME_INFORMATION

/* ── KUSER_SHARED_DATA for tick count ────────────────────── */

#define KUSER_SHARED_DATA_ADDR  0x7FFE0000
#define TICK_COUNT_LOW_OFFSET   0x320

/* ── Memory info class ───────────────────────────────────── */

#define MemoryBasicInformation 0

/* ── ACL/ACE definitions for manual DACL construction ────── */

#ifndef ACL_REVISION
#define ACL_REVISION 2
#endif

#ifndef ACCESS_ALLOWED_ACE_TYPE
#define ACCESS_ALLOWED_ACE_TYPE 0
#endif

#ifndef _ACE_HEADER_DEFINED
#define _ACE_HEADER_DEFINED
typedef struct _ACE_HEADER {
    BYTE  AceType;
    BYTE  AceFlags;
    WORD  AceSize;
} ACE_HEADER;
#endif

#ifndef _ACCESS_ALLOWED_ACE_DEFINED
#define _ACCESS_ALLOWED_ACE_DEFINED
typedef struct _ACCESS_ALLOWED_ACE {
    ACE_HEADER  Header;
    ACCESS_MASK Mask;
    DWORD       SidStart;
} ACCESS_ALLOWED_ACE;
#endif

#endif /* NTDEFS_H */
