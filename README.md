# kervault

Remote Windows credential extraction over SMB — SAM/LSA secrets + LSASS memory dump.

Zero external tool dependencies. No impacket, no nxc, no lsassy.

## Features

- **SAM hashes** — raw NTFS disk read of hive files + AES/DES decrypt (verified against nxc)
- **LSA secrets** — DPAPI keys, service passwords, NL$KM
- **LSASS dump** — BYOVD kernel driver reads LSASS via MmCopyVirtualMemory, zero `NtReadVirtualMemory`, zero EDR alerts
- **LSASS parser** — custom MDMP parser, MSV1.0 (NTLM) + WDigest extraction
- **Disk module injection** — lsasrv.dll .text loaded from disk via SMB for pattern scanning (no LSASS .text read)
- **Pass-the-Hash** — `-H` flag, no password needed

## How it works

kervault deploys a lightweight native agent (~44KB, x64) on the target. The agent
performs **all privileged operations** locally using only NT syscalls:

### Registry hives (--sam, --lsa)

Opens the raw `\\.\C:` volume and parses NTFS structures (boot sector, MFT,
directory indexes, data runs) to read SAM/SYSTEM/SECURITY hive files directly
from disk clusters — bypasses kernel file locks and EDR file filters. Agent
executed via Task Scheduler (MS-TSCH RPC, avoids Event 7045).

### LSASS memory (--lsass)

BYOVD (Bring Your Own Vulnerable Driver) approach with three layers of evasion:

1. **Driver load** — uploads a signed kernel driver (KKYUM.sys) via SMB to
   `System32\drivers\`, creates and starts a kernel driver service via SVCCTL
2. **ETW-Ti disable** — agent reads ntoskrnl.exe on disk to find
   `EtwThreatIntProvRegHandle` RVA, zeros it via the driver's kernel write
   primitive — kills the telemetry pipeline
3. **Direct process read** — agent reads LSASS memory via the driver's
   `MmCopyVirtualMemory` IOCTL (kernel-mode cross-process copy), completely
   bypassing `NtReadVirtualMemory` and the user-mode syscall layer

The process handle is opened with `PROCESS_QUERY_INFORMATION` only (no
`PROCESS_VM_READ`), so EDR OB callbacks have nothing to strip or alert on.
Memory reads go through the kernel driver, invisible to user-mode hooks.

Agent delivery uses a two-stage SCM failure action:

1. **Service stub** — agent registers as a Windows service (mode 16), reaches
   `SERVICE_RUNNING`, then exits with error code 1
2. **Failure action** — SCM spawns the real dump command as a LOCAL process
   (created by `services.exe`)

The Python orchestrator injects lsasrv.dll's `.text` section from disk (read
via SMB) as a synthetic memory segment — provides pattern signatures for the
credential extractor without ever touching LSASS `.text` in memory.

### Exfiltration

Output streamed through a temp file on disk, XOR-encrypted with the output name
as a rolling key. Self-deletes from disk via ADS rename + `FileDispositionInfo`
before exiting.

## Architecture

```
ORCHESTRATOR (Linux/Python)                   TARGET (Windows)
┌──────────────────────┐         SMB 445      ┌──────────────────────┐
│  kervault CLI        │◄────────────────────►│                      │
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
│  └─────────────────┘ │  SVCCTL → kernel     │  │ (LOCAL process) │ │
│                      │  driver service      │  └────────┬────────┘ │
│                      │                      │           │          │
│                      │                      │  ┌────────▼────────┐ │
│                      │                      │  │ KKYUM.sys       │ │
│                      │                      │  │ MmCopyVirtMem   │ │
│                      │◄─────────────────────│  │ → LSASS read    │ │
│                      │ XOR-encrypted output │  └─────────────────┘ │
└──────────────────────┘                      └──────────────────────┘
```

### Project structure

```
main.py                 Entry point
requirements.txt        Dependencies (smbprotocol, pycryptodome)

kervault/               Python orchestrator
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
│   └── methods.py      Agent deployment, BYOVD driver load, XOR decrypt
└── parser/
    ├── minidump.py     MDMP format parser
    └── extract.py      Credential extraction (MSV1.0, WDigest)

agent/                  ~44KB x64 PE, MinGW cross-compiled
├── Makefile            MSVC (nmake) + MinGW cross-compilation (make cross)
├── src/
│   ├── main.c          Entry, service stub (mode 16), BYOVD orchestration, self-delete
│   ├── byovd.c         BYOVD driver interface — ETW-Ti disable, kernel R/W, direct process read
│   ├── syscalls.c      Hell's Gate SSN resolution, ETW patch
│   ├── syscalls_gas.S  Indirect syscall stubs (GAS, 4 variants by arg count)
│   ├── syscalls.asm    Indirect syscall stubs (MASM, for MSVC builds)
│   ├── registry.c      Hive file reading — raw NTFS volume access
│   ├── ntfs.c          NTFS parser — boot sector, MFT, indexes, data runs
│   ├── dump.c          LSASS dump → MDMP stream (KKYUM or NtReadVirtualMemory)
│   └── pipe.c          Named pipe server, restricted DACL, XOR cipher
├── include/
│   ├── byovd.h         BYOVD types and API
│   ├── registry.h      Hive reader API
│   ├── syscalls.h      DJB2 hash constants, syscall table
│   ├── ntfs.h          Raw NTFS reader API
│   ├── agent.h         MDMP structures
│   └── ntdefs.h        NT type definitions, ACL/ACE structs
└── drivers/
    ├── KKYUM.sys        Signed kernel driver — MmCopyVirtualMemory (primary)
    ├── signeddrv.sys    Fallback driver — .data section R/W only
    └── RTCore64.sys     Fallback driver — MSI Afterburner
```

## Installation

```bash
virtualenv env && source env/bin/activate && pip install -r requirements.txt
```

Build agent (requires x86_64-w64-mingw32-gcc)
```
cd agent && make cross
```

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
python main.py -t 10.0.0.5 -u admin -p pass --sam --lsa --lsass

# Pass-the-Hash
python main.py -t 10.0.0.5 -u admin -H aad3b4...ef40 --sam --lsa
```

At least one flag is required. All of them can be combined, order doesn't matter.

## Agent internals

| Technique | Detail |
|---|---|
| Indirect syscalls | SSN resolved via Hell's Gate / Halo's Gate from ntdll PEB walk |
| Call stack spoofing | Synthetic ntdll return frame — `sub rsp,8` + `ret` gadget at [rsp] creates a double-ret chain through ntdll, masking the real caller |
| Stub variants | 4 asm stubs (0/2/7/10 stack shifts) matching NT arg counts — prevents stack corruption |
| API hashing | All Nt* exports resolved by DJB2 hash — zero plaintext function names |
| BYOVD kernel driver | KKYUM.sys loaded as kernel service — MmCopyVirtualMemory for arbitrary cross-process reads |
| ETW-Ti disable | EtwThreatIntProvRegHandle zeroed via kernel write — kills telemetry pipeline |
| Direct process read | LSASS memory read via kernel IOCTL, no NtReadVirtualMemory, no user-mode hooks |
| OB callback bypass | Handle opened with PROCESS_QUERY_INFORMATION only — OB callbacks have nothing to strip |
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
