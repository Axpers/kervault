# pydump

Remote Windows credential extraction over SMB — SAM/LSA secrets + LSASS memory dump.

Zero external tool dependencies. No impacket, no nxc, no lsassy.

## Features

- **SAM hashes** — RegSaveKey + offline REGF parse + AES/DES decrypt (verified against nxc)
- **LSA secrets** — DPAPI keys, service passwords, NL$KM
- **LSASS dump** — native C agent, indirect syscalls, dump streamed via named pipe
- **LSASS parser** — custom MDMP parser, NTLM + WDigest extraction (Win11 24H2)
- **Pass-the-Hash** — `-H` flag, no password needed

## How it works

pydump deploys a lightweight native agent (~12KB, x64) on the target as a
temporary Windows service. The agent performs **all privileged operations**
locally:

1. **Registry hives**: enables `SeBackupPrivilege`, uses NT syscalls
   (`NtOpenKey` / `NtSaveKey`) to snapshot SAM/SYSTEM/SECURITY into
   temp files with `FILE_DELETE_ON_CLOSE`, reads them into memory
2. **LSASS memory**: reads process memory using indirect syscalls, builds a
   MiniDump in-memory
3. **Exfiltration**: streams everything back through a named pipe, XOR-encrypted
   with the pipe name as a rolling key
4. **Cleanup**: self-deletes from disk via ADS rename before exiting

The Python orchestrator handles deployment (SMB upload + scheduled task creation
via TSCH RPC), receives the encrypted pipe data, decrypts and parses offline —
no direct registry or process access from the network.

## Architecture

```
ORCHESTRATOR (Linux/Python)                   TARGET (Windows)
┌──────────────────────┐         SMB 445      ┌──────────────────────┐
│  pydump CLI          │◄────────────────────►│                      │
│                      │                      │  TSCH → Sched. Task  │
│  ┌─ agent output ──┐ │   upload + execute   │  ┌─────────────────┐ │
│  │ XOR decrypt     │ │─────────────────────►│  │ agent.exe       │ │
│  │ hives → decrypt │ │◄─────────────────────│  │ NT syscalls     │ │
│  │ LSASS → parse   │ │ XOR-encrypted stream │  │ LSASS dump      │ │
│  └─────────────────┘ │ (hives + MDMP)       │  │ ETW patch       │ │
│                      │                      │  │ self-delete     │ │
└──────────────────────┘                      │  └─────────────────┘ │
                                              └──────────────────────┘
```

### Project structure

```
pydump/                 Python orchestrator
├── cli.py              CLI (dump, parse)
├── smb.py              SMB session, named pipes, file I/O
├── rpc/
│   ├── core.py         DCE/RPC bind/request (bare + PKT_PRIVACY sealed)
│   ├── ndr.py          NDR encoding
│   ├── ntlm.py         NTLMv2 auth + seal/unseal (no impacket)
│   ├── svcctl.py       Service Control Manager (used for LSASS PID query)
│   └── tsch.py         Task Scheduler (agent execution, avoids Event 7045)
├── secrets/
│   ├── hivereader.py   Custom REGF hive parser
│   ├── crypto.py       Boot key, SAM/LSA AES/DES/RC4 decrypt
│   └── registry.py     SAM + LSA orchestration
├── dump/
│   └── methods.py      Agent deployment + pipe read + XOR decrypt
└── parser/
    ├── minidump.py     MDMP format parser
    └── extract.py      Credential extraction (MSV1.0, WDigest)

agent/                  ~12KB x64 PE, MinGW cross-compiled
├── src/
│   ├── main.c          Entry, protocol, self-delete
│   ├── syscalls.c      Hell's Gate SSN resolution, ETW patch
│   ├── syscalls_gas.S  Indirect syscall stubs (GAS, 4 variants by arg count)
│   ├── syscalls.asm    Indirect syscall stubs (MASM, for MSVC builds)
│   ├── registry.c      NT syscall hive extraction (NtOpenKey/NtSaveKey)
│   ├── dump.c          LSASS memory read → MDMP stream
│   └── pipe.c          Named pipe server, restricted DACL, XOR cipher
└── include/
    ├── syscalls.h      DJB2 hash constants, syscall table
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
| Pure NT syscalls | No Win32 API — registry, pipes, files, all via Nt* syscalls |
| ETW patch | `EtwEventWrite` overwritten with `xor eax,eax; ret` via `NtProtectVirtualMemory` |
| Wire encryption | Rolling XOR cipher keyed on pipe name — no plaintext signatures on the wire |
| Restricted DACL | Pipe access limited to SYSTEM + BUILTIN\Administrators (no NULL DACL) |
| Self-delete | ADS rename + `FileDispositionInfo` — binary removed before `ExitProcess` |
| PE hardening | `.comment` stripped, sections renamed, PE timestamp zeroed, `-fno-ident` |
| Frame pointer omission | `-fomit-frame-pointer` — RBP-based stack walkers cannot trace frames |
| TSCH execution | Agent launched via scheduled task (MS-TSCH RPC), not SVCCTL — avoids Event 7045 |
| Stealth naming | Task path/pipe/agent names mimic legitimate Windows components |
| No CRT | `-nostdlib -nostartfiles`, ~12KB binary |

## Requirements

- Python >= 3.11
- Admin credentials on target (password or NT hash)
- SMB port 445 open

## Disclaimer

This tool is designed for IT forensics and authorized credential auditing on systems you own or manage. Unauthorized use on third-party systems is illegal.
