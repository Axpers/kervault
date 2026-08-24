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

pydump deploys a lightweight native agent (24KB, x64) on the target as a
temporary Windows service. The agent performs **all privileged operations**
locally:

1. **Registry hives**: enables `SeBackupPrivilege`, calls `RegSaveKeyW` to
   snapshot SAM/SYSTEM/SECURITY, reads them into memory, deletes temp files
2. **LSASS memory**: reads process memory using indirect syscalls, builds a
   MiniDump in-memory
3. **Exfiltration**: streams everything back through a named pipe using a
   binary protocol (`PYD\x01` header + hive data + MDMP)
4. **Cleanup**: self-deletes from disk via ADS rename before exiting

The Python orchestrator handles deployment (SMB upload + service creation),
receives the pipe data, then parses and decrypts offline — no direct
registry or process access from the network.

## Architecture

```
ORCHESTRATOR (Linux/Python)                   TARGET (Windows)
┌──────────────────────┐         SMB 445      ┌──────────────────────┐
│  pydump CLI          │◄───────────────────►│                      │
│                      │                      │  SVCCTL → Service    │
│  ┌─ agent output ──┐ │   upload + execute   │  ┌─────────────────┐ │
│  │ hives → decrypt  │ │─────────────────────►│  │ agent.exe       │ │
│  │ LSASS → parse    │ │◄─────────────────────│  │ RegSaveKey      │ │
│  └─────────────────┘ │   named pipe stream  │  │ LSASS dump      │ │
│                      │   (hives + MDMP)     │  │ ETW patch       │ │
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
│   ├── core.py         DCE/RPC bind/request
│   ├── ndr.py          NDR encoding
│   └── svcctl.py       Service Control Manager
├── secrets/
│   ├── hivereader.py   Custom REGF hive parser
│   ├── crypto.py       Boot key, SAM/LSA AES/DES/RC4 decrypt
│   └── registry.py     SAM + LSA orchestration
├── dump/
│   └── methods.py      Agent deployment + pipe read
└── parser/
    ├── minidump.py     MDMP format parser
    └── extract.py      Credential extraction (MSV1.0, WDigest)

agent/                  24KB x64 PE, MinGW cross-compiled
├── src/
│   ├── main.c          Entry, protocol, self-delete
│   ├── syscalls.c      Hell's Gate SSN resolution, ETW patch
│   ├── registry.c      RegSaveKey hive extraction
│   ├── dump.c          LSASS memory read → MDMP stream
│   └── pipe.c          Named pipe server
└── include/
    ├── syscalls.h      DJB2 hash constants, syscall table
    ├── agent.h         MDMP structures
    └── ntdefs.h        NT type definitions
```

## Installation

```bash
virtualenv env && source env/bin/activate
pip install -r requirements.txt

# Build agent (requires x86_64-w64-mingw32-gcc)
cd agent && make cross
```

Dependencies: `smbprotocol` + `pycryptodome` only.

## Usage

```bash
# Full extraction (registry + LSASS)
python main.py dump -t 192.168.1.50 -u admin -p 'P@ssw0rd'

# Registry only (no LSASS, no PID lookup)
python main.py dump -t 192.168.1.50 -u admin -p 'P@ssw0rd' -m registry

# Save raw LSASS dump
python main.py dump -t 192.168.1.50 -u admin -p pass -o lsass.dmp

# Pass-the-Hash
python main.py dump -t 192.168.1.50 -u admin -H aad3b435b51404eeaad3b435b51404ee

# Parse existing dump offline
python main.py parse -f lsass.dmp
```

## Agent internals

| Technique | Detail |
|---|---|
| Indirect syscalls | SSN resolved via Hell's Gate / Halo's Gate from ntdll PEB walk |
| API hashing | All Nt* exports resolved by DJB2 hash — zero plaintext function names |
| ETW patch | `EtwEventWrite` overwritten with `xor eax,eax; ret` via `NtProtectVirtualMemory` |
| Self-delete | ADS rename + `FileDispositionInfo` — binary removed before `ExitProcess` |
| No CRT | `-nostdlib -nostartfiles`, 24KB binary |

## Requirements

- Python >= 3.11
- Admin credentials on target (password or NT hash)
- SMB port 445 open

## Disclaimer

This tool is designed for IT forensics and authorized credential auditing on systems you own or manage. Unauthorized use on third-party systems is illegal.
