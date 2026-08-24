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

pydump combines two extraction methods, both over a single SMB connection:

**Registry secrets** (SAM/LSA) are extracted via Windows RPC: the tool calls
`RegSaveKey` to save hive snapshots, reads them over SMB, then parses and decrypts
offline. This uses standard Windows administration APIs and requires no executable
on the target.

**LSASS memory** requires a native agent (19KB, x64) deployed as a temporary
service. The agent reads LSASS process memory using indirect syscalls, builds a
MiniDump in-memory, streams it back through a named pipe, then self-deletes.
No dump file is written to disk.

## Architecture

```
ORCHESTRATOR (Linux/Python)                   TARGET (Windows)
┌──────────────────────┐         SMB 445      ┌──────────────────────┐
│  pydump CLI          │◄───────────────────►│                      │
│                      │                      │  SVCCTL → Service    │
│  ┌─ registry ──────┐ │   WinReg RPC        │  ┌─────────────────┐ │
│  │ SAM + LSA       │ │◄────────────────────►│  │ RegSaveKey      │ │
│  │ offline decrypt │ │   hive snapshots     │  │ SAM/SYSTEM/SEC  │ │
│  └─────────────────┘ │                      │  └─────────────────┘ │
│                      │                      │                      │
│  ┌─ agent ─────────┐ │   upload + execute   │  ┌─────────────────┐ │
│  │ LSASS → parse   │ │─────────────────────►│  │ agent.exe       │ │
│  │ NTLM + WDigest  │ │◄─────────────────────│  │ indirect syscall│ │
│  └─────────────────┘ │   named pipe stream  │  │ ETW patch       │ │
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
│   ├── svcctl.py       Service Control Manager
│   └── winreg.py       Remote Registry (RegSaveKey)
├── secrets/
│   ├── hivereader.py   Custom REGF hive parser
│   ├── crypto.py       Boot key, SAM/LSA AES/DES/RC4 decrypt
│   └── registry.py     SAM + LSA orchestration
├── dump/
│   └── methods.py      Agent deployment + pipe read
└── parser/
    ├── minidump.py     MDMP format parser
    └── extract.py      Credential extraction (MSV1.0, WDigest)

agent/                  Native x64 agent (19KB, no CRT)
├── src/
│   ├── main.c          Entry, self-delete (ADS rename)
│   ├── syscalls.c      Hell's Gate SSN resolution, ETW patch
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
python -m pydump dump -t 192.168.1.50 -u admin -p 'P@ssw0rd'

# Registry only (SAM + LSA, no agent needed)
python -m pydump dump -t 192.168.1.50 -u admin -p 'P@ssw0rd' -m registry

# LSASS only
python -m pydump dump -t 192.168.1.50 -u admin -p pass -m pipe

# Pass-the-Hash
python -m pydump dump -t 192.168.1.50 -u admin -H aad3b435b51404eeaad3b435b51404ee

# Save raw LSASS dump
python -m pydump dump -t 192.168.1.50 -u admin -p pass -o lsass.dmp

# Parse existing dump offline
python -m pydump parse -f lsass.dmp
```

## Agent internals

| Technique | Detail |
|---|---|
| Indirect syscalls | SSN resolved via Hell's Gate / Halo's Gate from ntdll PEB walk |
| API hashing | All Nt* exports resolved by DJB2 hash — zero plaintext function names |
| ETW patch | `EtwEventWrite` overwritten with `xor eax,eax; ret` via `NtProtectVirtualMemory` |
| Self-delete | ADS rename + `FileDispositionInfo` — binary removed before `ExitProcess` |
| No CRT | `-nostdlib -nostartfiles`, 19KB PE |

## Requirements

- Python >= 3.11
- Admin credentials on target (password or NT hash)
- SMB port 445 open

## Disclaimer

This tool is designed for IT forensics and authorized credential auditing on systems you own or manage. Unauthorized use on third-party systems is illegal.
