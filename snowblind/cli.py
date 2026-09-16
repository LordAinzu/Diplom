"""Local provisioning, service entrypoints and a resumable user client."""
import argparse
import asyncio
import os
import secrets
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
import httpx
import uvicorn
from . import wire as w
from . import protocol as p
from .client import save_json, read_json, issue
from .signer import Signer


def provision(directory, identity_private, n=3, threshold=2, port=8000):
    if not 2 <= threshold <= n <= 32 or not 1024 <= port <= 65535-n:
        raise ValueError("require 2 <= threshold <= N <= 32 and valid ports")
    root = Path(directory)
    if root.exists():
        raise ValueError("use a new directory; provisioning never overwrites keys")
    coordinator_key = w.new_ed()
    node_keys = {i: (w.new_ed(), w.new_x()) for i in range(1, n+1)}
    group = dict(version=w.VERSION, id=secrets.token_hex(32), threshold=threshold,
                 identity_public=w.x_public(identity_private), coordinator_public=w.ed_public(coordinator_key),
                 nodes={str(i): dict(auth_public=w.ed_public(keys[0]), transport_public=w.x_public(keys[1]),
                                     url=f"http://127.0.0.1:{port+i}") for i, keys in node_keys.items()})
    client_token, admin_token = secrets.token_hex(32), secrets.token_hex(32)
    save_json(root/"group.json", group)
    save_json(root/"coordinator"/"config.json", dict(group=group, auth_private=coordinator_key,
              client_token=client_token, admin_token=admin_token, port=port))
    save_json(root/"client"/"config.json", dict(group=group, client_token=client_token, url=f"http://127.0.0.1:{port}"))
    save_json(root/"admin.json", dict(url=f"http://127.0.0.1:{port}", admin_token=admin_token))
    for i, (auth, transport) in node_keys.items():
        save_json(root/f"signer-{i}"/"config.json", dict(group=group, id=i, auth_private=auth,
                  transport_private=transport, identity_private=identity_private, port=port+i))
    return group


@contextmanager
def process_lock(path):
    """Refuse a second worker on the same database (including on Windows)."""
    with open(path, "a+b") as f:
        f.seek(0)
        f.write(b"0")
        f.flush()
        f.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            if os.name == "nt":
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def serve_all(root):
    root = Path(root)
    group = read_json(root/"group.json")
    children = []
    try:
        for name in [*(f"signer-{i}" for i in group["nodes"]), "coordinator"]:
            role = "coordinator" if name == "coordinator" else "signer"
            children.append(subprocess.Popen([sys.executable, "-m", "snowblind", "serve", role,
                "--config", str(root/name/"config.json")],
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
        print("Services started. Ctrl+C stops all child processes.", flush=True)
        # Wait without polling the filesystem. A failed child terminates the group.
        import time
        while all(poll.poll() is None for poll in children):
            time.sleep(0.5)
        raise RuntimeError("a service exited; check its output")
    except KeyboardInterrupt:
        pass
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            child.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description="Educational Snowblind SB+ services")
    sub = parser.add_subparsers(dest="command", required=True)
    key = sub.add_parser("identity-key")
    key.add_argument("--out", required=True)
    init = sub.add_parser("init")
    init.add_argument("--directory", required=True)
    init.add_argument("--identity-key", required=True)
    init.add_argument("--nodes", type=int, default=3)
    init.add_argument("--threshold", type=int, default=2)
    init.add_argument("--port", type=int, default=8000)
    serve = sub.add_parser("serve")
    serve.add_argument("role", choices=["signer", "coordinator"])
    serve.add_argument("--config", required=True)
    serve.add_argument("--host", default="127.0.0.1")
    all_cmd = sub.add_parser("serve-all")
    all_cmd.add_argument("--directory", required=True)
    allow = sub.add_parser("allow")
    allow.add_argument("--config", required=True)
    allow_source = allow.add_mutually_exclusive_group(required=True)
    allow_source.add_argument("--identity-file")
    allow_source.add_argument("--hash")
    dkg = sub.add_parser("dkg")
    dkg.add_argument("--admin", required=True)
    claim = sub.add_parser("issue")
    claim.add_argument("--config", required=True)
    claim.add_argument("--state", required=True)
    claim.add_argument("--identity-file")
    claim.add_argument("--message-file")
    verify = sub.add_parser("verify")
    verify.add_argument("--public-key", required=True)
    verify.add_argument("--message-file", required=True)
    verify.add_argument("--signature", required=True, help="97-byte signature as hex")
    args = parser.parse_args()
    if args.command == "identity-key":
        if Path(args.out).exists():
            raise ValueError("key file already exists")
        secret = w.new_x()
        save_json(args.out, dict(private=secret, public=w.x_public(secret)))
        print("Identity encryption key created; distribute privately to signers only.")
    elif args.command == "init":
        provision(args.directory, read_json(args.identity_key)["private"], args.nodes, args.threshold, args.port)
        print("Configuration created. No group signing secret has been generated yet.")
    elif args.command == "serve":
        from .apps import signer_app, coordinator_app
        config = read_json(args.config)
        db = Path(args.config).with_name("state.sqlite3")
        with process_lock(str(db)+".lock"):
            app = signer_app(config, db) if args.role == "signer" else coordinator_app(config, db)
            uvicorn.run(app, host=args.host, port=config["port"], access_log=False, workers=1)
    elif args.command == "serve-all":
        serve_all(args.directory)
    elif args.command == "allow":
        config = read_json(args.config)
        hashed = args.hash or w.identity_hash(Path(args.identity_file).read_bytes())
        Signer(config, Path(args.config).with_name("state.sqlite3")).allow(hashed)
        print("Identity hash added to this signer's registry.")
    elif args.command == "dkg":
        config = read_json(args.admin)
        with httpx.Client(timeout=120, trust_env=False) as client:
            result = client.post(config["url"]+"/admin/dkg", headers={"Authorization": "Bearer "+config["admin_token"]})
            result.raise_for_status()
            print(result.json()["public_key"])
    elif args.command == "issue":
        state = asyncio.run(issue(read_json(args.config), args.state,
            Path(args.identity_file).read_bytes() if args.identity_file else None,
            Path(args.message_file).read_bytes() if args.message_file else None))
        print(json_output(state))
    elif args.command == "verify":
        valid = p.verify(args.public_key, Path(args.message_file).read_bytes(), w.unhex(args.signature))
        print("VALID" if valid else "INVALID")
        if not valid:
            raise SystemExit(1)


def json_output(state):
    import json
    return json.dumps({k: state[k] for k in ("public_key", "signature")}, indent=2)
