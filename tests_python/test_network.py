"""Real TCP, separate Python processes, HTTP boundaries and CLI recovery."""
import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

from snowblind import wire as w, protocol as p
from snowblind.cli import provision
from snowblind.client import read_json, issue
from snowblind.signer import Signer


def free_ports(count):
    for base in range(23000, 60000, count):
        sockets = []
        try:
            for port in range(base, base+count):
                sock = socket.socket()
                sockets.append(sock)
                sock.bind(("127.0.0.1", port))
            return base
        except OSError:
            pass
        finally:
            for sock in sockets:
                sock.close()
    raise RuntimeError("no free ports")


def test_separate_servers_cli_and_restart(tmp_path):
    root = tmp_path/"cluster"
    base = free_ports(4)
    group = provision(root, w.new_x(), port=base)
    identity, message = b"network private identity", b"network secret signing message"
    for i in (1, 2):
        config = read_json(root/f"signer-{i}/config.json")
        Signer(config, root/f"signer-{i}/state.sqlite3").allow(w.identity_hash(identity))
    processes, logs = {}, []

    def start(name):
        role = "coordinator" if name == "coordinator" else "signer"
        log = open(tmp_path/(name+".log"), "ab")
        logs.append(log)
        process = subprocess.Popen([sys.executable, "-m", "snowblind", "serve", role,
            "--config", str(root/name/"config.json")], stdout=log, stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        processes[name] = process
        port = read_json(root/name/"config.json")["port"]
        deadline = time.monotonic()+20
        with httpx.Client(timeout=0.5, trust_env=False) as client:
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise AssertionError((tmp_path/(name+".log")).read_text())
                try:
                    if client.get(f"http://127.0.0.1:{port}/health").status_code == 200:
                        return
                except httpx.HTTPError:
                    pass
                time.sleep(0.05)
        raise AssertionError("server startup timed out")

    def stop(name):
        process = processes[name]
        process.terminate()
        process.wait(timeout=10)

    try:
        for name in ("signer-1", "signer-2", "signer-3", "coordinator"):
            start(name)
        admin = read_json(root/"admin.json")
        with httpx.Client(base_url=admin["url"], timeout=30, trust_env=False) as client:
            assert client.post("/admin/dkg").status_code == 401
            reply = client.post("/admin/dkg", headers={"Authorization": "Bearer "+admin["admin_token"]})
            assert reply.status_code == 200, reply.text
            assert client.post("/sessions", json={}).status_code == 401
            public = client.get("/group").json()
            assert "private" not in json.dumps(public)
        stop("signer-3")
        config = read_json(root/"client/config.json")
        state_path = root/"client/session.json"
        state = asyncio.run(issue(config, state_path, identity, message))
        assert p.verify(state["public_key"], message, w.unhex(state["signature"]))
        # Restart every server; third catches up from the coordinator's durable outbox.
        for name in ("coordinator", "signer-1", "signer-2"):
            stop(name)
        for name in ("signer-1", "signer-2", "signer-3", "coordinator"):
            start(name)
        from snowblind.store import Store
        deadline = time.monotonic()+15
        third = Store(root/"signer-3/state.sqlite3")
        while time.monotonic() < deadline:
            if third.read()["uses"].get(w.identity_hash(identity), {}).get("status") == "issued":
                break
            time.sleep(0.05)
        assert third.read()["uses"][w.identity_hash(identity)]["status"] == "issued"
        assert w.identity_hash(identity) not in third.read()["identities"]
        resumed = subprocess.run([sys.executable, "-m", "snowblind", "issue", "--config",
            str(root/"client/config.json"), "--state", str(state_path)], capture_output=True, text=True, timeout=30)
        assert resumed.returncode == 0, resumed.stderr
        assert json.loads(resumed.stdout)["signature"] == state["signature"]
        coord_state = json.dumps(Store(root/"coordinator/state.sqlite3").read())
        assert message.hex() not in coord_state and identity.hex() not in coord_state
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        for log in logs:
            log.close()
