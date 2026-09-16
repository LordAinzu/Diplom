"""Real HTTP DKG/signing -> unblinded SB+ -> deployed token on local Anvil.

Requires forge/anvil on PATH or in .tools. Set SBPLUS_REQUIRE_FOUNDRY=1 to
fail instead of skipping when these optional integration tools are absent.
"""
import asyncio
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import httpx
import pytest
from snowblind import wire as w
from snowblind.cli import provision
from snowblind.client import issue, read_json
from snowblind.signer import Signer
from test_network import free_ports

ROOT = Path(__file__).resolve().parents[1]


def tool(name):
    local = ROOT / ".tools" / (name+".exe" if os.name == "nt" else name)
    found = str(local) if local.is_file() else shutil.which(name)
    if not found:
        if os.environ.get("SBPLUS_REQUIRE_FOUNDRY") == "1":
            pytest.fail(f"{name} is required")
        pytest.skip(f"install {name} to run local-chain integration")
    return found


def word(number):
    return number.to_bytes(32, "big")


def abi_bytes(*values):
    offset = 32*len(values)
    heads, tails = [], []
    for value in values:
        tail = word(len(value))+value+bytes((-len(value)) % 32)
        heads.append(word(offset))
        tails.append(tail)
        offset += len(tail)
    return b"".join(heads+tails)


def calldata(signature, arguments=b""):
    return "0x"+w.identity_hash(signature.encode())[:8]+arguments.hex()


def test_server_signature_mints_token_on_anvil(tmp_path):
    forge, anvil = tool("forge"), tool("anvil")
    built = subprocess.run([forge, "build"], cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
    assert built.returncode == 0, built.stderr
    artifact = json.loads((ROOT/"out/FrostRewardToken.sol/FrostRewardToken.json").read_text())
    runtime = artifact["deployedBytecode"]["object"].removeprefix("0x")
    assert len(runtime)//2 <= 24576
    root = tmp_path/"cluster"
    base = free_ports(5)
    provision(root, w.new_x(), port=base)
    identity = b"local-chain integration identity"
    for i in (1, 2):
        Signer(read_json(root/f"signer-{i}/config.json"), root/f"signer-{i}/state.sqlite3").allow(w.identity_hash(identity))
    processes, logs = [], []
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    def start(name, command):
        log = open(tmp_path/(name+".log"), "wb")
        logs.append(log)
        process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=log, creationflags=flags)
        processes.append(process)
        return process

    def wait_for(probe):
        deadline = time.monotonic()+20
        while time.monotonic() < deadline:
            assert all(process.poll() is None for process in processes), "a service exited"
            try:
                if probe():
                    return
            except (httpx.HTTPError, ValueError):
                pass
            time.sleep(0.05)
        raise AssertionError("service startup timeout")

    try:
        start("anvil", [anvil, "--host", "127.0.0.1", "--port", str(base+4), "--hardfork", "paris", "--silent"])
        for name in ("signer-1", "signer-2", "signer-3", "coordinator"):
            role = "coordinator" if name == "coordinator" else "signer"
            start(name, [sys.executable, "-m", "snowblind", "serve", role, "--config", str(root/name/"config.json")])
        with httpx.Client(timeout=30, trust_env=False) as http:
            rpc_url = f"http://127.0.0.1:{base+4}"

            def rpc(method, params):
                response = http.post(rpc_url, json=dict(jsonrpc="2.0", id=1, method=method, params=params))
                response.raise_for_status()
                result = response.json()
                if "error" in result:
                    raise ValueError(result["error"])
                return result["result"]

            wait_for(lambda: rpc("eth_chainId", []))
            for port in range(base, base+4):
                wait_for(lambda port=port: http.get(f"http://127.0.0.1:{port}/health").status_code == 200)
            accounts = rpc("eth_accounts", [])
            relayer, recipient = accounts[0], accounts[1]
            admin = read_json(root/"admin.json")
            response = http.post(admin["url"]+"/admin/dkg", headers={"Authorization": "Bearer "+admin["admin_token"]})
            response.raise_for_status()
            key = bytes.fromhex(response.json()["public_key"])
            message = bytes.fromhex(recipient[2:])+b"\x00SB+ token integration\xff"
            state = asyncio.run(issue(read_json(root/"client/config.json"), root/"client/session.json", identity, message))
            signature = bytes.fromhex(state["signature"])
            assert bytes.fromhex(state["public_key"]) == key and len(signature) == 97

            def transaction(data, to=None):
                tx = {"from": relayer, "data": data, "gas": hex(12_000_000)}
                if to:
                    tx["to"] = to
                tx_hash = rpc("eth_sendTransaction", [tx])
                deadline = time.monotonic()+20
                while time.monotonic() < deadline:
                    receipt = rpc("eth_getTransactionReceipt", [tx_hash])
                    if receipt is not None:
                        return receipt
                    time.sleep(0.05)
                raise AssertionError("transaction was not mined")

            deploy_data = artifact["bytecode"]["object"]+abi_bytes(key).hex()
            deployed = transaction(deploy_data)
            assert deployed["status"] == "0x1"
            address = deployed["contractAddress"]

            def call(function, arguments=b""):
                return rpc("eth_call", [{"to": address, "data": calldata(function, arguments)}, "latest"])

            assert int(call("verifySignature(bytes,bytes)", abi_bytes(message, signature)), 16) == 1
            stolen = bytes.fromhex(relayer[2:])+message[20:]
            assert int(call("verifySignature(bytes,bytes)", abi_bytes(stolen, signature)), 16) == 0
            claimed = transaction(calldata("claim(bytes,bytes)", abi_bytes(message, signature)), address)
            assert claimed["status"] == "0x1"
            assert int(call("balanceOf(address)", word(int(recipient, 16))), 16) == 10**18
            assert int(call("balanceOf(address)", word(int(relayer, 16))), 16) == 0
            assert int(call("totalSupply()"), 16) == 10**18
            assert int(call("usedDataHashes(bytes32)", bytes.fromhex(w.identity_hash(message))), 16) == 1
            assert int(call("verifySignature(bytes,bytes)", abi_bytes(message, signature)), 16) == 1
            topics = [log["topics"][0] for log in claimed["logs"]]
            assert "0x"+w.identity_hash(b"Transfer(address,address,uint256)") in topics
            assert "0x"+w.identity_hash(b"RewardClaimed(bytes32,address,uint256)") in topics
            replay = transaction(calldata("claim(bytes,bytes)", abi_bytes(message, signature)), address)
            assert replay["status"] == "0x0"
            assert int(call("totalSupply()"), 16) == 10**18
            print(f"Anvil: runtime {len(runtime)//2} bytes; claim transaction {int(claimed['gasUsed'], 16)} gas")
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        for log in logs:
            log.close()
