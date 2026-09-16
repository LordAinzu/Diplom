import asyncio
import copy

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from snowblind import curve as ec, wire as w, protocol as p
from snowblind.cli import provision
from snowblind.client import read_json, prepare, collect, validate_parameters
from snowblind.signer import Signer, node_result
from snowblind.coordinator import Coordinator


class Cluster:
    def __init__(self, root, n=3, threshold=2):
        self.root = root
        self.group = provision(root, w.new_x(), n, threshold)
        self.nodes = {i: Signer(read_json(root/f"signer-{i}/config.json"), root/f"signer-{i}/state.sqlite3")
                      for i in range(1, n+1)}
        self.offline = set()
        self.drop_after = None
        self.coord = Coordinator(read_json(root/"coordinator/config.json"), root/"coordinator/state.sqlite3", self.transport)

    async def transport(self, i, packet):
        if i in self.offline:
            raise ConnectionError("offline")
        result = self.nodes[i].rpc(packet)
        if self.drop_after == i:
            self.drop_after = None
            raise ConnectionError("reply lost after durable commit")
        return result

    def allow(self, identity, members=None):
        for i in members or self.nodes:
            self.nodes[i].allow(w.identity_hash(identity))

    def restart(self):
        self.nodes = {i: Signer(node.config, node.store.path) for i, node in self.nodes.items()}
        self.coord = Coordinator(self.coord.config, self.coord.store.path, self.transport)

    async def sign(self, identity, message, state=None):
        state = state or prepare(self.group, identity, message)
        session = await self.coord.create(state["request"])
        members = session["members"]
        assert members is not None
        sid = state["request"]["session"]

        async def round(number, data):
            out = await self.coord.round(sid, number, data)
            return collect(self.group, members, out, dict(session=sid, round=number, members=members, input=data))

        nonces = await round(1, {})
        ssid = [[i, nonces[str(i)]["nonce"]] for i in members]
        commits = await round(2, {i: v["nonce"] for i, v in nonces.items()})
        pk = self.coord.parameters()["public_key"]
        a, b, r = (p.sc(state[k]) for k in ("alpha", "beta", "r"))
        rbar, c = p.blind(pk, message, commits, a, b, r)
        cms = {i: v["cm"] for i, v in commits.items()}
        reveals = await round(3, dict(c=c, commitments=cms))
        final_input = {i: {k: v[k] for k in ("y", "ds")} for i, v in reveals.items()}
        p.check_reveals(ssid, members, c, cms, final_input, self.group["nodes"])
        final = await round(4, final_input)
        shares = p.recover_shares(members, {i: v["slots"] for i, v in final.items()})
        signature = p.unblind(pk, message, members, commits, reveals, shares, a, b, r, rbar, c)
        return pk, signature, state


def test_shared_encryption_and_aad():
    key = w.new_x()
    ctx = w.identity_context("group", "request", w.identity_hash(b"identity"))
    packet = w.encrypt(w.x_public(key), b"identity", ctx)
    for _ in range(3):
        assert w.decrypt(key, packet, ctx) == b"identity"
    with pytest.raises(InvalidTag):
        w.decrypt(w.new_x(), packet, ctx)
    with pytest.raises(InvalidTag):
        w.decrypt(key, packet, [*ctx, "different session"])
    altered = copy.deepcopy(packet)
    altered["ciphertext"] = (bytes([int(packet["ciphertext"][:2], 16) ^ 1])+bytes.fromhex(packet["ciphertext"][2:])).hex()
    with pytest.raises(InvalidTag):
        w.decrypt(key, altered, ctx)


@pytest.mark.parametrize("members", [(1, 2), (1, 3), (2, 3)])
def test_any_two_third_denies_and_notified(tmp_path, members):
    async def scenario():
        cluster = Cluster(tmp_path/"cluster")
        await cluster.coord.dkg()
        cluster.allow(b"identity", members)
        pk, sig, state = await cluster.sign(b"identity", b"private message")
        assert p.verify(pk, b"private message", sig)
        assert not p.verify(pk, b"changed", sig)
        hashed = w.identity_hash(b"identity")
        third = ({1, 2, 3}-set(members)).pop()
        ledger = cluster.nodes[third].store.read()
        assert hashed not in ledger["identities"]
        assert ledger["uses"][hashed]["status"] == "issued"
        with pytest.raises(ValueError, match="already"):
            await cluster.coord.create(prepare(cluster.group, b"identity", b"other")["request"])
        cluster.restart()
        await cluster.coord.dkg()  # resumes cached DKG, never regenerates shares
        _, again, _ = await cluster.sign(b"identity", b"private message", state)
        assert sig == again
        for signer in cluster.nodes.values():
            assert signer.store.read()["dkg"]["public_key"] == pk
    asyncio.run(scenario())


def test_offline_notification_and_two_of_four(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path/"cluster", 4, 2)
        await cluster.coord.dkg()
        cluster.allow(b"id")
        cluster.offline = {3, 4}
        pk, sig, _ = await cluster.sign(b"id", b"")
        assert p.verify(pk, b"", sig)
        assert sum(not e["delivered"] for e in cluster.coord.store.read()["outbox"].values()) == 2
        cluster.restart()
        cluster.offline.clear()
        await cluster.coord.flush()
        assert all(e["delivered"] for e in cluster.coord.store.read()["outbox"].values())
    asyncio.run(scenario())


def test_approval_checks_and_request_conflicts(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path/"cluster")
        await cluster.coord.dkg()
        request = prepare(cluster.group, b"unknown", b"msg")["request"]
        result = await cluster.coord.create(request)
        assert result["members"] is None
        assert result["status"] == "rejected"
        assert w.identity_hash(b"unknown") not in cluster.coord.store.read()["uses"]
        assert (await cluster.coord.create(request))["status"] == "rejected"
        assert all(not v["approved"] for v in result["approvals"].values())
        cluster.allow(b"actual")
        request = prepare(cluster.group, b"actual", b"msg")["request"]
        sid = request["session"]
        # Valid AEAD, but plaintext does not match the claimed registered hash.
        request["encrypted_identity"] = w.encrypt(cluster.group["identity_public"], b"different",
                w.identity_context(cluster.group["id"], sid, request["identity_hash"]))
        assert (await cluster.coord.create(request))["members"] is None
        changed = copy.deepcopy(request)
        changed["encrypted_identity"]["nonce"] = "00"*12
        with pytest.raises(ValueError, match="conflicting"):
            await cluster.coord.create(changed)
        corrected = prepare(cluster.group, b"actual", b"msg")["request"]
        assert (await cluster.coord.create(corrected))["members"] == [1, 2]
    asyncio.run(scenario())


def test_lost_round_response_and_no_nonce_reuse(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path/"cluster")
        await cluster.coord.dkg()
        cluster.allow(b"id")
        state = prepare(cluster.group, b"id", b"m")
        sid = state["request"]["session"]
        await cluster.coord.create(state["request"])
        cluster.drop_after = 1
        with pytest.raises(ConnectionError):
            await cluster.coord.round(sid, 1, {})
        old = cluster.nodes[1].store.read()["cache"]["round:"+sid+":1"]["response"]
        cluster.restart()
        response = await cluster.coord.round(sid, 1, {})
        assert response["1"] == old
        with pytest.raises(ValueError, match="conflicting"):
            await cluster.coord.round(sid, 1, {"different": True})
        pk, sig, _ = await cluster.sign(b"id", b"m", state)
        assert p.verify(pk, b"m", sig)
    asyncio.run(scenario())


def test_concurrent_identity_reservation(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path/"cluster")
        await cluster.coord.dkg()
        cluster.allow(b"id")
        requests = [prepare(cluster.group, b"id", b"m")["request"] for _ in range(2)]
        results = await asyncio.gather(*(cluster.coord.create(r) for r in requests), return_exceptions=True)
        assert sum(isinstance(x, ValueError) for x in results) == 1
        assert len(cluster.coord.store.read()["uses"]) == 1
    asyncio.run(scenario())


def test_dkg_tampered_share_and_transcript(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path/"cluster")
        coord = cluster.coord
        commits = {str(i): await coord.send(i, "dkg_commit", {}, f"commit{i}") for i in cluster.nodes}
        shares = {str(i): await coord.send(i, "dkg_shares", {"commitments": commits}, f"shares{i}") for i in cluster.nodes}
        bad = copy.deepcopy(shares)
        result = bad["1"]["value"]["body"]["result"]
        result["transcript"] = "00"*32
        bad["1"]["signature"] = w.sign(cluster.nodes[1].config["auth_private"], bad["1"]["value"])
        with pytest.raises(ValueError, match="inconsistent"):
            await coord.send(2, "dkg_finish", {"shares": bad}, "bad-finish")
        bad = copy.deepcopy(shares)
        result = bad["1"]["value"]["body"]["result"]
        ctx = ["dkg-share", cluster.group["id"], result["transcript"], 1, 2]
        result["packets"]["2"] = w.encrypt(cluster.group["nodes"]["2"]["transport_public"], ec.sb(123), ctx)
        bad["1"]["signature"] = w.sign(cluster.nodes[1].config["auth_private"], bad["1"]["value"])
        with pytest.raises(ValueError, match="invalid DKG secret"):
            await coord.send(2, "dkg_finish", {"shares": bad}, "bad-share")
        # Rejected operations rolled back: original valid transcript still succeeds.
        response = await coord.send(2, "dkg_finish", {"shares": shares}, "valid-finish")
        assert node_result(cluster.group, response, "dkg_finish", 2)["public_key"]
    asyncio.run(scenario())


def test_envelope_forgery_and_key_mismatch(tmp_path):
    cluster = Cluster(tmp_path/"cluster")
    packet = w.envelope(w.new_ed(), cluster.group["id"], "coordinator", "request",
                        dict(recipient="1", op="dkg_commit", payload={}))
    with pytest.raises(InvalidSignature):
        cluster.nodes[1].rpc(packet)
    config = copy.deepcopy(cluster.nodes[1].config)
    config["identity_private"] = w.new_x()
    with pytest.raises(ValueError, match="keys"):
        Signer(config, tmp_path/"bad.sqlite3")


def test_curve_and_signature_boundaries():
    assert ec.mul(ec.N) is None
    assert ec.add(ec.G, (ec.G[0], -ec.G[1] % ec.P)) is None
    assert ec.decode(ec.encode(ec.H)) == ec.H
    assert ec.H != ec.G
    for raw in (b"", bytes(33), b"\x02"+ec.P.to_bytes(32, "big"), b"\x02"+bytes(32)):
        with pytest.raises(ValueError):
            ec.decode(raw)
    for raw in (b"", ec.N.to_bytes(32, "big")):
        with pytest.raises(ValueError):
            ec.scalar(raw)
    assert not p.verify(p.ph(ec.G), b"", bytes(97))
    assert not p.verify(p.ph(ec.G), b"", bytes(65))


def test_sbplus_masks_require_all_signers_and_bind_inputs():
    members = [1, 2, 3]
    keys = {(1, 2): bytes([12])*32, (1, 3): bytes([13])*32, (2, 3): bytes([23])*32}
    def response(i, sid="session", data=None):
        return p.masked_share(i, members, i*11, {j: keys[tuple(sorted((i, j)))] for j in members if j != i}, sid, data or {"input": "a"})
    responses = {str(i): response(i) for i in members}
    assert p.recover_shares(members, responses) == {"1": 11, "2": 22, "3": 33}
    with pytest.raises(ValueError, match="missing"):
        p.recover_shares(members, {"1": responses["1"], "2": responses["2"]})
    for replacement in (response(3, sid="other"), response(3, data={"input": "b"})):
        changed = dict(responses, **{"3": replacement})
        try:
            assert p.recover_shares(members, changed) != {"1": 11, "2": 22, "3": 33}
        except ValueError:
            pass


def test_three_of_five(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path/"cluster", 5, 3)
        await cluster.coord.dkg()
        cluster.allow(b"identity", [1, 3, 5])
        pk, sig, _ = await cluster.sign(b"identity", b"three-of-five")
        assert p.verify(pk, b"three-of-five", sig)
    asyncio.run(scenario())


def test_round_tampering_and_lost_final_reply(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path/"cluster")
        await cluster.coord.dkg()
        cluster.allow(b"id")
        state = prepare(cluster.group, b"id", b"m")
        sid = state["request"]["session"]
        await cluster.coord.create(state["request"])
        first = await cluster.coord.round(sid, 1, {})
        nonces = {i: node_result(cluster.group, v, "round", int(i))["nonce"] for i, v in first.items()}
        original = dict(session=sid, round=2, members=[1, 2], input=nonces)

        def direct(payload):
            return cluster.nodes[1].rpc(w.envelope(cluster.coord.config["auth_private"], cluster.group["id"],
                "coordinator", "request", dict(op="round", recipient="1", payload=payload)))

        altered = copy.deepcopy(original)
        altered["members"] = [1, 3]
        with pytest.raises(ValueError, match="signer set"):
            direct(altered)
        altered = copy.deepcopy(original)
        altered["input"]["1"] = "00"*32
        with pytest.raises(ValueError, match="nonce"):
            direct(altered)
        responses = await cluster.coord.round(sid, 2, nonces)
        commits = {i: node_result(cluster.group, v, "round", int(i)) for i, v in responses.items()}
        pk = cluster.coord.parameters()["public_key"]
        _, c = p.blind(pk, b"m", commits, *(p.sc(state[k]) for k in ("alpha", "beta", "r")))
        cms = {i: v["cm"] for i, v in commits.items()}
        responses = await cluster.coord.round(sid, 3, dict(c=c, commitments=cms))
        reveals = {i: node_result(cluster.group, v, "round", int(i)) for i, v in responses.items()}
        final_input = {i: {k: v[k] for k in ("y", "ds")} for i, v in reveals.items()}
        bad = copy.deepcopy(final_input)
        bad["2"]["ds"] = "00"*64
        with pytest.raises(InvalidSignature):
            direct(dict(session=sid, round=4, members=[1, 2], input=bad))
        assert cluster.nodes[1].store.read()["sessions"][sid]["stage"] == 3
        cluster.drop_after = 2
        with pytest.raises(ConnectionError):
            await cluster.coord.round(sid, 4, final_input)
        before = cluster.nodes[2].store.read()["cache"]["round:"+sid+":4"]["response"]
        assert "a" not in cluster.nodes[2].store.read()["sessions"][sid]
        cluster.restart()
        result = await cluster.coord.round(sid, 4, final_input)
        assert result["2"] == before
        pk, sig, _ = await cluster.sign(b"id", b"m", state)
        assert p.verify(pk, b"m", sig)
    asyncio.run(scenario())


def test_group_pinning_and_tampered_activation(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path/"cluster")
        params = await cluster.coord.dkg()
        assert validate_parameters(cluster.group, params) == params["public_key"]
        changed = copy.deepcopy(params)
        changed["group"]["identity_public"] = w.x_public(w.new_x())
        with pytest.raises(ValueError, match="group mismatch"):
            validate_parameters(cluster.group, changed)
        changed = copy.deepcopy(params)
        changed["activation"]["1"]["signature"] = "00"*64
        with pytest.raises(InvalidSignature):
            validate_parameters(cluster.group, changed)
    asyncio.run(scenario())


def test_dkg_requires_every_node_and_resumes_after_loss(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path/"cluster")
        cluster.offline.add(3)
        with pytest.raises(ConnectionError):
            await cluster.coord.dkg()
        assert not cluster.coord.parameters()["active"]
        before = cluster.nodes[1].store.read()["dkg"]["commitment"]
        cluster.restart()
        cluster.offline.clear()
        cluster.drop_after = 3
        with pytest.raises(ConnectionError):
            await cluster.coord.dkg()
        cluster.restart()
        result = await cluster.coord.dkg()
        assert result["active"]
        assert cluster.nodes[1].store.read()["dkg"]["commitment"] == before
        # Persisted PoK must be checked even when the envelope is authentically signed.
        fresh = Cluster(tmp_path/"fresh")
        commits = {str(i): await fresh.coord.send(i, "dkg_commit", {}, f"commit{i}") for i in fresh.nodes}
        commits["1"]["value"]["body"]["result"]["z"] = p.sh(1)
        commits["1"]["signature"] = w.sign(fresh.nodes[1].config["auth_private"], commits["1"]["value"])
        with pytest.raises(ValueError, match="proof"):
            await fresh.coord.send(2, "dkg_shares", {"commitments": commits}, "bad-pok")
    asyncio.run(scenario())
