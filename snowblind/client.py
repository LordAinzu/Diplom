"""Resumable client. Message and blinding factors are persisted only locally."""
import json
import os
import secrets
from pathlib import Path
import httpx
from . import wire as w
from . import curve as ec
from . import protocol as p
from .signer import node_result


def save_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name+".tmp")
    with open(temp, "w", encoding="utf-8") as f:
        if os.name != "nt":
            os.chmod(temp, 0o600)
        json.dump(value, f, indent=2, ensure_ascii=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_parameters(pinned, parameters):
    if parameters["group"] != pinned or not parameters["active"]:
        raise ValueError("group mismatch or DKG inactive")
    pk = parameters["public_key"]
    p.pt(pk)
    if set(parameters["ready"]) != set(pinned["nodes"]) or set(parameters["activation"]) != set(pinned["nodes"]):
        raise ValueError("missing activation certificates")
    for i in pinned["nodes"]:
        for field, op in (("ready", "dkg_finish"), ("activation", "dkg_activate")):
            result = node_result(pinned, parameters[field][i], op, int(i))
            if result["public_key"] != pk:
                raise ValueError("inconsistent activation key")
    return pk


def collect(group, members, packets, payload):
    if set(packets) != {str(i) for i in members}:
        raise ValueError("missing signer response")
    results = {}
    for i in members:
        packet = packets[str(i)]
        result = node_result(group, packet, "round", i)
        if packet["value"]["body"]["payload_hash"] != w.digest(payload):
            raise ValueError("response to different round")
        results[str(i)] = result
    return results


def prepare(pinned, identity, message):
    sid = secrets.token_hex(32)
    hashed = w.identity_hash(identity)
    ciphertext = w.encrypt(pinned["identity_public"], identity, w.identity_context(pinned["id"], sid, hashed))
    return dict(group_fingerprint=w.digest(pinned), message=message.hex(),
                request=dict(session=sid, identity_hash=hashed, encrypted_identity=ciphertext),
                alpha=p.sh(ec.random_scalar()), beta=p.sh(ec.random_scalar()), r=p.sh(ec.random_scalar()))


async def issue(config, state_path, identity=None, message=None):
    path = Path(state_path)
    pinned = config["group"]
    if path.exists():
        state = read_json(path)
        if state["group_fingerprint"] != w.digest(pinned):
            raise ValueError("client state belongs to another group")
        if message is not None and message.hex() != state["message"]:
            raise ValueError("cannot change the message of a session")
        if identity is not None and w.identity_hash(identity) != state["request"]["identity_hash"]:
            raise ValueError("cannot change identity")
    else:
        if identity is None or message is None:
            raise ValueError("identity and message are required for a new session")
        state = prepare(pinned, identity, message)
        save_json(path, state)  # Preserve randomness BEFORE the first network request.
    message = w.unhex(state["message"])
    async with httpx.AsyncClient(base_url=config["url"], timeout=60, trust_env=False,
                                 headers={"Authorization": "Bearer "+config["client_token"]}) as client:
        result = await client.get("/group")
        result.raise_for_status()
        pk = validate_parameters(pinned, result.json())
        if "signature" in state:
            if not p.verify(pk, message, w.unhex(state["signature"])):
                raise ValueError("saved signature is invalid")
            return state
        result = await client.post("/sessions", json=state["request"])
        result.raise_for_status()
        session = result.json()
        members = session["members"]
        if not members:
            raise ValueError("not enough approvals; retry the SAME client state later")
        if state.get("members", members) != members:
            raise ValueError("participant set changed")
        state["members"] = members
        save_json(path, state)
        sid = state["request"]["session"]

        async def round(number, data):
            payload = dict(session=sid, round=number, members=members, input=data)
            reply = await client.post(f"/sessions/{sid}/rounds/{number}", json=data)
            reply.raise_for_status()
            return collect(pinned, members, reply.json(), payload)

        nonces = await round(1, {})
        nonce_set = {i: v["nonce"] for i, v in nonces.items()}
        ssid = [[i, nonce_set[str(i)]] for i in members]
        commitments = await round(2, nonce_set)
        alpha, beta, r = (p.sc(state[k]) for k in ("alpha", "beta", "r"))
        rbar, c = p.blind(pk, message, commitments, alpha, beta, r)
        cms = {i: v["cm"] for i, v in commitments.items()}
        reveals = await round(3, dict(c=c, commitments=cms))
        final_input = {i: {k: v[k] for k in ("y", "ds")} for i, v in reveals.items()}
        p.check_reveals(ssid, members, c, cms, final_input, pinned["nodes"])
        final = await round(4, final_input)
        shares = p.recover_shares(members, {i: v["slots"] for i, v in final.items()})
        signature = p.unblind(pk, message, members, commitments, reveals, shares, alpha, beta, r, rbar, c)
        state.update(public_key=pk, signature=signature.hex())
        save_json(path, state)
        return state
