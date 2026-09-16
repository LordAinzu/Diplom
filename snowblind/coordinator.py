"""Trusted issuance ledger and durable relay; no group or identity secrets."""
import asyncio
import httpx
from . import wire as w
from .signer import node_result
from .store import Store


class Coordinator:
    def __init__(self, config, database, transport=None):
        self.config, self.group = config, config["group"]
        if w.ed_public(config["auth_private"]) != self.group["coordinator_public"]:
            raise ValueError("invalid coordinator key")
        self.store = Store(database)
        self.transport = transport
        self.lock = asyncio.Lock()
        with self.store.transaction() as s:
            fingerprint = w.digest(self.group)
            if s.get("group_fingerprint", fingerprint) != fingerprint:
                raise ValueError("database belongs to another group")
            s["group_fingerprint"] = fingerprint
            for field in ("sessions", "uses", "relay", "outbox"):
                s.setdefault(field, {})

    async def send(self, i, op, payload, cache_key):
        fingerprint = w.digest(payload)
        cached = self.store.read()["relay"].get(cache_key)
        if cached:
            if cached["hash"] != fingerprint:
                raise ValueError("relay request changed")
            return cached["response"]
        body = dict(recipient=str(i), op=op, payload=payload)
        packet = w.envelope(self.config["auth_private"], self.group["id"], "coordinator", "request", body)
        if self.transport:
            response = await self.transport(i, packet)
        else:
            async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
                r = await client.post(self.group["nodes"][str(i)]["url"]+"/rpc", json=packet)
                r.raise_for_status()
                response = r.json()
        node_result(self.group, response, op, i)
        if response["value"]["body"]["payload_hash"] != fingerprint:
            raise ValueError("response to different request")
        with self.store.transaction() as s:
            s["relay"][cache_key] = dict(hash=fingerprint, response=response)
        return response

    async def dkg(self):
        async with self.lock:
            packets = {}
            for op, field in (("dkg_commit", None), ("dkg_shares", "commitments"),
                              ("dkg_finish", "shares"), ("dkg_activate", "ready")):
                payload = {} if field is None else {field: packets}
                next_packets = {}
                for i in sorted(map(int, self.group["nodes"])):
                    next_packets[str(i)] = await self.send(i, op, payload, op+":"+str(i))
                if op == "dkg_finish":
                    public_keys = {node_result(self.group, v, op, int(i))["public_key"] for i, v in next_packets.items()}
                    if len(public_keys) != 1:
                        raise ValueError("inconsistent public keys")
                    with self.store.transaction() as s:
                        s["public_key"] = public_keys.pop()
                        s["ready"] = next_packets
                packets = next_packets
            with self.store.transaction() as s:
                s["active"] = True
                s["activation"] = packets
            return self.parameters()

    def parameters(self):
        s = self.store.read()
        return dict(group=self.group, active=s.get("active", False), public_key=s.get("public_key"),
                    ready=s.get("ready"), activation=s.get("activation"))

    async def create(self, payload):
        sid, hashed = payload["session"], payload["identity_hash"]
        w.unhex(sid, 32)
        w.unhex(hashed, 32)
        if set(payload) != {"session", "identity_hash", "encrypted_identity"}:
            raise ValueError("unexpected request fields")
        async with self.lock:
            with self.store.transaction() as s:
                if not s.get("active"):
                    raise ValueError("DKG not complete")
                old = s["sessions"].get(sid)
                if old and old["request"] != payload:
                    raise ValueError("conflicting session retry")
                if old and old["status"] == "rejected":
                    return self.session(sid)
                if hashed in s["uses"] and s["uses"][hashed] != sid:
                    raise ValueError("identity already reserved or issued")
                s["uses"][hashed] = sid
                s["sessions"].setdefault(sid, dict(request=payload, rounds={}, status="checking"))
            current = self.store.read()["sessions"][sid]
            if "members" in current:
                return self.session(sid)
            approvals = {}
            # Probe all nodes concurrently so an unavailable third does not serialize timeouts.
            ids = sorted(map(int, self.group["nodes"]))
            replies = await asyncio.gather(*(self.send(i, "approve", payload, sid+":approve:"+str(i)) for i in ids),
                                           return_exceptions=True)
            for i, reply in zip(ids, replies):
                if not isinstance(reply, BaseException):
                    result = node_result(self.group, reply, "approve", i)
                    if result["session"] != sid:
                        raise ValueError("approval for another session")
                    approvals[str(i)] = result
            members = [i for i in ids if approvals.get(str(i), {}).get("approved")][:self.group["threshold"]]
            with self.store.transaction() as s:
                item = s["sessions"][sid]
                item["approvals"] = approvals
                if len(members) == self.group["threshold"]:
                    item.update(members=members, status="signing")
                elif len(approvals) == len(ids) and not any(v["approved"] for v in approvals.values()):
                    # All signed refusals prove that no signer reserved this request.
                    # A lost reply is not a refusal: uncertain sessions stay reserved.
                    item["status"] = "rejected"
                    del s["uses"][hashed]
            return self.session(sid)

    def session(self, sid):
        item = self.store.read()["sessions"][sid]
        return dict(session=sid, status=item["status"], members=item.get("members"),
                    approvals=item.get("approvals", {}), rounds=item["rounds"])

    async def round(self, sid, number, data):
        if type(number) is not int or number not in (1, 2, 3, 4):
            raise ValueError("invalid round")
        async with self.lock:
            with self.store.transaction() as s:
                item = s["sessions"][sid]
                if "members" not in item:
                    raise ValueError("not enough approvals")
                rounds = item["rounds"]
                previous = rounds.get(str(number))
                if previous and previous["input"] != data:
                    raise ValueError("conflicting round retry")
                if number > 1 and "responses" not in rounds.get(str(number-1), {}):
                    raise ValueError("previous round incomplete")
                rounds.setdefault(str(number), dict(input=data))
                members = item["members"]
                hashed = item["request"]["identity_hash"]
            payload = dict(session=sid, round=number, members=members, input=data)
            responses = {}
            for i in members:
                responses[str(i)] = await self.send(i, "round", payload, f"{sid}:round:{number}:{i}")
            with self.store.transaction() as s:
                s["sessions"][sid]["rounds"][str(number)]["responses"] = responses
                if number == 4:
                    s["sessions"][sid]["status"] = "issued"
                    notice = dict(session=sid, identity_hash=hashed, members=members, certificate=responses)
                    for i in self.group["nodes"]:
                        s["outbox"].setdefault(sid+":"+i, dict(node=int(i), notice=notice, delivered=False))
            if number == 4:
                await self._flush()
            return responses

    async def _flush(self):
        async def deliver(key, entry):
            if entry["delivered"]:
                return
            try:
                await self.send(entry["node"], "notify", entry["notice"], "notify:"+key)
            except Exception:
                return  # durable outbox retains the failed notification
            with self.store.transaction() as s:
                s["outbox"][key]["delivered"] = True
        await asyncio.gather(*(deliver(key, entry) for key, entry in self.store.read()["outbox"].items()))

    async def flush(self):
        async with self.lock:
            await self._flush()
