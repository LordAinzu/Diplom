"""A single reproducible signer role. Private keys never leave this process."""
import secrets
from . import curve as ec
from . import wire as w
from . import protocol as p
from .store import Store


def node_result(group, packet, op, i):
    body = w.open_envelope(packet, group["nodes"][str(i)]["auth_public"],
                           group["id"], str(i), "reply/"+op)
    return body["result"]


def all_results(group, packets, op):
    if set(packets) != set(group["nodes"]):
        raise ValueError("all DKG participants are required")
    return {i: node_result(group, packet, op, int(i)) for i, packet in packets.items()}


class Signer:
    def __init__(self, config, database):
        self.config, self.group = config, config["group"]
        self.i = config["id"]
        self.store = Store(database)
        me = self.group["nodes"][str(self.i)]
        if (w.ed_public(config["auth_private"]) != me["auth_public"] or
                w.x_public(config["transport_private"]) != me["transport_public"] or
                w.x_public(config["identity_private"]) != self.group["identity_public"]):
            raise ValueError("private keys do not match pinned group")
        with self.store.transaction() as state:
            fingerprint = w.digest(self.group)
            if state.get("group_fingerprint", fingerprint) != fingerprint:
                raise ValueError("database belongs to another group")
            state["group_fingerprint"] = fingerprint
            for field in ("cache", "identities", "uses", "sessions"):
                state.setdefault(field, {})

    def allow(self, hashed):
        w.unhex(hashed, 32)
        with self.store.transaction() as state:
            state["identities"][hashed] = True

    def rpc(self, packet):
        body = w.open_envelope(packet, self.group["coordinator_public"], self.group["id"],
                               "coordinator", "request")
        if body["recipient"] != str(self.i):
            raise ValueError("wrong recipient")
        op, payload = body["op"], body["payload"]
        handlers = {"dkg_commit": self.dkg_commit, "dkg_shares": self.dkg_shares,
                    "dkg_finish": self.dkg_finish, "dkg_activate": self.dkg_activate,
                    "approve": self.approve, "round": self.round, "notify": self.notify}
        if op not in handlers:
            raise ValueError("unknown operation")
        key = op+":"+payload.get("session", "group")
        if op == "round":
            key += ":"+str(payload["round"])
        fingerprint = w.digest(payload)
        with self.store.transaction() as state:
            cached = state["cache"].get(key)
            if cached:
                if cached["hash"] != fingerprint:
                    raise ValueError("conflicting retry")
                return cached["response"]
            result = handlers[op](state, payload)
            response = w.envelope(self.config["auth_private"], self.group["id"], str(self.i),
                                  "reply/"+op, dict(payload_hash=fingerprint, result=result))
            state["cache"][key] = dict(hash=fingerprint, response=response)
            return response  # context manager commits before the caller receives it

    def dkg_commit(self, state, payload):
        if payload != {} or "dkg" in state:
            raise ValueError("DKG already started")
        coeff = [ec.random_scalar() for _ in range(self.group["threshold"])]
        commitments = [p.ph(ec.mul(a)) for a in coeff]
        nonce = ec.random_scalar()
        r = p.ph(ec.mul(nonce))
        c = ec.hash_scalar(b"dkg-pok", w.canonical([self.group["id"], self.i, commitments, r]))
        out = dict(commitments=commitments, R=r, z=p.sh((nonce+c*coeff[0]) % ec.N))
        state["dkg"] = dict(coeff=[p.sh(a) for a in coeff], commitment=out)
        return out

    def checked_commitments(self, state, packets):
        results = all_results(self.group, packets, "dkg_commit")
        if results[str(self.i)] != state["dkg"]["commitment"]:
            raise ValueError("own DKG commitment changed")
        for i, item in results.items():
            cs = item["commitments"]
            if len(cs) != self.group["threshold"]:
                raise ValueError("wrong polynomial degree")
            for c in cs:
                p.pt(c)
            c = ec.hash_scalar(b"dkg-pok", w.canonical([self.group["id"], int(i), cs, item["R"]]))
            if ec.mul(p.sc(item["z"])) != ec.add(p.pt(item["R"]), ec.mul(c, p.pt(cs[0]))):
                raise ValueError("invalid DKG proof")
        return results

    def dkg_shares(self, state, payload):
        commits = self.checked_commitments(state, payload["commitments"])
        transcript = w.digest(commits)
        coeff = [p.sc(a) for a in state["dkg"]["coeff"]]
        packets = {}
        for j, node in self.group["nodes"].items():
            share = sum(a*pow(int(j), k, ec.N) for k, a in enumerate(coeff)) % ec.N
            ctx = ["dkg-share", self.group["id"], transcript, self.i, int(j)]
            packets[j] = w.encrypt(node["transport_public"], ec.sb(share), ctx)
        state["dkg"].update(transcript=transcript, commits=commits)
        return dict(transcript=transcript, packets=packets)

    def dkg_finish(self, state, payload):
        results = all_results(self.group, payload["shares"], "dkg_shares")
        dkg = state["dkg"]
        total = 0
        for j, item in results.items():
            if item["transcript"] != dkg["transcript"] or set(item["packets"]) != set(self.group["nodes"]):
                raise ValueError("inconsistent DKG broadcast")
            ctx = ["dkg-share", self.group["id"], dkg["transcript"], int(j), self.i]
            share = ec.scalar(w.decrypt(self.config["transport_private"], item["packets"][str(self.i)], ctx))
            expected = ec.sum_points(ec.mul(pow(self.i, k, ec.N), p.pt(c))
                                     for k, c in enumerate(dkg["commits"][j]["commitments"]))
            if ec.mul(share) != expected:
                raise ValueError("invalid DKG secret share")
            total = (total+share) % ec.N
        pk = p.ph(ec.sum_points(p.pt(c["commitments"][0]) for c in dkg["commits"].values()))
        result = dict(transcript=dkg["transcript"], public_key=pk, verification_share=p.ph(ec.mul(total)))
        dkg.update(share=p.sh(total), public_key=pk, ready=result)
        del dkg["coeff"]
        return result

    def dkg_activate(self, state, payload):
        results = all_results(self.group, payload["ready"], "dkg_finish")
        dkg = state["dkg"]
        for j, item in results.items():
            expected = ec.sum_points(ec.mul(pow(int(j), k, ec.N), p.pt(c))
                                     for commit in dkg["commits"].values()
                                     for k, c in enumerate(commit["commitments"]))
            if (item["transcript"] != dkg["transcript"] or item["public_key"] != dkg["public_key"] or
                    p.pt(item["verification_share"]) != expected):
                raise ValueError("inconsistent DKG activation")
        state["active"] = True
        return dict(public_key=dkg["public_key"], active=True)

    def approve(self, state, payload):
        if not state.get("active"):
            raise ValueError("group not active")
        sid, hashed = payload["session"], payload["identity_hash"]
        w.unhex(sid, 32)
        w.unhex(hashed, 32)
        try:
            plain = w.decrypt(self.config["identity_private"], payload["encrypted_identity"],
                              w.identity_context(self.group["id"], sid, hashed))
        except Exception:
            return dict(session=sid, approved=False, reason="invalid_identity")
        if w.identity_hash(plain) != hashed or not state["identities"].get(hashed):
            return dict(session=sid, approved=False, reason="invalid_identity")
        if hashed in state["uses"] and state["uses"][hashed]["session"] != sid:
            return dict(session=sid, approved=False, reason="already_reserved")
        state["uses"][hashed] = dict(session=sid, status="reserved")
        state["sessions"][sid] = dict(identity_hash=hashed, stage=0)
        return dict(session=sid, approved=True)

    def selected(self, members):
        if (not isinstance(members, list) or any(type(i) is not int for i in members) or
                members != sorted(set(members)) or len(members) != self.group["threshold"] or
                not all(str(i) in self.group["nodes"] for i in members) or self.i not in members):
            raise ValueError("invalid signer set")

    def round(self, state, payload):
        sid, number, members = payload["session"], payload["round"], payload["members"]
        self.selected(members)
        session = state["sessions"][sid]
        if number != session["stage"]+1 or session.get("members", members) != members:
            raise ValueError("wrong round or signer set")
        session["members"] = members
        data = payload["input"]
        if number == 1:
            if data != {}:
                raise ValueError("unexpected first input")
            nonce = secrets.token_hex(32)
            session["nonce"] = nonce
            out = dict(nonce=nonce)
        elif number == 2:
            if set(data) != {str(i) for i in members} or data[str(self.i)] != session["nonce"]:
                raise ValueError("invalid nonce set")
            for nonce in data.values():
                w.unhex(nonce, 32)
            # sid_SB := ssid3, with canonical participant ordering.
            ssid = [[i, data[str(i)]] for i in members]
            a, b, y = (ec.random_scalar() for _ in range(3))
            out = dict(A=p.ph(ec.mul(a)), B=p.ph(ec.add(ec.mul(b), ec.mul(y, ec.H))),
                       cm=p.cm(ssid, self.i, p.sh(y)))
            session.update(ssid=ssid, a=p.sh(a), b=p.sh(b), y=p.sh(y), commitment=out)
        elif number == 3:
            c, cms = data["c"], data["commitments"]
            p.sc(c)
            if set(cms) != {str(i) for i in members} or cms[str(self.i)] != session["commitment"]["cm"]:
                raise ValueError("invalid commitments")
            for cm in cms.values():
                p.sc(cm)
            tr = p.transcript(session["ssid"], members, c, cms)
            ds = w.sign(self.config["auth_private"], tr)
            session.update(c=c, commitments=cms)
            out = dict(b=session["b"], y=session["y"], ds=ds)
        elif number == 4:
            # Inner final input contains only y and ds, exactly as in Fig. 4.
            if any(set(v) != {"y", "ds"} for v in data.values()):
                raise ValueError("invalid final input")
            y = p.check_reveals(session["ssid"], members, session["c"], session["commitments"], data, self.group["nodes"])
            if y == 0:
                raise ValueError("degenerate aggregate y; session remains reserved")
            z = (p.sc(session["a"])+p.sc(session["c"])*y*ec.lagrange(self.i, members)*p.sc(state["dkg"]["share"])) % ec.N
            keys = {j: w.pair_key(self.config["transport_private"], self.group["nodes"][str(j)]["transport_public"],
                                  self.group["id"], self.i, j) for j in members if j != self.i}
            slots = p.masked_share(self.i, members, z, keys, session["ssid"], data)
            out = dict(slots=slots, session=sid, identity_hash=session["identity_hash"], members=members,
                       final_input_hash=w.digest(data))
            state["uses"][session["identity_hash"]]["status"] = "issued"
            for secret in ("a", "b", "y"):
                del session[secret]
        else:
            raise ValueError("unknown round")
        session["stage"] = number
        return out

    def notify(self, state, payload):
        sid, hashed, members = payload["session"], payload["identity_hash"], payload["members"]
        w.unhex(sid, 32)
        w.unhex(hashed, 32)
        if (len(members) != self.group["threshold"] or members != sorted(set(members)) or
                set(payload["certificate"]) != {str(i) for i in members}):
            raise ValueError("invalid issuance certificate")
        hashes = set()
        for i in members:
            r = node_result(self.group, payload["certificate"][str(i)], "round", i)
            if (r.get("session"), r.get("identity_hash"), r.get("members")) != (sid, hashed, members) or "slots" not in r:
                raise ValueError("invalid issuance receipt")
            hashes.add(r["final_input_hash"])
        if len(hashes) != 1:
            raise ValueError("inconsistent issuance receipts")
        old = state["uses"].get(hashed)
        if old and old["session"] != sid:
            raise ValueError("conflicting issuance; operator intervention required")
        state["uses"][hashed] = dict(session=sid, status="issued")
        return dict(recorded=True)
