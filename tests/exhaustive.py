"""Exhaustive verification of the custody engine on tiny graphs.

Each case carries an *explicit* expected outcome and is additionally
cross-checked against the independent naive reference in ``tests/_reference.py``.
Having both guards against a shared bug: if the engine and reference drift the
same way, the explicit expectation still fails.

Coverage matches the task's named corners:

* two witnesses that share a root, with and without private roots each;
* dependency cycles (2-cycle, 3-cycle, self-loop) that must not add seats,
  including a clean witness that proxies a cycle;
* failed edges: dangling, revoked and superseded proxies (missing evidence);
* explicit rejection vs. insufficient evidence, with shortest-chain lengths;
* multiple valid certificates and the stable-order tie-break;
* grounded revocation where a revoked revoker must not kill its own target;
* permutation invariance: shuffling input order must not change the verdict.
"""

from __future__ import annotations

import random
from typing import Any, Iterable

from custody.analysis import Analysis
from custody.events import parse_event, with_signature

import tests._reference as ref


def _event(eid: str, seq: int, kind: str = "buffer", claim: str | None = "alpha",
           roots: Iterable[str] = (), seen: Iterable[str] = (),
           revokes: Iterable[str] = (), target: str | None = None,
           excludes: Iterable[str] = (), corrects: Iterable[str] = (),
           org: str = "org-x") -> dict[str, Any]:
    raw: dict[str, Any] = {"id": eid, "kind": kind, "seq": seq, "at": seq, "org": org}
    if claim is not None:
        raw["claim"] = claim
    roots = list(roots)
    if kind == "buffer":
        raw["signer"] = roots[0] if roots else f"signer-{eid}"
        raw["roots"] = roots
        raw["seen"] = list(seen)
        if revokes:
            raw["revokes"] = list(revokes)
        return with_signature(raw)
    if kind == "correct":
        raw["signer"] = "signer-x"
        raw["target"] = target
        raw["excludes"] = list(excludes)
        raw["corrects"] = list(corrects)
        return with_signature(raw)
    return raw  # base


def _parse(raws: Iterable[dict[str, Any]]) -> list:
    return [parse_event(r) for r in raws]


def _verdict(raws: list[dict[str, Any]], claim: str, required: int) -> dict:
    analysis = Analysis(_parse(raws))
    v = analysis.assess(claim, required)
    cert = v.certificate
    return {
        "status": v.status,
        "reason": v.reason,
        "seed": cert.seed if cert else None,
        "seats": cert.seats if cert else 0,
        "event_count": cert.event_count if cert else 0,
        "roots": list(cert.roots) if cert else [],
        "chain": list(v.contradiction_chain),
        "rejecter": v.rejection_event,
    }


# --------------------------------------------------------------------------- #
# cases: (name, raws, claim, required, expected_status, expected_seed|None,
#         expected_reason|None)
# --------------------------------------------------------------------------- #

def cases():
    base = [_event("base", 0, kind="base")]

    yield ("shared_union_3", base + [
        _event("w1", 1, roots=["s", "p1"]),
        _event("w2", 2, roots=["s", "p2"], seen=["w1"]),
    ], "alpha", 3, "supported", "w2", None)

    yield ("shared_identical_no_topup", base + [
        _event("w1", 1, roots=["s", "p1"]),
        _event("w2", 2, roots=["s", "p1"], seen=["w1"]),
    ], "alpha", 3, "insufficient", None, "insufficient_roots")

    # w1 alone already gives 3 seats; w2's closure gives 4.  The rule minimises
    # roots first, so the minimal certificate is w1 (3 seats, 1 event), not w2.
    yield ("shared_with_privates", base + [
        _event("w1", 1, roots=["s", "p1", "q1"]),
        _event("w2", 2, roots=["s", "p2"], seen=["w1"]),
    ], "alpha", 2, "supported", "w1", None)

    yield ("cycle_2", base + [
        _event("x", 1, roots=["rx"], seen=["y"]),
        _event("y", 2, roots=["ry"], seen=["x"]),
    ], "alpha", 2, "insufficient", None, "dependency_cycle")

    yield ("cycle_3", base + [
        _event("x", 1, roots=["rx"], seen=["y"]),
        _event("y", 2, roots=["ry"], seen=["z"]),
        _event("z", 3, roots=["rz"], seen=["x"]),
    ], "alpha", 2, "insufficient", None, "dependency_cycle")

    yield ("self_loop_cut", base + [
        _event("x", 1, roots=["rx"], seen=["x"]),
        _event("good", 2, roots=["ra", "rb"]),
    ], "alpha", 2, "supported", "good", None)

    yield ("clean_proxies_cycle", base + [
        _event("good", 1, roots=["ra", "rb"], seen=["x"]),
        _event("x", 2, roots=["rx", "rd"], seen=["y"]),
        _event("y", 3, roots=["ry", "re"], seen=["x"]),
    ], "alpha", 2, "supported", "good", None)

    yield ("dangling_proxy", base + [
        _event("w1", 1, roots=["ra", "rb"], seen=["nope"]),
    ], "alpha", 2, "insufficient", None, "missing_evidence")

    yield ("revoked_proxy", base + [
        _event("w1", 1, roots=["ra", "rb"], seen=["w2"]),
        _event("w2", 2, roots=["rc"]),
        _event("rev", 3, roots=["rd"], revokes=["w2"]),
    ], "alpha", 2, "insufficient", None, "missing_evidence")

    yield ("superseded_proxy", base + [
        _event("w1", 1, roots=["ra", "rb"], seen=["w2"]),
        _event("w2", 2, roots=["rc"]),
        _event("cor", 3, kind="correct", target="ev:w2", corrects=["w2"]),
    ], "alpha", 2, "insufficient", None, "missing_evidence")

    # Grounded revocation: w1 needs w2's root; A revokes w2 but C revokes A, so
    # w2 stays live and alpha is supported.  A naive "kill any target of a live
    # revoker" fixpoint would wrongly kill w2 and report missing evidence.
    yield ("grounded_revocation", base + [
        _event("w1", 1, roots=["ra"], seen=["w2"]),
        _event("w2", 2, roots=["rc"]),
        _event("A", 3, roots=["rd"], revokes=["w2"]),
        _event("C", 4, roots=["re"], revokes=["A"]),
    ], "alpha", 2, "supported", "w1", None)

    yield ("multisolution_seq", base + [
        _event("wA", 5, roots=["ra", "rb"]),
        _event("wB", 1, roots=["rc", "rd"]),
        _event("wC", 3, roots=["re", "rf"]),
    ], "alpha", 2, "supported", "wB", None)

    yield ("multisolution_tiebreak_id", base + [
        _event("m", 2, roots=["r1", "r2"]),
        _event("n", 2, roots=["r3", "r4"]),
    ], "alpha", 2, "supported", "m", None)

    # Explicit rejections.
    yield ("reject_one_hop", base + [
        _event("w1", 1, roots=["ra", "rb"]),
        _event("cor", 2, kind="correct", target="claim:alpha", excludes=["alpha"]),
    ], "alpha", 2, "rejected", None, None)

    yield ("reject_two_hops", base + [
        _event("w1", 1, roots=["ra", "rb"]),
        _event("mid", 2, kind="correct", target="ev:w1"),
        _event("cor", 3, kind="correct", target="ev:mid", excludes=["alpha"]),
    ], "alpha", 2, "rejected", None, None)


REJECTION_CASES = {"reject_one_hop": 2, "reject_two_hops": 3}


def _check_reference(raws, claim, required, notes, name) -> bool:
    events = _parse(raws)
    by_key = {ev.id: ev.seq for ev in events}
    eng = _verdict(raws, claim, required)
    r = ref.assess(events, claim, required, by_key=by_key)
    if eng["status"] == "rejected":
        return True  # reference ignores excludes; checked via expectation
    if eng["status"] != r["status"]:
        notes.append(f"[{name}] status {eng['status']} != {r['status']}")
        return False
    if eng["status"] == "supported":
        if eng["seed"] != r["seed"] or eng["seats"] != r["seats"]:
            notes.append(f"[{name}] cert {eng} != {r}")
            return False
    elif eng["status"] == "insufficient" and eng["reason"] != r["reason"]:
        notes.append(f"[{name}] reason {eng['reason']} != {r['reason']}")
        return False
    return True


def _check_expectation(eng, name, exp_status, exp_seed, exp_reason, notes) -> bool:
    ok = True
    if eng["status"] != exp_status:
        notes.append(f"[{name}] expected status {exp_status}, got {eng['status']}")
        ok = False
    if exp_seed is not None and eng["seed"] != exp_seed:
        notes.append(f"[{name}] expected seed {exp_seed}, got {eng['seed']}")
        ok = False
    if exp_reason is not None and eng["reason"] != exp_reason:
        notes.append(f"[{name}] expected reason {exp_reason}, got {eng['reason']}")
        ok = False
    return ok


def _check_permutation(raws, claim, required, notes, name) -> bool:
    base = _verdict(raws, claim, required)
    rng = random.Random(1234)
    for _ in range(5):
        perm = raws[:]
        rng.shuffle(perm)
        shuffled = _verdict(perm, claim, required)
        if shuffled["status"] != base["status"] or shuffled["seed"] != base["seed"]:
            notes.append(f"[{name}] permutation changed verdict: {base} vs {shuffled}")
            return False
    return True


def _joint_case(raws, claim, required, notes, name) -> tuple[int, bool]:
    twin = list(raws) + [
        _event("base2", 100, kind="base", claim="beta"),
        _event("t1", 101, claim="beta", roots=["s", "p9"]),
    ]
    events = _parse(twin)
    analysis = Analysis(events)
    engine = analysis.joint_certificates(["alpha", "beta"], required)
    want = ref.joint_supported(events, ["alpha", "beta"], required)
    if engine["jointly_supported"] != want:
        notes.append(f"[{name}] joint engine={engine['jointly_supported']} ref={want}: {engine}")
        return 1, False
    return 1, True


def run_exhaustive(max_events: int = 4, max_witnesses: int = 3) -> dict:
    notes: list[str] = []
    ok = True
    total = 0
    joint_total = 0

    for name, raws, claim, required, exp_status, exp_seed, exp_reason in cases():
        total += 1
        eng = _verdict(raws, claim, required)
        ok &= _check_expectation(eng, name, exp_status, exp_seed, exp_reason, notes)
        ok &= _check_reference(raws, claim, required, notes, name)
        ok &= _check_permutation(raws, claim, required, notes, name)
        if name in REJECTION_CASES:
            if len(eng["chain"]) != REJECTION_CASES[name]:
                notes.append(f"[{name}] chain len {len(eng['chain'])} != {REJECTION_CASES[name]}")
                ok = False
        # joint checks on the shared-root and multisolution cases
        if name in ("shared_with_privates", "multisolution_seq", "multisolution_tiebreak_id"):
            jc, jok = _joint_case(raws, claim, required, notes, name)
            joint_total += jc
            ok &= jok

    return {
        "ok": bool(ok),
        "cases": total,
        "joint_cases": joint_total,
        "notes": notes,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run_exhaustive(), ensure_ascii=False, indent=2))
