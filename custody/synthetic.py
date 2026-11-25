"""Deterministic synthetic corpora.

Everything is generated locally from a fixed seed; there is no network, no wall
clock and no real evidence.

``fixed_timeline`` builds a small arrival sequence that exercises every headline
feature (independent roots, shared roots, a dependency cycle, missing evidence,
an explicit rejection, and a late correction that must not disturb an earlier
seal).

``generate_corpus`` builds a large corpus partitioned by organisation.  Each
conclusion is self-contained inside its own component: a base artifact plus two
signed witnesses where the second proxies through the first, so it shares one
root and adds a private one.  Because all references stay inside one conclusion,
the influence class of a retracted witness is small, which is what makes the
single-point retraction genuinely local.  Sparse corrections and revocations
keep the live-set fixpoint exercised.
"""

from __future__ import annotations

from typing import Any

from .events import with_signature

ORG_COUNT = 8


def _buffer(eid: str, seq: int, at: int, claim: str, signer: str,
            roots: list[str], seen: list[str] | None = None,
            org: str | None = None, revokes: list[str] | None = None,
            keys=None) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "id": eid, "kind": "buffer", "seq": seq, "at": at,
        "claim": claim, "signer": signer, "roots": roots, "seen": seen or [],
    }
    if org:
        raw["org"] = org
    if revokes:
        raw["revokes"] = revokes
    return with_signature(raw, keys)


def _base(eid: str, seq: int, at: int, claim: str, org: str) -> dict[str, Any]:
    return {"id": eid, "kind": "base", "seq": seq, "at": at, "claim": claim, "org": org}


def _correct(eid: str, seq: int, at: int, signer: str, target: str, claim: str,
             excludes: list[str] | None = None, corrects: list[str] | None = None,
             keys=None) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "id": eid, "kind": "correct", "seq": seq, "at": at, "signer": signer,
        "target": target, "claim": claim,
        "excludes": excludes or [], "corrects": corrects or [],
    }
    return with_signature(raw, keys)


def fixed_timeline(keys=None) -> dict[str, Any]:
    """A deterministic arrival sequence exercising every headline feature."""
    arrivals: list[dict[str, Any]] = []

    # (1) Three independent roots assembled through one temporary proxy hop.
    arrivals.append(_base("a1", 1, 10, "disk mounted read-only", "org-alpha"))
    arrivals.append(_buffer("a2", 2, 20, "disk mounted read-only", "r1",
                            ["r1", "r2"], org="org-alpha", keys=keys))
    arrivals.append(_buffer("a3", 3, 30, "disk mounted read-only", "r2",
                            ["r2", "r3"], seen=["a2"], org="org-alpha", keys=keys))

    # (2) Two witnesses share root r4: 4 declared root-slots collapse to 3 seats.
    arrivals.append(_base("b1", 4, 40, "partition encrypted", "org-beta"))
    arrivals.append(_buffer("b2", 5, 50, "partition encrypted", "r4",
                            ["r4", "r5"], org="org-beta", keys=keys))
    arrivals.append(_buffer("b3", 6, 60, "partition encrypted", "r4",
                            ["r4", "r6"], seen=["b2"], org="org-beta", keys=keys))

    # (3) Dependency cycle: c4 <-> c5 proxy each other; neither may top up.
    arrivals.append(_base("c1", 7, 70, "memory captured", "org-gamma"))
    arrivals.append(_buffer("c2", 8, 80, "memory captured", "r7",
                            ["r7"], org="org-gamma", keys=keys))
    arrivals.append(_buffer("c4", 9, 90, "memory captured", "r8",
                            ["r8", "r9"], seen=["c5"], org="org-gamma", keys=keys))
    arrivals.append(_buffer("c5", 10, 100, "memory captured", "r9",
                            ["r9", "r10"], seen=["c4"], org="org-gamma", keys=keys))

    # (4) Missing evidence: d2 proxies d3, which never arrives.
    arrivals.append(_base("d1", 11, 110, "clock synced", "org-delta"))
    arrivals.append(_buffer("d2", 12, 120, "clock synced", "r11",
                            ["r11", "r12"], seen=["d3"], org="org-delta", keys=keys))

    # (5) Explicit rejection.
    arrivals.append(_base("e1", 13, 130, "backup verified", "org-epsilon"))
    arrivals.append(_buffer("e2", 14, 140, "backup verified", "r13",
                            ["r13", "r14"], org="org-epsilon", keys=keys))
    arrivals.append(_correct("e3", 15, 150, "r13", "claim:backup verified",
                             "backup not verified", excludes=["backup verified"],
                             keys=keys))

    # (6) Late correction.  f3 logically precedes f4 (at 158 < 162) but arrives
    #     last.  Before f3, the minimal certificate for "device wiped" is f2
    #     (2 seats, seq 17).  f3 supersedes f2, so the current minimal
    #     certificate becomes f4.  A seal taken before f3 must restore byte for
    #     byte and still show f2 as its historical seed.
    arrivals.append(_base("f1", 16, 155, "device wiped", "org-zeta"))
    arrivals.append(_buffer("f2", 17, 160, "device wiped", "r15",
                            ["r15", "r16"], org="org-zeta", keys=keys))
    arrivals.append(_buffer("f4", 18, 162, "device wiped", "r17",
                            ["r17", "r18"], org="org-zeta", keys=keys))
    arrivals.append(_correct("f3", 19, 158, "r15", "claim:device wiped",
                             "device wiped", corrects=["f2"], keys=keys))

    return {
        "arrivals": arrivals,
        "claims": [
            "disk mounted read-only",
            "partition encrypted",
            "memory captured",
            "clock synced",
            "backup verified",
            "device wiped",
        ],
        "required": {
            "disk mounted read-only": 3,
            "partition encrypted": 3,
            "memory captured": 2,
            "clock synced": 2,
            "backup verified": 2,
            "device wiped": 2,
        },
        "seal_before_late_id": "f3",
        "late_claim": "device wiped",
        "historical_seed": "f2",
    }


def generate_corpus(total_events: int = 60_000, orgs: int = ORG_COUNT,
                    seed: int = 20261126, keys=None) -> list[dict[str, Any]]:
    """Deterministic corpus partitioned into ``orgs`` organisations.

    Each conclusion owns exactly one base artifact and two signed witnesses
    (``w0`` then ``w1`` proxying through ``w0``).  All references stay inside the
    conclusion, so a witness retraction only influences its own component.
    """
    arrivals: list[dict[str, Any]] = []
    per_org = max(1, total_events // orgs)
    seq = 0
    at = 0

    def bump() -> tuple[int, int]:
        nonlocal seq, at
        seq += 1
        at += 1
        return seq, at

    for oi in range(orgs):
        org = f"org-{oi:02d}"
        produced = 0
        ci = 0
        while produced < per_org:
            claim = f"{org} conclusion {ci:06d}"
            r0 = f"root-{oi:02d}-{ci:06d}-a"
            r1 = f"root-{oi:02d}-{ci:06d}-b"
            r2 = f"root-{oi:02d}-{ci:06d}-c"
            base_id = f"e{oi:02d}-{ci:06d}-base"
            w0 = f"e{oi:02d}-{ci:06d}-w0"
            w1 = f"e{oi:02d}-{ci:06d}-w1"

            s, t = bump()
            arrivals.append(_base(base_id, s, t, claim, org))
            produced += 1

            s, t = bump()
            arrivals.append(_buffer(w0, s, t, claim, r0, [r0, r1],
                                    org=org, keys=keys))
            produced += 1

            s, t = bump()
            arrivals.append(_buffer(w1, s, t, claim, r1, [r1, r2], seen=[w0],
                                    org=org, keys=keys))
            produced += 1

            # Sparse correction: extends the claim set, supersedes nothing.
            if ci % 250 == 7:
                s, t = bump()
                arrivals.append(_correct(f"e{oi:02d}-{ci:06d}-cor", s, t, r0,
                                         f"claim:{claim}", claim, keys=keys))
                produced += 1

            # Sparse revocation: retract w0 of the *same* conclusion, so the
            # class stays local.  w1 now dangles -> that conclusion turns into
            # missing evidence, demonstrating that revocation is live.
            if ci % 400 == 399:
                s, t = bump()
                arrivals.append(_buffer(f"e{oi:02d}-{ci:06d}-rev", s, t, claim, r0,
                                        [r0, r1], org=org, revokes=[w0], keys=keys))
                produced += 1

            ci += 1
    return arrivals[:total_events]
