"""Independent, deliberately naive reference for the custody rules.

Shares no helper code with :mod:`custody.analysis`.  It re-derives revocation
(grounded extension), supersession, closures, cycles, seats and minimal
certificates from first principles so the exhaustive tests can cross-check the
optimised engine.  Only fast enough for tiny graphs, which is the point.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from typing import Iterable

from custody.events import Event


# --------------------------------------------------------------------------- #
# revocation / supersession
# --------------------------------------------------------------------------- #

def grounded_live(events: dict[str, Event]) -> set[str]:
    candidates = {
        eid for eid, ev in events.items()
        if ev.kind == "base" or ev.signature_ok
    }
    attackers: dict[str, set[str]] = {}
    for ev in events.values():
        if not ev.signature_ok and ev.kind != "base":
            continue
        for target in ev.revokes:
            if ev.id in candidates and target in candidates:
                attackers.setdefault(target, set()).add(ev.id)
    inn: set[str] = set()
    out: set[str] = set()
    changed = True
    while changed:
        changed = False
        for eid in candidates:
            if eid in inn or eid in out:
                continue
            atk = attackers.get(eid, set())
            if any(a in inn for a in atk):
                out.add(eid)
                changed = True
            elif all(a in out for a in atk):
                inn.add(eid)
                changed = True
    return inn


def superseded_of(events: dict[str, Event], live: set[str]) -> set[str]:
    sup: set[str] = set()
    for eid in live:
        ev = events[eid]
        if ev.kind == "correct":
            for cid in ev.corrects:
                if cid in events:
                    sup.add(cid)
    return sup


# --------------------------------------------------------------------------- #
# certificates
# --------------------------------------------------------------------------- #

def _attests(ev: Event, claim: str) -> bool:
    return ev.claim == claim or claim in ev.attrs


def _pool(events: dict[str, Event], claim: str) -> dict[str, Event]:
    live = grounded_live(events)
    sup = superseded_of(events, live)
    pool: dict[str, Event] = {}
    for eid in live:
        ev = events[eid]
        if ev.kind != "buffer":
            continue
        if eid in sup:
            continue
        if not _attests(ev, claim):
            # still a valid pool event, but a proxy must attest; keep it out of
            # the proxy set by omission from this claim-bound pool
            continue
        pool[eid] = ev
    return pool


def _seen_targets(ev: Event) -> list[str]:
    out: list[str] = []
    for ref in ev.seen:
        out.append(ref[3:] if ref.startswith("ev:") else ref)
    return out


def _reachable(start: str, pool: dict[str, Event]) -> set[str]:
    seen: set[str] = set()
    stack = [start]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for target in _seen_targets(pool[cur]):
            if target in pool:
                stack.append(target)
    return seen


def _is_cyclic(node: str, pool: dict[str, Event]) -> bool:
    seen: set[str] = set()
    stack = [t for t in _seen_targets(pool[node]) if t in pool]
    while stack:
        cur = stack.pop()
        if cur == node:
            return True
        if cur in seen:
            continue
        seen.add(cur)
        for target in _seen_targets(pool[cur]):
            if target in pool:
                stack.append(target)
    return False


def _dangling(clean: set[str], pool: dict[str, Event], all_ids: set[str]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for nid in clean:
        for target in _seen_targets(pool[nid]):
            if target not in all_ids or target not in pool:
                out.append((nid, target))
    return out


@dataclass(frozen=True)
class RefCert:
    seed: str
    clean: tuple[str, ...]
    roots: tuple[str, ...]
    missing: tuple[tuple[str, str], ...]
    cyclic: tuple[str, ...]
    complete: bool
    raw_roots: tuple[str, ...]

    @property
    def seats(self) -> int:
        return len(self.roots)


def certificate_for(seed: str, pool: dict[str, Event], all_ids: set[str]) -> RefCert:
    reach = _reachable(seed, pool)
    cyclic = {n for n in reach if _is_cyclic(n, pool)}
    if seed in cyclic:
        clean: set[str] = set()
    else:
        clean = set()
        stack = [seed]
        while stack:
            cur = stack.pop()
            if cur in clean:
                continue
            clean.add(cur)
            for target in _seen_targets(pool[cur]):
                if target in pool and target not in cyclic:
                    stack.append(target)
    roots: set[str] = set()
    for nid in clean:
        roots.update(pool[nid].roots)
    raw: set[str] = set()
    for nid in reach:
        raw.update(pool[nid].roots)
    missing = _dangling(clean, pool, all_ids)
    return RefCert(
        seed=seed,
        clean=tuple(sorted(clean)),
        roots=tuple(sorted(roots)),
        missing=tuple(sorted(set(missing))),
        cyclic=tuple(sorted(cyclic)),
        complete=bool(clean) and not missing,
        raw_roots=tuple(sorted(raw)),
    )


def all_certificates(events: list[Event], claim: str) -> list[RefCert]:
    by_id = {ev.id: ev for ev in events}
    pool = _pool(by_id, claim)
    all_ids = set(by_id)
    out: list[RefCert] = []
    for eid in sorted(pool):
        out.append(certificate_for(eid, pool, all_ids))
    return out


def assess(events: list[Event], claim: str, required: int, by_key: dict[str, int] | None = None) -> dict:
    certs = all_certificates(events, claim)
    qualifying = [c for c in certs if c.complete and c.seats >= required]
    if qualifying:
        def key(c: RefCert):
            stable = tuple(sorted((by_key[eid], eid) for eid in c.clean)) if by_key else c.clean
            return (c.seats, len(c.clean), stable, c.seed)
        best = min(qualifying, key=key)
        return {
            "status": "supported",
            "seed": best.seed,
            "seats": best.seats,
            "event_count": len(best.clean),
            "roots": list(best.roots),
        }
    if not certs:
        return {"status": "insufficient", "reason": "no_witness", "seed": None, "seats": 0}
    missing_loss = any(c.missing and c.seats >= required for c in certs)
    cycle_loss = any(
        not c.missing and len(c.raw_roots) >= required and c.seats < required
        for c in certs
    )
    if missing_loss:
        reason = "missing_evidence"
    elif cycle_loss:
        reason = "dependency_cycle"
    else:
        reason = "insufficient_roots"
    return {"status": "insufficient", "reason": reason, "seed": None, "seats": 0}


def joint_supported(events: list[Event], claims: list[str], required: int) -> bool:
    """Brute force: each claim gets ``required`` roots from one certificate, all
    roots globally distinct? """
    seat_sets: dict[str, set[tuple[str, ...]]] = {}
    for claim in claims:
        sets: set[tuple[str, ...]] = set()
        for cert in all_certificates(events, claim):
            if cert.complete and cert.seats >= required:
                for combo in combinations(cert.roots, required):
                    sets.add(tuple(sorted(combo)))
        seat_sets[claim] = sets
    if any(not seat_sets[c] for c in claims):
        return False
    order = sorted(claims, key=lambda c: (len(seat_sets[c]), c))

    def go(i: int, used: set[str]) -> bool:
        if i == len(order):
            return True
        for combo in sorted(seat_sets[order[i]]):
            if used & set(combo):
                continue
            if go(i + 1, used | set(combo)):
                return True
        return False

    return go(0, set())
