"""Custody analysis: certificates, contradictions, independence.

Formal definitions (v1)
=======================

*Live set (revocation)*
    Base artifacts are unsigned by design; buffer/correction events must carry
    a valid signature.  ``R revokes T`` is an attack edge ``R -> T`` and we take
    the *grounded extension*: an event is IN when all its attackers are OUT (so
    an unattacked event is IN), OUT when some attacker is IN, otherwise
    undecided.  This is the semantics that does **not** let a revoked revoker
    kill its target: if ``C`` revokes ``A`` and ``A`` revokes ``B``, then ``C``
    is IN, ``A`` is OUT and ``B`` stays IN.

*Superseded set* (current view only)
    A live correction's ``corrects`` list names events that are stale for the
    current view.  Superseded events stay sealed historically but are not
    certificate material now.

*Certificate pool*
    ``live - superseded``; only buffers can be seeds or proxies.

*Closure of a seed*
    The seed is a pool buffer attesting the conclusion.  The closure is the set
    of pool events reachable from the seed along ``seen`` edges (multi-hop
    proxies).  A proxy must itself attest the conclusion; a ``seen`` reference
    that is absent, revoked, superseded, unsigned, not a buffer *or attests a
    different conclusion* is *missing evidence*.

*Cycle rule*
    In the induced ``seen`` subgraph, a node is cycle-cut iff it can reach
    itself by a path of length >= 1 (a self-loop counts).  Starting from the
    seed we keep only nodes reachable **without passing through a cycle-cut
    node**; the seed itself being cycle-cut empties the clean set.  Only clean
    nodes contribute seats, so a dependency cycle can never top up the count.

*Seats*
    The number of distinct custody roots declared by the clean nodes.  Temporary
    witnesses join through multi-hop proxies, and a shared root collapses to a
    single seat.

*Supported*
    A clean closure is a complete certificate when it is non-empty and has no
    missing evidence.  A conclusion with requirement ``K`` is supported iff some
    seed yields a complete certificate with at least ``K`` seats.

*Minimal certificate*
    Among supported certificates choose ``(seats, event count, stable order,
    seed)`` where stable order is the sorted tuple of ``(seq, id)`` pairs of the
    clean events.  This is a total order, so multi-solution cases are
    deterministic.

*Contradiction chain*
    Starting from live events that attest the conclusion, follow live
    corrections that affect them (``corrects`` membership, event target, or
    claim target).  A correction that lists the conclusion in ``excludes`` is an
    explicit rejection; the BFS distance is the chain length and the first such
    correction found is the shortest one (ties broken deterministically).  An
    explicit rejection takes precedence over a certificate: the conclusion is
    reported ``rejected`` and the supporting certificate, if any, is still
    surfaced.  No rejecter means a shortfall is *insufficient evidence*
    (缺证), subdivided into ``no_witness``, ``missing_evidence``,
    ``dependency_cycle`` or ``insufficient_roots``.

*Joint independence*
    Each conclusion draws ``K`` roots from a single complete certificate (so the
    seats really co-occur), and across a set of conclusions a root may seat only
    one conclusion (global unit root capacity).  Two witnesses that share a root
    but also carry private roots remain jointly independent; if the only roots
    available are the shared ones the joint requirement fails.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from itertools import combinations
from typing import Iterable, Mapping, Sequence

from .events import Event, parse_scope_ref


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _cycle_nodes(nodes: Iterable[str], edges: Mapping[str, Iterable[str]]) -> frozenset[str]:
    """Nodes lying on at least one directed cycle in the induced subgraph.

    A node is cyclic iff it can reach itself by a path of length >= 1 (a
    self-loop counts).  Implemented with plain reachability rather than a
    recursive SCC so it is easy to audit against the brute-force reference;
    custody closures are tiny, so the extra factor is irrelevant.
    """
    node_set = set(nodes)
    adj: dict[str, set[str]] = {
        n: {w for w in edges.get(n, ()) if w in node_set} for n in node_set
    }
    cyclic: set[str] = set()
    for start in node_set:
        seen: set[str] = set()
        stack: list[str] = list(adj.get(start, ()))
        while stack:
            v = stack.pop()
            if v == start:
                cyclic.add(start)  # found a path start -> ... -> start
                break
            if v in seen:
                continue
            seen.add(v)
            stack.extend(adj.get(v, ()))
    return frozenset(cyclic)


def event_claims(ev: Event) -> set[str]:
    return set(ev.attr_claims)


# --------------------------------------------------------------------------- #
# data types
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class MissingRef:
    source: str
    ref: str
    reason: str

    def as_dict(self) -> dict:
        return {"source": self.source, "ref": self.ref, "reason": self.reason}


@dataclass
class Certificate:
    claim: str
    seed: str
    events: tuple[str, ...]
    roots: tuple[str, ...]
    cycle_events: tuple[str, ...]
    missing: tuple[MissingRef, ...]
    seats: int
    complete: bool
    raw_seats: int = 0     # seats if cycles were ignored (diagnostic only)

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def order_key(self) -> tuple:
        # Stable order is supplied by the caller through ``stable`` tuples.
        return (self.seats, self.event_count, self.seed)

    def as_dict(self) -> dict:
        return {
            "claim": self.claim,
            "seed": self.seed,
            "events": list(self.events),
            "roots": list(self.roots),
            "cycle_events": list(self.cycle_events),
            "missing": [m.as_dict() for m in self.missing],
            "seats": self.seats,
            "raw_seats": self.raw_seats,
            "event_count": self.event_count,
            "complete": self.complete,
        }


@dataclass
class Verdict:
    claim: str
    required: int
    status: str                      # supported | rejected | insufficient
    reason: str
    certificate: Certificate | None = None
    contradiction_chain: tuple[str, ...] = ()
    rejection_event: str | None = None
    candidates_considered: int = 0
    details: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "supported"

    def as_dict(self) -> dict:
        return {
            "claim": self.claim,
            "required_roots": self.required,
            "status": self.status,
            "reason": self.reason,
            "certificate": self.certificate.as_dict() if self.certificate else None,
            "contradiction_chain": list(self.contradiction_chain),
            "rejection_event": self.rejection_event,
            "candidates_considered": self.candidates_considered,
            "details": self.details,
        }


# --------------------------------------------------------------------------- #
# analysis
# --------------------------------------------------------------------------- #

class Analysis:
    """Custody analysis over a fixed collection of synthetic events."""

    def __init__(self, events: Iterable[Event], keys: Mapping[str, bytes] | None = None) -> None:
        self.events: dict[str, Event] = {}
        self.duplicates: list[str] = []
        self.structure_errors: dict[str, str] = {}
        self.signature_failures: list[str] = []
        for ev in events:
            if not ev.is_usable:
                self.structure_errors[ev.id] = ev.structure_error or "invalid"
                continue
            if ev.id in self.events:
                self.duplicates.append(ev.id)
                continue
            self.events[ev.id] = ev
        for ev in self.events.values():
            if ev.kind in ("buffer", "correct") and not ev.signature_ok:
                self.signature_failures.append(ev.id)

        self._index()
        self._compute_live()
        self._closure_cache: dict[str, tuple[tuple[str, ...], tuple[MissingRef, ...]]] = {}
        self._cert_cache: dict[tuple[str, int], list[Certificate]] = {}

    # --------------------------------------------------------------- indexing
    def _index(self) -> None:
        self.seen_out: dict[str, tuple[str, ...]] = {}
        self.seen_in: dict[str, list[str]] = defaultdict(list)
        self.corrects_in: dict[str, list[str]] = defaultdict(list)
        self.target_event_in: dict[str, list[str]] = defaultdict(list)
        self.claim_correctors: dict[str, list[str]] = defaultdict(list)
        self.claim_index: dict[str, list[str]] = defaultdict(list)
        self.revokers_of: dict[str, list[str]] = defaultdict(list)
        for ev in self.events.values():
            for ref in ev.seen:
                kind = "event"
                tid = ref
                if ref.startswith(("ev:", "claim:", "cl:")):
                    k, v = parse_scope_ref(ref)
                    if k != "event":
                        kind = "non_event"
                    tid = v
                self.seen_in[tid].append(ev.id)
            for cid in ev.corrects:
                self.corrects_in[cid].append(ev.id)
            if ev.kind == "correct" and ev.target:
                k, v = parse_scope_ref(ev.target)
                if k == "event":
                    self.target_event_in[v].append(ev.id)
                elif k == "claim":
                    self.claim_correctors[v].append(ev.id)
                elif k == "claim_hash":
                    self.claim_correctors["cl:" + v].append(ev.id)
            for c in ev.attr_claims:
                self.claim_index[c].append(ev.id)
            for t in ev.revokes:
                self.revokers_of[t].append(ev.id)

    # ------------------------------------------------------------- live sets
    def _compute_live(self) -> None:
        """Grounding semantics for revocation.

        "R revokes T" is an attack edge R -> T.  Label events with the grounded
        extension:

        * IN  when every attacker is OUT (vacuously IN when unattacked),
        * OUT when some attacker is IN,
        * UNDECIDED otherwise (attacked only from attack cycles).

        This is the one semantics that does not let a revoked revoker kill its
        target: if C revokes A and A revokes B, then C is IN, A is OUT, and B
        stays IN.  ``live`` is the IN set; ``revoked`` is everything else.
        """
        candidates: set[str] = set()
        for eid, ev in self.events.items():
            if ev.kind == "base":
                candidates.add(eid)
            elif ev.signature_ok:
                candidates.add(eid)

        attackers: dict[str, set[str]] = defaultdict(set)
        for target, revokers in self.revokers_of.items():
            for r in revokers:
                if r in candidates and target in candidates:
                    attackers[target].add(r)

        inn: set[str] = set()
        out: set[str] = set()
        changed = True
        while changed:
            changed = False
            for eid in sorted(candidates):
                if eid in inn or eid in out:
                    continue
                atk = attackers.get(eid, set())
                if any(a in inn for a in atk):
                    out.add(eid)
                    changed = True
                elif all(a in out for a in atk):
                    inn.add(eid)
                    changed = True
        self.live: set[str] = inn
        self.revoked: set[str] = candidates - inn
        self.undecided: set[str] = candidates - inn - out

        superseded: set[str] = set()
        for eid in self.live:
            ev = self.events[eid]
            if ev.kind == "correct":
                for cid in ev.corrects:
                    if cid in self.events:
                        superseded.add(cid)
        self.superseded: set[str] = superseded
        self.pool: set[str] = {eid for eid in self.live if eid not in superseded}

    # --------------------------------------------------------------- closures
    def closure(self, seed: str, claim: str | None = None) -> tuple[tuple[str, ...], tuple[MissingRef, ...]]:
        cache_key = seed + "\x00" + (claim or "")
        if cache_key in self._closure_cache:
            return self._closure_cache[cache_key]
        nodes: list[str] = []
        missing: list[MissingRef] = []
        seen_nodes: set[str] = set()
        queue: deque[str] = deque([seed])
        while queue:
            eid = queue.popleft()
            if eid in seen_nodes:
                continue
            seen_nodes.add(eid)
            nodes.append(eid)
            ev = self.events.get(eid)
            if ev is None:
                continue
            for ref in ev.seen:
                target, reason = self._resolve_proxy(ref, claim)
                if target is None:
                    missing.append(MissingRef(source=eid, ref=ref, reason=reason))
                    continue
                if target not in seen_nodes:
                    queue.append(target)
        result = (tuple(sorted(nodes)), tuple(missing))
        self._closure_cache[cache_key] = result
        return result

    def _resolve_proxy(self, ref: str, claim: str | None) -> tuple[str | None, str]:
        if ref.startswith(("ev:", "claim:", "cl:")):
            kind, value = parse_scope_ref(ref)
            if kind != "event":
                return None, "proxy_must_name_event"
            ref = value
        ev = self.events.get(ref)
        if ev is None:
            return None, "absent"
        if ev.kind != "buffer":
            return None, "not_a_buffer"
        if ref in self.revoked:
            return None, "revoked"
        if ref in self.superseded:
            return None, "superseded"
        if not ev.signature_ok:
            return None, "bad_signature"
        if ref not in self.pool:
            return None, "inactive"
        if claim is not None and claim not in ev.attr_claims:
            return None, "claim_mismatch"
        return ref, ""

    def _closure_graph(self, nodes: Sequence[str], claim: str | None = None) -> tuple[dict[str, set[str]], frozenset[str]]:
        node_set = set(nodes)
        adj: dict[str, set[str]] = {n: set() for n in nodes}
        for eid in nodes:
            ev = self.events.get(eid)
            if ev is None:
                continue
            for ref in ev.seen:
                target, _ = self._resolve_proxy(ref, claim)
                if target is not None and target in node_set:
                    adj[eid].add(target)
        cyclic = _cycle_nodes(nodes, adj)
        return adj, cyclic

    def _clean_nodes(self, seed: str, nodes: Sequence[str], adj: Mapping[str, set[str]],
                     cyclic: frozenset[str]) -> set[str]:
        """Nodes reachable from the seed without passing through a cyclic node.

        The seed itself is excluded from the result when it is cyclic (the whole
        certificate then has no clean footing and is incomplete).
        """
        if seed in cyclic:
            return set()
        clean: set[str] = set()
        stack = [seed]
        while stack:
            v = stack.pop()
            if v in clean:
                continue
            clean.add(v)
            for w in adj.get(v, ()):
                if w not in cyclic and w not in clean:
                    stack.append(w)
        return clean

    def _seats(self, nodes: Iterable[str]) -> tuple[str, ...]:
        roots: set[str] = set()
        for eid in nodes:
            ev = self.events.get(eid)
            if ev is None or ev.kind != "buffer":
                continue
            roots.update(ev.roots)
        return tuple(sorted(roots))

    def _missing_from(self, clean: Iterable[str], claim: str | None) -> tuple[MissingRef, ...]:
        out: list[MissingRef] = []
        for eid in sorted(clean):
            ev = self.events.get(eid)
            if ev is None:
                continue
            for ref in ev.seen:
                target, reason = self._resolve_proxy(ref, claim)
                if target is None:
                    out.append(MissingRef(source=eid, ref=ref, reason=reason))
        return tuple(out)

    # ----------------------------------------------------------- certificates
    def seed_candidates(self, claim: str) -> list[str]:
        out: list[str] = []
        for eid in self.claim_index.get(claim, ()):
            ev = self.events[eid]
            if ev.kind == "buffer" and eid in self.pool:
                out.append(eid)
        return sorted(set(out))

    def certificates_for(self, claim: str, required: int = 1) -> list[Certificate]:
        key = (claim, required)
        if key in self._cert_cache:
            return self._cert_cache[key]
        certs: list[Certificate] = []
        for seed in self.seed_candidates(claim):
            nodes, _ = self.closure(seed, claim)
            adj, cyclic = self._closure_graph(nodes, claim)
            clean = self._clean_nodes(seed, nodes, adj, cyclic)
            roots = self._seats(clean)
            raw_roots = self._seats(nodes)  # diagnostic: ignore cycles entirely
            missing = self._missing_from(clean, claim)
            complete = bool(clean) and not missing
            cert = Certificate(
                claim=claim,
                seed=seed,
                events=tuple(sorted(clean)),
                roots=roots,
                cycle_events=tuple(sorted(cyclic)),
                missing=missing,
                seats=len(roots),
                complete=complete,
                raw_seats=len(raw_roots),
            )
            certs.append(cert)
        self._cert_cache[key] = certs
        return certs

    def _stable_tuple(self, cert: Certificate) -> tuple:
        pairs = sorted(
            (self.events[eid].seq, eid) for eid in cert.events if eid in self.events
        )
        return tuple(pairs)

    def minimal_certificate(self, claim: str, required: int) -> Certificate | None:
        best: Certificate | None = None
        best_key: tuple | None = None
        for cert in self.certificates_for(claim, required):
            if not cert.complete or cert.seats < required:
                continue
            key = (cert.seats, cert.event_count, self._stable_tuple(cert), cert.seed)
            if best_key is None or key < best_key:
                best_key = key
                best = cert
        return best

    def best_effort_certificate(self, claim: str) -> Certificate | None:
        """Highest-seat certificate even if incomplete, for diagnostics."""
        best: Certificate | None = None
        best_key: tuple | None = None
        for cert in self.certificates_for(claim, 0):
            key = (cert.complete, cert.seats, -cert.event_count, cert.seed)
            if best_key is None or key > best_key:
                best_key = key
                best = cert
        return best

    # ----------------------------------------------------------- rejection
    def _affecting_corrections(self, event_id: str, claim: str | None = None) -> list[str]:
        out: set[str] = set()
        for cid in self.corrects_in.get(event_id, ()):
            if cid in self.pool:
                out.add(cid)
        for cid in self.target_event_in.get(event_id, ()):
            if cid in self.pool:
                out.add(cid)
        claims = set()
        ev = self.events.get(event_id)
        if ev is not None:
            claims.update(ev.attr_claims)
        if claim:
            claims.add(claim)
        for c in claims:
            for cid in self.claim_correctors.get(c, ()):
                if cid in self.pool:
                    out.add(cid)
        return sorted(out)

    def rejection_chain(self, claim: str) -> tuple[tuple[str, ...], str | None]:
        """Shortest chain of live corrections from a carrier to an excluder.

        A carrier is any live, non-superseded event that attests the claim and
        is *not* a correction (a correction is the rejecter side, not
        supporting evidence).  We BFS across correction edges (``corrects``,
        event target, claim target) and, on every node popped, test whether it
        is a correction listing the claim in ``excludes``.  Because BFS is level
        order and carriers are seeded first, the first excluder found yields a
        shortest chain; ties break deterministically by sorted seeds and sorted
        neighbours.
        """
        carriers = sorted(
            eid for eid in self.claim_index.get(claim, ())
            if eid in self.live
            and eid not in self.superseded
            and self.events[eid].kind != "correct"
        )

        def is_excluder(eid: str) -> bool:
            ev = self.events.get(eid)
            return ev is not None and ev.kind == "correct" and claim in ev.excludes

        parent: dict[str, str | None] = {eid: None for eid in carriers}
        queue: deque[str] = deque(carriers)
        while queue:
            eid = queue.popleft()
            if is_excluder(eid):
                path: list[str] = []
                cur: str | None = eid
                while cur is not None:
                    path.append(cur)
                    cur = parent.get(cur)
                path.reverse()
                return tuple(path), eid
            for cid in self._affecting_corrections(eid, claim):
                if cid in parent:
                    continue
                parent[cid] = eid
                queue.append(cid)
        return (), None

    # --------------------------------------------------------------- verdict
    def assess(self, claim: str, required: int = 1) -> Verdict:
        if required < 1:
            raise ValueError("required root count must be at least 1")
        cert = self.minimal_certificate(claim, required)
        chain, rejecter = self.rejection_chain(claim)
        candidates = len(self.certificates_for(claim, required))
        details: dict = {}
        best = self.best_effort_certificate(claim)
        if best is not None:
            details["best_partial"] = best.as_dict()

        if rejecter is not None:
            return Verdict(
                claim=claim,
                required=required,
                status="rejected",
                reason="explicit_rejection",
                certificate=cert,
                contradiction_chain=chain,
                rejection_event=rejecter,
                candidates_considered=candidates,
                details=details,
            )

        if cert is not None:
            return Verdict(
                claim=claim,
                required=required,
                status="supported",
                reason="certificate",
                certificate=cert,
                candidates_considered=candidates,
                details=details,
            )

        # No certificate reached the bar.  Classify the shortfall precisely so
        # "explicit rejection" (above) stays distinct from "insufficient
        # evidence" and the sub-reason is reproducible:
        #   no_witness        - nothing even attests the claim
        #   dependency_cycle  - a candidate would qualify if cycles counted
        #   missing_evidence  - a candidate carries enough seats but a proxy dangles
        #   insufficient_roots- otherwise genuinely too few distinct roots
        candidates_all = self.certificates_for(claim, required)
        missing: list[dict] = []
        any_cycle_loss = False
        any_missing_loss = False
        for cand in candidates_all:
            if not cand.missing and cand.raw_seats >= required >= 1 and cand.seats < required:
                any_cycle_loss = True
            if cand.missing and cand.seats >= required:
                any_missing_loss = True
            missing.extend(m.as_dict() for m in cand.missing)
        if not self.seed_candidates(claim):
            reason = "no_witness"
        elif any_missing_loss:
            reason = "missing_evidence"
        elif any_cycle_loss:
            reason = "dependency_cycle"
        else:
            reason = "insufficient_roots"
        details["missing"] = missing
        return Verdict(
            claim=claim,
            required=required,
            status="insufficient",
            reason=reason,
            candidates_considered=candidates,
            details=details,
        )

    # ----------------------------------------------------- joint independence
    def complete_certificates(self, claim: str, required: int) -> list[Certificate]:
        certs = [
            c for c in self.certificates_for(claim, required)
            if c.complete and c.seats >= required
        ]
        certs.sort(key=lambda c: (c.seats, c.event_count, self._stable_tuple(c), c.seed))
        return certs

    def joint_certificates(self, claims: Sequence[str], required: int = 1) -> dict:
        """Jointly independent certificates with global unit root capacity.

        A root seats at most one conclusion across the whole set.  Two witnesses
        that share a root but also carry private roots remain jointly
        independent; if the only roots available are the shared ones the joint
        requirement fails.

        Each conclusion must be backed by a *single* complete certificate (so
        its ``required`` seats really co-occur in one witnessed chain); roots
        are then matched globally with capacity one.  The search is exact
        backtracking, which is fine for the small graphs this is meant for and
        is what the exhaustive test checks.
        """
        claim_list = list(claims)
        options = {c: self.complete_certificates(c, required) for c in claim_list}
        best_assign: dict[str, list[str]] | None = None

        # For each claim, the candidate seat-sets are all required-sized subsets
        # of each complete certificate's roots (sorted, deterministic).
        seat_sets: dict[str, list[tuple[str, ...]]] = {}
        for c in claim_list:
            pool: list[tuple[str, ...]] = []
            for cert in options[c]:
                for combo in combinations(cert.roots, required):
                    pool.append(combo)
            # dedupe, stable order
            seen: set[tuple[str, ...]] = set()
            uniq: list[tuple[str, ...]] = []
            for combo in pool:
                if combo not in seen:
                    seen.add(combo)
                    uniq.append(combo)
            seat_sets[c] = uniq

        # Try claims in order of fewest seat-sets first, for early pruning.
        order = sorted(claim_list, key=lambda c: (len(seat_sets[c]), c))

        def search(i: int, used: set[str], chosen: dict[str, list[str]]) -> bool:
            nonlocal best_assign
            if i == len(order):
                best_assign = dict(chosen)
                return True
            claim = order[i]
            for combo in seat_sets[claim]:
                if any(r in used for r in combo):
                    continue
                chosen[claim] = list(combo)
                if search(i + 1, used | set(combo), chosen):
                    return True
                del chosen[claim]
            return False

        feasible = bool(claim_list) and search(0, set(), {})
        pools = {
            c: sorted({r for combo in seat_sets[c] for r in combo}) for c in claim_list
        }
        shared = sorted(
            r for r in {r for pool in pools.values() for r in pool}
            if sum(1 for c in claim_list if r in pools[c]) > 1
        )
        empty = [c for c in claim_list if not options[c]]
        total_need = required * len(claim_list)
        assignments = best_assign or {}
        return {
            "claims": claim_list,
            "required_each": required,
            "total_required": total_need,
            "total_satisfied": sum(len(v) for v in assignments.values()),
            "jointly_supported": feasible and not empty,
            "assignments": {c: sorted(assignments.get(c, [])) for c in claim_list},
            "shared_roots": shared,
            "pools": pools,
            "unsupported_claims": empty,
        }

    # ------------------------------------------------------------- reporting
    def summary(self) -> dict:
        return {
            "events": len(self.events),
            "live": len(self.live),
            "revoked": sorted(self.revoked),
            "superseded": sorted(self.superseded),
            "signature_failures": sorted(self.signature_failures),
            "structure_errors": dict(sorted(self.structure_errors.items())),
            "duplicates": sorted(set(self.duplicates)),
        }
