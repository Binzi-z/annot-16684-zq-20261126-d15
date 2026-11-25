"""Organisation-partitioned store with measured single-point retraction.

Partitioning
------------
Every event belongs to one component keyed by its organisation (``__global__``
when an event has no org).  Components are joined in an *undirected influence
graph* whenever:

* an event in one component references an event in another through ``seen``,
  ``corrects``, ``target`` or ``revokes``; or
* two components carry events for the same conclusion claim.

A conclusion's certificates can only use events from its connected class: a
``seen`` proxy, a correction target and a revocation target are all influence
edges, and every carrier of a claim is in that claim's class.  So retracting a
point only requires re-analysing the class that contains it.

Retraction
----------
``Store.retract(event_id)``:

1. finds the affected class (and nothing else),
2. re-analyses that class's conclusions from the class's remaining events,
3. reuses the cached verdicts for every other class,
4. runs a *complete full recheck* over all remaining events and reports every
   field-level difference against the incremental answer.

The reported counters are exactly what the incremental path loaded, so the
locality claim is measured rather than asserted.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .analysis import Analysis, Certificate, MissingRef, Verdict
from .events import Event, parse_scope_ref

GLOBAL_COMPONENT = "__global__"


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, x: str) -> None:
        self.parent.setdefault(x, x)

    def find(self, x: str) -> str:
        self.add(x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # deterministic root choice
            lo, hi = sorted((ra, rb))
            self.parent[hi] = lo

    def class_members(self) -> dict[str, set[str]]:
        classes: dict[str, set[str]] = defaultdict(set)
        for x in self.parent:
            classes[self.find(x)].add(x)
        return classes


def fingerprint(verdict: Verdict) -> dict:
    cert = verdict.certificate
    return {
        "status": verdict.status,
        "reason": verdict.reason,
        "seats": cert.seats if cert else 0,
        "event_count": cert.event_count if cert else 0,
        "seed": cert.seed if cert else None,
        "roots": list(cert.roots) if cert else [],
        "events": list(cert.events) if cert else [],
        "cycle_events": list(cert.cycle_events) if cert else [],
        "missing": [m.as_dict() for m in cert.missing] if cert else [],
        "contradiction_chain": list(verdict.contradiction_chain),
        "rejection_event": verdict.rejection_event,
    }


@dataclass
class RetractionResult:
    event_id: str
    removed_component: str
    class_components: tuple[str, ...]
    components_total: int
    events_total: int
    events_read: int
    claims_total: int
    claims_recomputed: int
    claims_reused: int
    incremental: dict[str, dict]
    full_checked: int
    differences: list[dict]

    def as_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "removed_component": self.removed_component,
            "components_total": self.components_total,
            "components_read": len(self.class_components),
            "class_components": list(self.class_components),
            "events_total": self.events_total,
            "events_read": self.events_read,
            "claims_total": self.claims_total,
            "claims_recomputed": self.claims_recomputed,
            "claims_reused": self.claims_reused,
            "full_recheck_claims": self.full_checked,
            "differences": self.differences,
        }


class Store:
    def __init__(self, events: Iterable[Event], keys: Mapping[str, bytes] | None = None,
                 required: int = 1) -> None:
        self.keys = keys
        self.required_default = required
        self.required: dict[str, int] = {}
        self._events: dict[str, list[Event]] = defaultdict(list)
        self._component_of: dict[str, str] = {}
        self._event_by_id: dict[str, Event] = {}
        self._duplicates: list[str] = []
        for ev in events:
            self._ingest(ev)
        self.components: list[str] = sorted(self._events)
        self._build_influence()
        self._cache: dict[str, dict] = {}
        self._primed = False
        self._removed: set[str] = set()

    # --------------------------------------------------------------- ingestion
    def _ingest(self, ev: Event) -> None:
        if not ev.is_usable:
            return
        if ev.id in self._event_by_id:
            self._duplicates.append(ev.id)
            return
        comp = ev.org or GLOBAL_COMPONENT
        self._events[comp].append(ev)
        self._component_of[ev.id] = comp
        self._event_by_id[ev.id] = ev

    @property
    def duplicates(self) -> list[str]:
        return list(self._duplicates)

    def component_events(self, comp: str) -> list[Event]:
        return [ev for ev in self._events.get(comp, ()) if ev.id not in self._removed]

    def all_events(self, exclude: Iterable[str] = ()) -> list[Event]:
        skip = set(exclude) | self._removed
        return [
            self._event_by_id[eid]
            for eid in sorted(self._event_by_id)
            if eid not in skip
        ]

    # ---------------------------------------------------------- influence graph
    def _build_influence(self) -> None:
        self._uf = _UnionFind()
        for comp in self._events:
            self._uf.add(comp)

        claim_components: dict[str, set[str]] = defaultdict(set)
        for ev in self._event_by_id.values():
            for c in ev.attr_claims:
                claim_components[c].add(self._component_of[ev.id])
            if ev.kind == "correct" and ev.target:
                kind, value = parse_scope_ref(ev.target)
                if kind == "claim":
                    claim_components[value].add(self._component_of[ev.id])

        def link(a_id: str | None, b_id: str | None) -> None:
            if a_id and b_id and a_id in self._component_of and b_id in self._component_of:
                self._uf.union(self._component_of[a_id], self._component_of[b_id])

        # 1) a whole claim is one evidence pool: link all its carriers
        for comps in claim_components.values():
            comps_sorted = sorted(comps)
            for other in comps_sorted[1:]:
                self._uf.union(comps_sorted[0], other)

        # 2) cross-references link components
        claim_carriers: dict[str, list[str]] = defaultdict(list)
        for ev in self._event_by_id.values():
            for c in ev.attr_claims:
                claim_carriers[c].append(ev.id)
        for ev in self._event_by_id.values():
            for ref in ev.seen:
                tid = ref
                if ref.startswith(("ev:", "claim:", "cl:")):
                    kind, value = parse_scope_ref(ref)
                    if kind != "event":
                        continue
                    tid = value
                link(ev.id, tid)
            for cid in ev.corrects:
                link(ev.id, cid)
            for rid in ev.revokes:
                link(ev.id, rid)
            if ev.kind == "correct" and ev.target:
                kind, value = parse_scope_ref(ev.target)
                if kind == "event":
                    link(ev.id, value)
                else:
                    for carrier in claim_carriers.get(value, ()):
                        link(ev.id, carrier)

        self._claim_carriers = {c: sorted(v) for c, v in claim_carriers.items()}
        self._claims_by_class: dict[str, list[str]] = defaultdict(list)
        for claim, carriers in self._claim_carriers.items():
            cls = self._uf.find(self._component_of[carriers[0]])
            self._claims_by_class[cls].append(claim)
        for cls in self._claims_by_class:
            self._claims_by_class[cls].sort()
        self._class_members = self._uf.class_members()
        self.claims: list[str] = sorted(self._claim_carriers)

    # ---------------------------------------------------------------- analysis
    def _required(self, claim: str) -> int:
        return self.required.get(claim, self.required_default)

    def _analysis(self, events: Sequence[Event]) -> Analysis:
        return Analysis(events, self.keys)

    def prime(self) -> dict:
        analysis = self._analysis(self.all_events())
        self._cache = {
            c: fingerprint(analysis.assess(c, self._required(c))) for c in self.claims
        }
        self._primed = True
        return {
            "claims": len(self.claims),
            "components": len(self.components),
            "events": len(self._event_by_id),
            "summary": analysis.summary(),
        }

    def assess(self, claim: str) -> Verdict:
        if not self._primed:
            self.prime()
        fp = self._cache.get(claim)
        if fp is None:
            analysis = self._analysis(self.all_events())
            fp = fingerprint(analysis.assess(claim, self._required(claim)))
            self._cache[claim] = fp
        return self._verdict_from_fp(claim, fp)

    def _verdict_from_fp(self, claim: str, fp: Mapping[str, Any]) -> Verdict:
        cert = None
        if fp["seed"] is not None:
            cert = Certificate(
                claim=claim,
                seed=fp["seed"],
                events=tuple(fp["events"]),
                roots=tuple(fp["roots"]),
                cycle_events=tuple(fp["cycle_events"]),
                missing=tuple(MissingRef(**m) for m in fp["missing"]),
                seats=fp["seats"],
                complete=fp["status"] == "supported",
            )
        return Verdict(
            claim=claim,
            required=self._required(claim),
            status=fp["status"],
            reason=fp["reason"],
            certificate=cert,
            contradiction_chain=tuple(fp["contradiction_chain"]),
            rejection_event=fp["rejection_event"],
        )

    # -------------------------------------------------------------- retraction
    def retract(self, event_id: str) -> RetractionResult:
        if event_id not in self._component_of:
            raise KeyError(f"unknown event id: {event_id}")
        if event_id in self._removed:
            raise KeyError(f"event already retracted: {event_id}")
        if not self._primed:
            self.prime()

        comp = self._component_of[event_id]
        root = self._uf.find(comp)
        class_components = tuple(sorted(self._class_members.get(root, {comp})))
        class_claims = list(self._claims_by_class.get(root, []))

        # Events the incremental path actually reads: the class minus the point.
        class_event_ids = sorted({
            ev.id
            for c in class_components
            for ev in self._events.get(c, ())
            if ev.id != event_id and ev.id not in self._removed
        })
        class_events = [self._event_by_id[eid] for eid in class_event_ids]

        # ---- incremental: only the affected class, with the point removed
        inc_analysis = self._analysis(class_events)
        incremented = {
            c: fingerprint(inc_analysis.assess(c, self._required(c))) for c in class_claims
        }
        merged: dict[str, dict] = dict(self._cache)
        merged.update(incremented)

        # ---- complete full recheck over all remaining events
        self._removed.add(event_id)
        try:
            full = self._analysis(self.all_events())
        finally:
            self._removed.discard(event_id)
        full_fps = {
            c: fingerprint(full.assess(c, self._required(c))) for c in self.claims
        }

        differences: list[dict] = []
        for claim in self.claims:
            inc = merged.get(claim)
            ful = full_fps[claim]
            if inc != ful:
                fields = sorted(
                    k for k in set(inc or {}) | set(ful) if (inc or {}).get(k) != ful.get(k)
                )
                differences.append({
                    "claim": claim,
                    "fields": fields,
                    "incremental": {k: (inc or {}).get(k) for k in fields},
                    "full_recheck": {k: ful.get(k) for k in fields},
                })

        # This call reports on a hypothetical removal and leaves the store and
        # its cache intact, so repeated experiments stay independent.  Use
        # ``apply_retraction`` to make a removal permanent.
        return RetractionResult(
            event_id=event_id,
            removed_component=comp,
            class_components=class_components,
            components_total=len(self.components),
            events_total=len(self._event_by_id) - 1,
            events_read=len(class_events),
            claims_total=len(self.claims),
            claims_recomputed=len(class_claims),
            claims_reused=len(self.claims) - len(class_claims),
            incremental={c: merged[c] for c in sorted(merged)},
            full_checked=len(self.claims),
            differences=differences,
        )

    def apply_retraction(self, event_id: str) -> None:
        """Permanently remove an event so later operations no longer see it."""
        if event_id not in self._component_of:
            raise KeyError(f"unknown event id: {event_id}")
        self._removed.add(event_id)
        self._primed = False

    # ------------------------------------------------------------------ report
    def report(self, claims: Sequence[str] | None = None) -> dict:
        if not self._primed:
            self.prime()
        selected = list(claims) if claims is not None else list(self.claims)
        return {
            "components": len(self.components),
            "events": len(self._event_by_id),
            "claims": len(self.claims),
            "verdicts": {c: dict(self._cache[c]) for c in selected if c in self._cache},
        }
