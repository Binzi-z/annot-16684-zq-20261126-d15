"""Arrival ledger with byte-exact historical seals.

The ledger ingests synthetic records in *arrival* order.  Every arrival is
appended to a SHA-256 chain over its canonical bytes, so the seal of a prefix of
arrivals is a cryptographic commitment to those exact bytes.

A *late correction* arrives after events whose logical ``at`` time precedes it.
Two things must hold at once:

* the **current** analysis includes the late correction and reports the current
  minimal certificate;
* every **historical seal** can still be restored byte for byte, unaffected by
  the correction that logically predates it.

This module deliberately keeps the seal artifact self-describing: restoring a
seal reproduces its original bytes exactly (re-sealing the restored prefix is a
fixed point), and restoring verifies the stored chain head.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .analysis import Analysis
from .events import Event, EventError, event_with_error, parse_event, sealed_record, _json_bytes

GENESIS = b"CFX-LEDGER-GENESIS-V1"
SEAL_FORMAT = "cfx-seal-v1"


@dataclass
class Arrival:
    index: int
    event: Event
    record: dict[str, Any]
    record_bytes: bytes
    chain: bytes


@dataclass
class Seal:
    count: int
    head: str
    bytes: bytes
    records: tuple[dict[str, Any], ...]


@dataclass
class RestoredSeal:
    count: int
    head: str
    events: tuple[Event, ...]
    records: tuple[dict[str, Any], ...]
    bytes: bytes
    chain_verified: bool

    def summary(self) -> dict:
        return {
            "count": self.count,
            "head": self.head,
            "chain_verified": self.chain_verified,
            "bytes_sha256": hashlib.sha256(self.bytes).hexdigest(),
            "ids": [ev.id for ev in self.events],
        }


class Ledger:
    def __init__(self, keys: Mapping[str, bytes] | None = None) -> None:
        self.keys = keys
        self.arrivals: list[Arrival] = []
        self._chain = hashlib.sha256(GENESIS).digest()
        self._idem: dict[str, bytes] = {}

    # --------------------------------------------------------------- ingestion
    def add(self, raw: Mapping[str, Any]) -> Event:
        try:
            ev = parse_event(raw, self.keys)
        except EventError as exc:
            ev = event_with_error(raw, str(exc))
        record = sealed_record(ev)
        record_bytes = _json_bytes(record)
        if ev.id in self._idem:
            if self._idem[ev.id] != record_bytes:
                # Conflicting re-arrival of the same id: keep first, chain both.
                pass
        else:
            self._idem[ev.id] = record_bytes
        self._chain = hashlib.sha256(self._chain + b"\x1e" + record_bytes).digest()
        self.arrivals.append(Arrival(
            index=len(self.arrivals),
            event=ev,
            record=record,
            record_bytes=record_bytes,
            chain=self._chain,
        ))
        return ev

    def add_all(self, raws: Iterable[Mapping[str, Any]]) -> list[Event]:
        return [self.add(raw) for raw in raws]

    def __len__(self) -> int:
        return len(self.arrivals)

    @property
    def head(self) -> str:
        return self._chain.hex()

    # ------------------------------------------------------------------ seals
    def _seal_artifact(self, records: Sequence[Mapping[str, Any]], head: bytes) -> bytes:
        artifact = {
            "format": SEAL_FORMAT,
            "count": len(records),
            "head": head.hex(),
            "records": list(records),
        }
        return _json_bytes(artifact)

    def seal(self, count: int | None = None) -> Seal:
        if count is None:
            count = len(self.arrivals)
        if count < 0 or count > len(self.arrivals):
            raise ValueError("seal count out of range")
        records = tuple(a.record for a in self.arrivals[:count])
        head = hashlib.sha256(GENESIS).digest()
        for a in self.arrivals[:count]:
            head = hashlib.sha256(head + b"\x1e" + a.record_bytes).digest()
        blob = self._seal_artifact(records, head)
        return Seal(count=count, head=head.hex(), bytes=blob, records=records)

    def restore(self, sealed_bytes: bytes) -> RestoredSeal:
        """Restore a seal exactly, verifying its chain commitment."""
        try:
            artifact = json.loads(sealed_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"not a seal artifact: {exc}") from exc
        if artifact.get("format") != SEAL_FORMAT:
            raise ValueError("unknown seal format")
        records = artifact.get("records")
        if not isinstance(records, list):
            raise ValueError("seal has no records")
        declared_head = artifact.get("head")
        count = artifact.get("count")
        if not isinstance(count, int) or count != len(records):
            raise ValueError("seal count does not match record count")

        head = hashlib.sha256(GENESIS).digest()
        events: list[Event] = []
        for rec in records:
            head = hashlib.sha256(head + b"\x1e" + _json_bytes(rec)).digest()
            if isinstance(rec, Mapping) and rec.get("error") is not None:
                events.append(event_with_error(rec, str(rec.get("error"))))
                continue
            try:
                events.append(parse_event(rec, self.keys))
            except EventError as exc:
                events.append(event_with_error(rec, str(exc)))
        verified = head.hex() == declared_head
        # Re-sealing the restored records must reproduce the exact original bytes.
        rebuilt = self._seal_artifact(records, head)
        if rebuilt != sealed_bytes:
            verified = False
        return RestoredSeal(
            count=count,
            head=declared_head,
            events=tuple(events),
            records=tuple(records),
            bytes=sealed_bytes,
            chain_verified=verified,
        )

    def reseal_prefix(self, count: int) -> bytes:
        """Recompute a prefix seal from the live ledger (byte-exact check)."""
        return self.seal(count).bytes

    # ---------------------------------------------------------------- views
    def analysis(self, count: int | None = None, skip: Iterable[str] = ()) -> Analysis:
        if count is None:
            count = len(self.arrivals)
        skip_set = set(skip)
        events = [a.event for a in self.arrivals[:count] if a.event.id not in skip_set]
        return Analysis(events, self.keys)

    def current_analysis(self) -> Analysis:
        return self.analysis()

    def late_arrivals(self) -> list[dict]:
        """Report arrivals whose logical time precedes something already seen."""
        latest_at = -1
        latest_seq = -1
        out: list[dict] = []
        for a in self.arrivals:
            ev = a.event
            if not ev.is_usable:
                continue
            if ev.at < latest_at or ev.seq < latest_seq:
                out.append({
                    "arrival_index": a.index,
                    "id": ev.id,
                    "kind": ev.kind,
                    "at": ev.at,
                    "seq": ev.seq,
                    "arrival_at": latest_at,
                    "late": True,
                })
            latest_at = max(latest_at, ev.at)
            latest_seq = max(latest_seq, ev.seq)
        return out

    def assessments(self, claims: Sequence[str], required: int = 1) -> dict:
        analysis = self.current_analysis()
        out: dict[str, Any] = {}
        for claim in claims:
            out[claim] = analysis.assess(claim, required).as_dict()
        return {
            "head": self.head,
            "count": len(self.arrivals),
            "summary": analysis.summary(),
            "late_arrivals": self.late_arrivals(),
            "verdicts": out,
        }
