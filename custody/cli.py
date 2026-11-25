"""Offline forensic custody checker (synthetic data only).

Commands
--------
``assess``      verdicts for a JSON array of synthetic events
``timeline``    replay the built-in scenario, sealing before a late correction
``exhaustive``  brute-force cross-check of the engine on all tiny graphs
``bench``       partition, retraction-locality and full-recheck benchmark

All input is synthetic and local; nothing touches the network or a live system.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .analysis import Analysis
from .events import EventError, event_with_error, parse_event
from .ledger import Ledger
from .store import Store
from .synthetic import fixed_timeline, generate_corpus


def _load_events(path: Path, keys=None) -> list:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("events", raw.get("arrivals", []))
    events = []
    for item in raw:
        try:
            events.append(parse_event(item, keys))
        except EventError as exc:
            events.append(event_with_error(item, str(exc)))
    return events


def _emit(obj: Any) -> None:
    json.dump(obj, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")


# --------------------------------------------------------------------------- #
# assess
# --------------------------------------------------------------------------- #

def cmd_assess(args: argparse.Namespace) -> int:
    events = _load_events(Path(args.events))
    required_map = json.loads(args.required) if args.required else {}
    default_required = args.min_roots
    analysis = Analysis(events)
    claims = args.claims or sorted({
        c for ev in analysis.events.values() for c in ev.attr_claims
    })
    verdicts = {
        c: analysis.assess(c, required_map.get(c, default_required)).as_dict()
        for c in claims
    }
    result: dict[str, Any] = {
        "summary": analysis.summary(),
        "verdicts": verdicts,
    }
    if args.joint:
        pairs = [c.strip() for c in args.joint.split(",") if c.strip()]
        result["joint"] = analysis.joint_certificates(
            pairs, required_map.get(pairs[0], default_required) if pairs else default_required
        )
    _emit(result)
    return 0


# --------------------------------------------------------------------------- #
# timeline
# --------------------------------------------------------------------------- #

def cmd_timeline(args: argparse.Namespace) -> int:
    scenario = fixed_timeline()
    required = scenario["required"]
    cross_claim = scenario["late_claim"]
    seal_before = scenario["seal_before_late_id"]

    ledger = Ledger()
    seal = None
    for raw in scenario["arrivals"]:
        if raw["id"] == seal_before and seal is None:
            seal = ledger.seal()
        ledger.add(raw)
    if seal is None:
        seal = ledger.seal()
    current = ledger.current_analysis()

    restored = ledger.restore(seal.bytes)
    hist = Analysis(restored.events)
    historical_verdict = hist.assess(cross_claim, required[cross_claim]).as_dict()
    current_verdict = current.assess(cross_claim, required[cross_claim]).as_dict()

    result = {
        "arrival_count": len(ledger),
        "head": ledger.head,
        "late_arrivals": ledger.late_arrivals(),
        "seal": {
            "count": seal.count,
            "head": seal.head,
            "bytes_sha256": __import__("hashlib").sha256(seal.bytes).hexdigest(),
            "restored": restored.summary(),
            "byte_exact": ledger.reseal_prefix(seal.count) == seal.bytes,
        },
        "late_claim": cross_claim,
        "current": current_verdict,
        "historical": historical_verdict,
        "other_verdicts": {
            c: current.assess(c, required[c]).as_dict()
            for c in scenario["claims"] if c != cross_claim
        },
    }
    _emit(result)
    return 0


# --------------------------------------------------------------------------- #
# exhaustive
# --------------------------------------------------------------------------- #

def cmd_exhaustive(args: argparse.Namespace) -> int:
    from tests.exhaustive import run_exhaustive
    report = run_exhaustive(max_events=args.max_events, max_witnesses=args.max_witnesses)
    _emit(report)
    return 0 if report["ok"] else 1


# --------------------------------------------------------------------------- #
# bench
# --------------------------------------------------------------------------- #

def cmd_bench(args: argparse.Namespace) -> int:
    arrivals = generate_corpus(total_events=args.events, orgs=args.orgs)
    events = []
    for raw in arrivals:
        try:
            events.append(parse_event(raw))
        except EventError as exc:
            events.append(event_with_error(raw, str(exc)))
    store = Store(events, required=args.min_roots)
    primed = store.prime()

    # choose a retraction target with a non-trivial local class if possible
    comp_sizes: dict[str, int] = {}
    for comp in store.components:
        comp_sizes[comp] = len(store.component_events(comp))
    target_event = None
    for comp in sorted(comp_sizes, key=lambda c: (-comp_sizes[c], c)):
        for ev in store.component_events(comp):
            if ev.kind == "buffer":
                target_event = ev.id
                break
        if target_event:
            break
    if target_event is None:
        _emit({"error": "no buffer to retract"})
        return 1

    result = store.retract(target_event)
    report = {
        "primed": primed,
        "component_sizes": {c: comp_sizes[c] for c in sorted(comp_sizes)[:args.show_components]},
        "retraction": result.as_dict(),
        "differences_count": len(result.differences),
    }
    _emit(report)
    return 0


# --------------------------------------------------------------------------- #
# argparse
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="custody-check",
        description="Offline synthetic custody checker (no network, no live systems).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_assess = sub.add_parser("assess", help="assess verdicts for a JSON event file")
    p_assess.add_argument("events", help="path to a JSON array of synthetic events")
    p_assess.add_argument("--claims", nargs="*", help="claims to assess (default: all)")
    p_assess.add_argument("--required", help="JSON map claim -> required roots")
    p_assess.add_argument("--min-roots", type=int, default=2,
                          help="default required independent roots (default 2)")
    p_assess.add_argument("--joint", help="comma-separated claims for joint independence")
    p_assess.set_defaults(func=cmd_assess)

    p_timeline = sub.add_parser("timeline", help="replay the late-correction seal scenario")
    p_timeline.set_defaults(func=cmd_timeline)

    p_exh = sub.add_parser("exhaustive", help="brute-force cross-check on tiny graphs")
    p_exh.add_argument("--max-events", type=int, default=4)
    p_exh.add_argument("--max-witnesses", type=int, default=3)
    p_exh.set_defaults(func=cmd_exhaustive)

    p_bench = sub.add_parser("bench", help="partitioned retraction benchmark")
    p_bench.add_argument("--events", type=int, default=60_000)
    p_bench.add_argument("--orgs", type=int, default=8)
    p_bench.add_argument("--min-roots", type=int, default=2)
    p_bench.add_argument("--show-components", type=int, default=8)
    p_bench.set_defaults(func=cmd_bench)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
