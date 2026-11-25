"""Synthetic-only custody events, canonical encoding and signing.

This is an offline forensic *demonstrator*: it only parses caller-supplied
synthetic records and never touches a live system.

Signatures are HMAC-SHA256 values bound to the canonical event contents.  The
per-signer key is derived locally from the signer name (or taken from an
explicit registry).  That is a deterministic fixture for synthetic data, not a
production key-management design.

Event kinds
-----------
``base``
    An unsigned evidence record held by an organisation.  It establishes a
    claim but provides no custody seat.

``buffer``
    A signed custody witness.  ``roots`` are direct custody roots (each one a
    seat), ``seen`` names other buffer events used as proxies, and ``revokes``
    names events this witness invalidates.

``correct``
    A signed correction.  ``target`` is a claim or event scope, ``claim`` is the
    replacement claim, ``excludes`` names claims this correction explicitly
    rejects, and ``corrects`` names witness events it makes stale for the
    current view.

Canonical encoding sorts every set-like field and uses sorted-key compact JSON
so that sealing and restoring are byte deterministic.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

DEV_KEY_PREFIX = b"cfx-dev-key\x00"
SIG_PREFIX = "hmac-sha256:"
CLAIM_SCOPE_PREFIX = "claim:"
CLAIM_HASH_PREFIX = "cl:"
EVENT_SCOPE_PREFIX = "ev:"

ALLOWED_KINDS = frozenset({"base", "buffer", "correct"})

_KNOWN_FIELDS = frozenset({
    "id", "kind", "seq", "at", "org", "claim", "attrs", "scope",
    "signer", "signature", "roots", "seen", "revokes",
    "target", "excludes", "corrects",
})


class EventError(ValueError):
    """Raised when a record cannot be parsed into the synthetic model."""


def claim_hash(text: str) -> str:
    """Stable claim identifier used for claim-addressed scopes."""
    return hashlib.sha256(b"cfx-claim\x00" + text.encode("utf-8")).hexdigest()


def scope_key_for_event(event_id: str) -> str:
    return EVENT_SCOPE_PREFIX + event_id


def scope_key_for_claim(text: str) -> str:
    return CLAIM_HASH_PREFIX + claim_hash(text)


def parse_scope_ref(ref: str) -> tuple[str, str]:
    """Return ('event', id), ('claim', text) or ('claim_hash', hex)."""
    if not isinstance(ref, str) or not ref:
        raise EventError(f"invalid scope reference: {ref!r}")
    if ref.startswith(CLAIM_SCOPE_PREFIX):
        text = ref[len(CLAIM_SCOPE_PREFIX):]
        if not text:
            raise EventError("empty claim scope reference")
        return ("claim", text)
    if ref.startswith(CLAIM_HASH_PREFIX):
        digest = ref[len(CLAIM_HASH_PREFIX):]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise EventError(f"invalid claim hash reference: {ref!r}")
        return ("claim_hash", digest)
    if ref.startswith(EVENT_SCOPE_PREFIX):
        eid = ref[len(EVENT_SCOPE_PREFIX):]
        if not eid:
            raise EventError("empty event scope reference")
        return ("event", eid)
    return ("event", ref)


def claim_from_scope_ref(ref: str) -> str:
    """Return the claim text addressed by a claim-typed scope reference."""
    kind, value = parse_scope_ref(ref)
    if kind == "claim":
        return value
    if kind == "claim_hash":
        raise EventError("claim hash references are not resolvable to text")
    raise EventError(f"not a claim scope reference: {ref!r}")


def _str_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise EventError(f"{field_name} must be a list of strings")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise EventError(f"{field_name} entries must be non-empty strings")
        out.append(item)
    return out


def _int(value: Any, field_name: str) -> int:
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int):
        raise EventError(f"{field_name} must be an integer")
    if value < 0:
        raise EventError(f"{field_name} must be non-negative")
    return value


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


@dataclass(frozen=True)
class Event:
    id: str
    kind: str
    seq: int
    at: int
    claim: str | None
    attrs: tuple[str, ...]
    org: str | None
    scope_refs: tuple[str, ...]
    signer: str | None
    roots: tuple[str, ...]
    seen: tuple[str, ...]
    revokes: tuple[str, ...]
    target: str | None
    excludes: tuple[str, ...]
    corrects: tuple[str, ...]
    signature: str | None
    signature_ok: bool
    signing_bytes: bytes
    canonical_dict: Mapping[str, Any]
    structure_error: str | None = None

    @property
    def attr_claims(self) -> tuple[str, ...]:
        """Claims directly asserted by this event."""
        claims: list[str] = []
        if self.claim:
            claims.append(self.claim)
        claims.extend(self.attrs)
        return tuple(_dedupe(claims))

    @property
    def is_usable(self) -> bool:
        return self.structure_error is None

    @property
    def is_valid_signed(self) -> bool:
        return self.is_usable and self.signature_ok

    @property
    def stable_key(self) -> tuple[int, str]:
        """Stable numbering order: sequence number, then event id."""
        return (self.seq, self.id)

    def canonical_state_bytes(self) -> bytes:
        """Full semantic state including the signature; deterministic."""
        data = dict(self.canonical_dict)
        data["signature"] = self.signature
        return _json_bytes(data)


def canonical_fields(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Normalise the semantic fields of an event (signature included if given)."""
    if not isinstance(raw, Mapping):
        raise EventError("event must be an object")
    unknown = sorted(set(raw) - _KNOWN_FIELDS)
    if unknown:
        raise EventError(f"unknown fields: {', '.join(unknown)}")
    eid = raw.get("id")
    if not isinstance(eid, str) or not eid:
        raise EventError("id must be a non-empty string")
    if eid.startswith((CLAIM_SCOPE_PREFIX, EVENT_SCOPE_PREFIX, CLAIM_HASH_PREFIX)):
        raise EventError("event id uses a reserved scope prefix")
    kind = raw.get("kind")
    if kind not in ALLOWED_KINDS:
        raise EventError(f"unknown event kind: {kind!r}")
    seq = _int(raw.get("seq"), "seq")
    at = _int(raw.get("at"), "at")
    claim = raw.get("claim")
    if claim is not None and (not isinstance(claim, str) or not claim):
        raise EventError("claim must be a non-empty string when present")
    attrs = sorted(set(_str_list(raw.get("attrs"), "attrs")))

    out: dict[str, Any] = {"id": eid, "kind": kind, "seq": seq, "at": at}
    if claim is not None:
        out["claim"] = claim
    if attrs:
        out["attrs"] = attrs

    if "org" in raw:
        org = raw.get("org")
        if not isinstance(org, str) or not org:
            raise EventError("org must be a non-empty string")
        out["org"] = org

    if kind == "base":
        _reject_present(raw, "base artifacts", (
            "signer", "signature", "roots", "seen", "revokes",
            "target", "excludes", "corrects",
        ))
        if claim is None:
            raise EventError("base artifacts require a claim")
        if "org" not in out:
            raise EventError("base artifacts require the holding org")
        refs = sorted(set(_str_list(raw.get("scope"), "scope")))
        for ref in refs:
            parse_scope_ref(ref)
        if refs:
            out["scope"] = refs
        return out

    if kind == "buffer":
        _reject_present(raw, "buffers", ("scope", "target", "excludes", "corrects"))
        signer = raw.get("signer")
        if not isinstance(signer, str) or not signer:
            raise EventError("buffers require a signer")
        if claim is None:
            raise EventError("buffers require a claim")
        roots = sorted(set(_str_list(raw.get("roots"), "roots")))
        if not roots:
            raise EventError("buffers require at least one custody root")
        seen = sorted(set(_str_list(raw.get("seen"), "seen")))
        for ref in seen:
            if ref.startswith((CLAIM_SCOPE_PREFIX, CLAIM_HASH_PREFIX)):
                raise EventError("seen references must name events, not claims")
        revokes = sorted(set(_str_list(raw.get("revokes"), "revokes")))
        out.update({
            "roots": roots,
            "seen": seen,
            "signer": signer,
            "signature": _signature_value(raw),
        })
        if revokes:
            out["revokes"] = revokes
        return out

    # correction
    _reject_present(raw, "corrections", ("scope", "roots", "seen", "revokes"))
    signer = raw.get("signer")
    if not isinstance(signer, str) or not signer:
        raise EventError("corrections require a signer")
    if claim is None:
        raise EventError("corrections require a replacement claim")
    target = raw.get("target")
    if not isinstance(target, str) or not target:
        raise EventError("corrections require a target scope reference")
    if not target.startswith((CLAIM_SCOPE_PREFIX, CLAIM_HASH_PREFIX, EVENT_SCOPE_PREFIX)):
        raise EventError("correction targets must use ev:, claim: or cl:")
    parse_scope_ref(target)
    out.update({
        "signer": signer,
        "target": target,
        "excludes": sorted(set(_str_list(raw.get("excludes"), "excludes"))),
        "corrects": sorted(set(_str_list(raw.get("corrects"), "corrects"))),
        "signature": _signature_value(raw),
    })
    return out


def _reject_present(raw: Mapping[str, Any], what: str, fields: Iterable[str]) -> None:
    present = [f for f in fields if f in raw]
    if present:
        raise EventError(f"{what} cannot carry fields: {', '.join(sorted(present))}")


def _signature_value(raw: Mapping[str, Any]) -> str | None:
    signature = raw.get("signature")
    if signature is not None:
        if not isinstance(signature, str) or not signature.startswith(SIG_PREFIX):
            raise EventError("signature must use hmac-sha256:hex format")
    return signature


def signing_payload(fields: Mapping[str, Any]) -> bytes:
    payload = _json_bytes({k: v for k, v in fields.items() if k != "signature"})
    return b"CFX-EVENT-V1\x00" + payload


def signer_key(signer: str, keys: Mapping[str, bytes] | None = None) -> bytes:
    if keys is not None and signer in keys:
        return keys[signer]
    return hashlib.sha256(DEV_KEY_PREFIX + signer.encode("utf-8")).digest()


def sign_event(raw: Mapping[str, Any], keys: Mapping[str, bytes] | None = None) -> str:
    """Return the signature string for a signed-kind event."""
    clean = {k: v for k, v in raw.items() if k != "signature"}
    fields = canonical_fields(clean)
    signer = fields.get("signer")
    if not signer:
        raise EventError("only signed events can be signed")
    digest = hmac.new(
        signer_key(signer, keys), signing_payload(fields), hashlib.sha256
    ).hexdigest()
    return SIG_PREFIX + digest


def with_signature(raw: Mapping[str, Any], keys: Mapping[str, bytes] | None = None) -> dict[str, Any]:
    out = dict(raw)
    out["signature"] = sign_event(raw, keys)
    return out


def parse_event(raw: Mapping[str, Any], keys: Mapping[str, bytes] | None = None) -> Event:
    fields = canonical_fields(raw)
    signature = fields.get("signature")
    semantic = {k: v for k, v in fields.items() if k != "signature"}
    sig_ok = False
    if signature is not None:
        provided = signature[len(SIG_PREFIX):]
        expected = hmac.new(
            signer_key(fields["signer"], keys), signing_payload(semantic), hashlib.sha256
        ).hexdigest()
        sig_ok = hmac.compare_digest(provided, expected)
    elif fields["kind"] in ("buffer", "correct"):
        raise EventError("signed event kinds require a signature")

    return Event(
        id=fields["id"],
        kind=fields["kind"],
        seq=fields["seq"],
        at=fields["at"],
        claim=fields.get("claim"),
        attrs=tuple(fields.get("attrs", ())),
        org=fields.get("org"),
        scope_refs=tuple(fields.get("scope", ())),
        signer=fields.get("signer"),
        roots=tuple(fields.get("roots", ())),
        seen=tuple(fields.get("seen", ())),
        revokes=tuple(fields.get("revokes", ())),
        target=fields.get("target"),
        excludes=tuple(fields.get("excludes", ())),
        corrects=tuple(fields.get("corrects", ())),
        signature=signature,
        signature_ok=sig_ok,
        signing_bytes=signing_payload(semantic),
        canonical_dict=semantic,
    )


def event_with_error(raw: Any, error: str) -> Event:
    """Represent a structurally broken record so it can be reported and sealed."""
    eid = raw.get("id") if isinstance(raw, Mapping) else None
    if not isinstance(eid, str) or not eid:
        digest = hashlib.sha256(_json_bytes(raw)).hexdigest()[:16]
        eid = f"<invalid:{digest}>"
    org = raw.get("org") if isinstance(raw, Mapping) else None
    return Event(
        id=eid,
        kind=str(raw.get("kind", "<invalid>")) if isinstance(raw, Mapping) else "<invalid>",
        seq=0,
        at=0,
        claim=None,
        attrs=(),
        org=org if isinstance(org, str) else None,
        scope_refs=(),
        signer=None,
        roots=(),
        seen=(),
        revokes=(),
        target=None,
        excludes=(),
        corrects=(),
        signature=None,
        signature_ok=False,
        signing_bytes=b"",
        canonical_dict={},
        structure_error=error,
    )


def sealed_record(ev: Event) -> dict[str, Any]:
    """Deterministic record used by the arrival ledger."""
    if ev.structure_error is not None:
        return {"error": ev.structure_error, "id": ev.id, "kind": ev.kind}
    data = dict(ev.canonical_dict)
    data["signature"] = ev.signature
    return data
