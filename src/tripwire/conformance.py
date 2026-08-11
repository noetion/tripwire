from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

from tripwire import __version__
from tripwire.adapters.agentdojo import canonical_json
from tripwire.core.engine import evaluate
from tripwire.core.events import AgentEvent
from tripwire.core.rules import load_rule
from tripwire.corpus import deserialise_event

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EVENT_FIELDS = {
    "session_id",
    "seq",
    "observed_at",
    "kind",
    "tool_name",
    "tool_role",
    "source_trust",
    "tool_call_id",
    "arguments",
    "result",
    "outcome",
}
_EVENT_KINDS = {"user_input", "agent_output", "tool_call", "tool_result"}
_TOOL_ROLES = {
    "external_input",
    "sensitive_read",
    "external_write",
    "state_change",
    "other",
    "unknown",
}
_SOURCE_TRUST = {"external", "internal", "unknown"}
_OUTCOMES = {"success", "failure", "refused", "unknown"}
_RULE_PURPOSES = {"measured_rule", "test_only_window_semantics"}


class ConformanceError(RuntimeError):
    pass


def evaluate_conformance(root: Path, suite: Path) -> dict[str, Any]:
    from tripwire.evaluation import run_rule_tests

    root = root.resolve()
    suite_root = _resolve_path(root, suite, label="suite")
    manifest_path = suite_root / "manifest.json"
    manifest = _load_object(manifest_path)
    _require_exact_keys(
        manifest,
        {
            "schema_version",
            "suite_id",
            "events_file",
            "events_sha256",
            "result_file",
            "rules",
        },
        manifest_path,
        "manifest",
    )
    if manifest["schema_version"] != 1:
        raise ConformanceError(f"{manifest_path}: unsupported schema_version")
    suite_id = _non_empty_string(manifest, "suite_id", manifest_path)
    expected_events_sha256 = _sha256(manifest, "events_sha256", manifest_path)
    events_path = _resolve_path(
        root, Path(_non_empty_string(manifest, "events_file", manifest_path)), label="events"
    )
    try:
        events_bytes = events_path.read_bytes()
    except OSError as exc:
        raise ConformanceError(f"{events_path}: cannot load event corpus: {exc}") from exc
    actual_events_sha256 = hashlib.sha256(events_bytes).hexdigest()
    if actual_events_sha256 != expected_events_sha256:
        raise ConformanceError(f"{events_path}: event corpus hash mismatch")
    sessions, event_count = _load_sessions(events_path, events_bytes)

    rules_raw = manifest["rules"]
    if not isinstance(rules_raw, list) or not rules_raw:
        raise ConformanceError(f"{manifest_path}: rules must be a non-empty array")
    rule_results: list[dict[str, Any]] = []
    seen_rule_ids: set[str] = set()
    for index, entry in enumerate(rules_raw):
        if not isinstance(entry, dict):
            raise ConformanceError(f"{manifest_path}: rule {index} must be an object")
        _require_exact_keys(entry, {"path", "purpose"}, manifest_path, f"rule {index}")
        rule_path = _resolve_path(
            root,
            Path(_non_empty_string(entry, "path", manifest_path)),
            label=f"rule {index}",
        )
        purpose = _non_empty_string(entry, "purpose", manifest_path)
        if purpose not in _RULE_PURPOSES:
            raise ConformanceError(f"{manifest_path}: rule {index} has invalid purpose")
        rule = load_rule(rule_path)
        if rule.rule_id in seen_rule_ids:
            raise ConformanceError(f"{manifest_path}: duplicate rule id {rule.rule_id}")
        seen_rule_ids.add(rule.rule_id)

        positive_fixtures, negative_fixtures = run_rule_tests(rule, root=root)

        detections: list[dict[str, Any]] = []
        for session_id, events in sorted(sessions.items()):
            for match in evaluate(rule, events):
                detections.append(
                    {
                        "matched_event_ordinals": list(match.matched_event_ordinals),
                        "matched_tool_names": list(match.matched_tool_names),
                        "session_id": session_id,
                    }
                )
        rule_results.append(
            {
                "detections": detections,
                "fixtures": {
                    "true_negatives": negative_fixtures,
                    "true_positives": positive_fixtures,
                },
                "purpose": purpose,
                "rule_id": rule.rule_id,
                "rule_sha256": rule.sha256,
            }
        )

    return {
        "engine_version": __version__,
        "event_count": event_count,
        "events_sha256": actual_events_sha256,
        "result_id": suite_id,
        "rules": sorted(rule_results, key=lambda value: cast(str, value["rule_id"])),
        "schema_version": 1,
        "session_count": len(sessions),
    }


def write_conformance_result(result: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verify_conformance(root: Path, suite: Path) -> str:
    root = root.resolve()
    suite_root = _resolve_path(root, suite, label="suite")
    manifest_path = suite_root / "manifest.json"
    manifest = _load_object(manifest_path)
    result_path = _resolve_path(
        root,
        Path(_non_empty_string(manifest, "result_file", manifest_path)),
        label="result",
    )
    generated = evaluate_conformance(root, suite_root)
    committed = _load_object(result_path)
    if canonical_json(generated) != canonical_json(committed):
        raise ConformanceError(f"{result_path}: committed conformance result does not reproduce")
    detections = sum(len(cast(list[Any], rule["detections"])) for rule in generated["rules"])
    return (
        f"{generated['result_id']} verified: rules={len(generated['rules'])} "
        f"sessions={generated['session_count']} detections={detections}"
    )


def conformance_result_path(root: Path, suite: Path) -> Path:
    root = root.resolve()
    suite_root = _resolve_path(root, suite, label="suite")
    manifest_path = suite_root / "manifest.json"
    manifest = _load_object(manifest_path)
    return _resolve_path(
        root,
        Path(_non_empty_string(manifest, "result_file", manifest_path)),
        label="result",
    )


def _load_sessions(path: Path, payload: bytes) -> tuple[dict[str, tuple[AgentEvent, ...]], int]:
    grouped: dict[str, list[AgentEvent]] = {}
    seen_ordinals: set[tuple[str, int]] = set()
    event_count = 0
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise ConformanceError(f"{path}: events must be UTF-8") from exc
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ConformanceError(f"{path}:{line_number}: invalid JSON") from exc
        event = _parse_event(raw, path, line_number)
        identity = (event.session_id, event.seq)
        if identity in seen_ordinals:
            raise ConformanceError(
                f"{path}:{line_number}: duplicate session ordinal {event.session_id}/{event.seq}"
            )
        seen_ordinals.add(identity)
        grouped.setdefault(event.session_id, []).append(event)
        event_count += 1
    if not grouped:
        raise ConformanceError(f"{path}: event corpus is empty")
    sessions = {
        session_id: tuple(sorted(events, key=lambda event: event.seq))
        for session_id, events in grouped.items()
    }
    return sessions, event_count


def _parse_event(raw: Any, path: Path, line_number: int) -> AgentEvent:
    if not isinstance(raw, dict):
        raise ConformanceError(f"{path}:{line_number}: event must be an object")
    _require_exact_keys(raw, _EVENT_FIELDS, path, f"line {line_number}")
    if not isinstance(raw["kind"], str) or raw["kind"] not in _EVENT_KINDS:
        raise ConformanceError(f"{path}:{line_number}: invalid event kind")
    if raw["tool_role"] is not None and (
        not isinstance(raw["tool_role"], str) or raw["tool_role"] not in _TOOL_ROLES
    ):
        raise ConformanceError(f"{path}:{line_number}: invalid tool role")
    if raw["source_trust"] is not None and (
        not isinstance(raw["source_trust"], str) or raw["source_trust"] not in _SOURCE_TRUST
    ):
        raise ConformanceError(f"{path}:{line_number}: invalid source trust")
    if raw["outcome"] is not None and (
        not isinstance(raw["outcome"], str) or raw["outcome"] not in _OUTCOMES
    ):
        raise ConformanceError(f"{path}:{line_number}: invalid outcome")
    if not isinstance(raw["session_id"], str) or not raw["session_id"]:
        raise ConformanceError(f"{path}:{line_number}: session_id must be non-empty")
    if not isinstance(raw["seq"], int) or isinstance(raw["seq"], bool) or raw["seq"] < 0:
        raise ConformanceError(f"{path}:{line_number}: seq must be a non-negative integer")
    for key in ("tool_name", "tool_call_id"):
        if raw[key] is not None and not isinstance(raw[key], str):
            raise ConformanceError(f"{path}:{line_number}: {key} must be a string or null")
    if raw["arguments"] is not None and not isinstance(raw["arguments"], dict):
        raise ConformanceError(f"{path}:{line_number}: arguments must be an object or null")
    try:
        event = deserialise_event(raw, path)
    except (TypeError, ValueError) as exc:
        raise ConformanceError(f"{path}:{line_number}: invalid event: {exc}") from exc
    if event.observed_at is not None and event.observed_at.utcoffset() is None:
        raise ConformanceError(f"{path}:{line_number}: observed_at must include a timezone")
    return event


def _load_object(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConformanceError(f"{path}: cannot load JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConformanceError(f"{path}: root must be an object")
    return raw


def _resolve_path(root: Path, path: Path, *, label: str) -> Path:
    candidate = path.resolve() if path.is_absolute() else (root / path).resolve()
    if not candidate.is_relative_to(root):
        raise ConformanceError(f"{label} path escapes repository root: {path}")
    return candidate


def _require_exact_keys(raw: dict[str, Any], expected: set[str], path: Path, label: str) -> None:
    missing = sorted(expected - set(raw))
    unknown = sorted(set(raw) - expected)
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unknown:
            details.append(f"unknown {', '.join(unknown)}")
        raise ConformanceError(f"{path}: {label} fields invalid: {'; '.join(details)}")


def _non_empty_string(raw: dict[str, Any], key: str, path: Path) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ConformanceError(f"{path}: {key} must be a non-empty string")
    return value


def _sha256(raw: dict[str, Any], key: str, path: Path) -> str:
    value = _non_empty_string(raw, key, path)
    if not _SHA256.fullmatch(value):
        raise ConformanceError(f"{path}: {key} must be a lowercase SHA-256")
    return value
