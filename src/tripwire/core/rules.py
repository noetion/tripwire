from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml

from tripwire.adapters.agentdojo import canonical_json
from tripwire.core.events import EventKind, SourceTrust, ToolRole


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class SequenceStep:
    alias: str
    kind: EventKind
    tool_role: ToolRole | None = None
    source_trust: SourceTrust | None = None


@dataclass(frozen=True)
class RuleTests:
    true_positives: tuple[str, ...]
    true_negatives: tuple[str, ...]


@dataclass(frozen=True)
class Rule:
    schema_version: int
    rule_id: str
    title: str
    status: str
    severity: str
    corpus: str
    sequence: tuple[SequenceStep, ...]
    group_by: tuple[str, ...]
    within_seconds: int | None
    tests: RuleTests
    sha256: str


def load_rule(path: Path) -> Rule:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RuleError(f"{path}: cannot load rule: {exc}") from exc
    if not isinstance(raw, dict):
        raise RuleError(f"{path}: rule root must be an object")
    sequence_raw = raw.get("sequence")
    if not isinstance(sequence_raw, list) or len(sequence_raw) < 2:
        raise RuleError(f"{path}: sequence must contain at least two steps")
    sequence = tuple(_parse_step(path, index, value) for index, value in enumerate(sequence_raw))
    aliases = [step.alias for step in sequence]
    if len(aliases) != len(set(aliases)):
        raise RuleError(f"{path}: sequence aliases must be unique")

    match = _object(raw, "match", path)
    group_by_raw = match.get("group_by")
    order_raw = match.get("order")
    if group_by_raw != ["session_id"]:
        raise RuleError(f"{path}: V1 requires group_by: [session_id]")
    if order_raw != aliases:
        raise RuleError(f"{path}: match.order must name every sequence alias in order")
    within = match.get("within")
    if within is not None and (
        not isinstance(within, int) or isinstance(within, bool) or within <= 0
    ):
        raise RuleError(f"{path}: within must be null or a positive integer number of seconds")

    tests_raw = _object(raw, "tests", path)
    tp = _string_list(tests_raw, "true_positives", path)
    tn = _string_list(tests_raw, "true_negatives", path)
    if not tp or not tn:
        raise RuleError(f"{path}: rule must own positive and negative fixtures")
    scope = _object(raw, "scope", path)
    schema_version = _integer(raw, "schema_version", path)
    if schema_version != 1:
        raise RuleError(f"{path}: unsupported schema_version {schema_version}")
    return Rule(
        schema_version=schema_version,
        rule_id=_string(raw, "id", path),
        title=_string(raw, "title", path),
        status=_string(raw, "status", path),
        severity=_string(raw, "severity", path),
        corpus=_string(scope, "corpus", path),
        sequence=sequence,
        group_by=("session_id",),
        within_seconds=within,
        tests=RuleTests(tp, tn),
        sha256=hashlib.sha256(canonical_json(raw).encode()).hexdigest(),
    )


def _parse_step(path: Path, index: int, value: Any) -> SequenceStep:
    if not isinstance(value, dict):
        raise RuleError(f"{path}: sequence step {index} must be an object")
    valid_kinds = {"user_input", "agent_output", "tool_call", "tool_result"}
    valid_roles = {
        "external_input",
        "sensitive_read",
        "external_write",
        "state_change",
        "other",
        "unknown",
    }
    valid_trust = {"external", "internal", "unknown"}
    kind = value.get("kind")
    role = value.get("tool_role")
    trust = value.get("source_trust")
    if kind not in valid_kinds:
        raise RuleError(f"{path}: sequence step {index} has invalid kind")
    if role is not None and role not in valid_roles:
        raise RuleError(f"{path}: sequence step {index} has invalid tool_role")
    if trust is not None and trust not in valid_trust:
        raise RuleError(f"{path}: sequence step {index} has invalid source_trust")
    return SequenceStep(
        alias=_string(value, "as", path),
        kind=cast(EventKind, kind),
        tool_role=cast(ToolRole | None, role),
        source_trust=cast(SourceTrust | None, trust),
    )


def _object(raw: dict[str, Any], key: str, path: Path) -> dict[str, Any]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise RuleError(f"{path}: {key} must be an object")
    return value


def _string(raw: dict[str, Any], key: str, path: Path) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise RuleError(f"{path}: {key} must be a non-empty string")
    return value


def _integer(raw: dict[str, Any], key: str, path: Path) -> int:
    value = raw.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise RuleError(f"{path}: {key} must be an integer")
    return value


def _string_list(raw: dict[str, Any], key: str, path: Path) -> tuple[str, ...]:
    value = raw.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise RuleError(f"{path}: {key} must be an array of strings")
    return tuple(value)
