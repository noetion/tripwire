from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from tripwire.adapters.agentdojo import (
    AgentDojoParseError,
    ToolTaxonomy,
    canonical_json,
    parse_run,
)
from tripwire.core.events import (
    AgentEvent,
    EventKind,
    JsonValue,
    NormalisedRun,
    Outcome,
    RunLabel,
    RunMetadata,
    SourceTrust,
    ToolRole,
)
from tripwire.core.sanitise import TraceSanitiser


@dataclass(frozen=True)
class CorpusInventory:
    positive: int
    negative: int
    unknown: int
    total: int
    unknown_reasons: tuple[str, ...]


@dataclass(frozen=True)
class CorpusBuildResult:
    inventory: CorpusInventory
    development_positive: int
    development_negative: int
    holdout_positive: int
    holdout_negative: int
    corpus_sha256: str
    split_sha256: str


def inventory(
    paths: Iterable[Path], taxonomy: ToolTaxonomy, *, source_root: Path
) -> CorpusInventory:
    positive = 0
    negative = 0
    reasons: list[str] = []
    total = 0
    for path in sorted(paths):
        total += 1
        try:
            run = parse_run(path, taxonomy, source_root=source_root)
        except AgentDojoParseError as exc:
            reasons.append(str(exc))
            continue
        if run.label.attack_present and run.label.attack_succeeded is True:
            positive += 1
        else:
            negative += 1
    return CorpusInventory(positive, negative, len(reasons), total, tuple(reasons))


def build_corpus(
    paths: Iterable[Path],
    taxonomy: ToolTaxonomy,
    *,
    source_root: Path,
    output: Path,
    source_url: str,
    source_revision: str,
    built_at: str,
) -> CorpusBuildResult:
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    output.mkdir(parents=True)
    (output / "dev").mkdir()
    (output / "holdout").mkdir()

    entries: list[dict[str, Any]] = []
    groups: dict[str, str] = {}
    split_sessions: dict[str, list[str]] = {"development": [], "holdout": []}
    reasons: list[str] = []
    positive = negative = 0
    split_counts = {
        "development": {"positive": 0, "negative": 0},
        "holdout": {"positive": 0, "negative": 0},
    }
    seen_sessions: set[str] = set()

    for path in sorted(paths):
        try:
            run = parse_run(path, taxonomy, source_root=source_root)
        except AgentDojoParseError as exc:
            reasons.append(str(exc))
            continue
        if run.events and run.events[0].session_id in seen_sessions:
            raise ValueError(f"duplicate session identity: {path}")
        session_id = (
            run.events[0].session_id if run.events else _session_from_metadata(run.metadata)
        )
        seen_sessions.add(session_id)
        class_name = (
            "positive"
            if run.label.attack_present and run.label.attack_succeeded is True
            else "negative"
        )
        if class_name == "positive":
            positive += 1
        else:
            negative += 1
        group_key = split_group_key(run.metadata)
        split = split_for_group(group_key)
        previous = groups.setdefault(group_key, split)
        if previous != split:
            raise AssertionError("deterministic group split changed")
        split_counts[split][class_name] += 1
        split_sessions[split].append(session_id)

        sanitised = NormalisedRun(
            events=TraceSanitiser().sanitise_events(run.events),
            label=run.label,
            metadata=run.metadata,
        )
        relative_file = f"{'dev' if split == 'development' else 'holdout'}/{session_id}.json"
        payload = serialise_run(sanitised)
        payload_bytes = (canonical_json(payload) + "\n").encode()
        (output / relative_file).write_bytes(payload_bytes)
        entries.append(
            {
                "class": class_name,
                "file": relative_file,
                "session_id": session_id,
                "sha256": hashlib.sha256(payload_bytes).hexdigest(),
                "source_entry": run.metadata.source_entry,
                "split": split,
            }
        )

    split_data: dict[str, Any] = {
        "schema_version": 1,
        "group_key": ["suite_name", "user_task_id", "injection_task_id"],
        "algorithm": "sha256(canonical JSON array) mod 10; 0-6 development, 7-9 holdout",
        "groups": dict(sorted(groups.items())),
        "development": sorted(split_sessions["development"]),
        "holdout": sorted(split_sessions["holdout"]),
    }
    split_bytes = (canonical_json(split_data) + "\n").encode()
    (output / "split.json").write_bytes(split_bytes)
    split_sha256 = hashlib.sha256(split_bytes).hexdigest()
    entries.sort(key=lambda entry: cast(str, entry["session_id"]))
    corpus_sha256 = hashlib.sha256(canonical_json(entries).encode()).hexdigest()
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "corpus_id": output.name,
        "suite": taxonomy.suite,
        "benchmark_version": taxonomy.benchmark_version,
        "agentdojo_package_version": "0.1.35",
        "source_url": source_url,
        "source_revision": source_revision,
        "source_selection": "gpt-4o-2024-05-13/tool_knowledge plus no-injection runs",
        "built_at": built_at,
        "inventory": {
            "positive": positive,
            "negative": negative,
            "unknown": len(reasons),
            "total": positive + negative + len(reasons),
        },
        "split_counts": split_counts,
        "unknown_reasons": reasons,
        "corpus_sha256": corpus_sha256,
        "split_sha256": split_sha256,
        "entries": entries,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return CorpusBuildResult(
        inventory=CorpusInventory(
            positive, negative, len(reasons), positive + negative + len(reasons), tuple(reasons)
        ),
        development_positive=split_counts["development"]["positive"],
        development_negative=split_counts["development"]["negative"],
        holdout_positive=split_counts["holdout"]["positive"],
        holdout_negative=split_counts["holdout"]["negative"],
        corpus_sha256=corpus_sha256,
        split_sha256=split_sha256,
    )


def validate_corpus(corpus: Path) -> dict[str, Any]:
    manifest_path = corpus / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("entries"), list):
        raise ValueError(f"{manifest_path}: malformed manifest")
    entries = cast(list[dict[str, Any]], manifest["entries"])
    corpus_root = corpus.resolve()
    for entry in entries:
        relative = entry.get("file")
        expected = entry.get("sha256")
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise ValueError(f"{manifest_path}: malformed entry")
        relative_path = Path(relative)
        candidate = (corpus / relative_path).resolve()
        if relative_path.is_absolute() or not candidate.is_relative_to(corpus_root):
            raise ValueError(f"corpus entry escapes corpus root: {relative}")
        actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"corpus hash mismatch: {relative}")
    actual_corpus = hashlib.sha256(canonical_json(entries).encode()).hexdigest()
    if actual_corpus != manifest.get("corpus_sha256"):
        raise ValueError("corpus aggregate hash mismatch")
    split_bytes = (corpus / "split.json").read_bytes()
    actual_split = hashlib.sha256(split_bytes).hexdigest()
    if actual_split != manifest.get("split_sha256"):
        raise ValueError("split hash mismatch")
    return manifest


def load_split_runs(corpus: Path, split: str) -> list[NormalisedRun]:
    if split not in {"development", "holdout"}:
        raise ValueError(f"unsupported split: {split}")
    manifest = validate_corpus(corpus)
    runs: list[NormalisedRun] = []
    for entry in cast(list[dict[str, Any]], manifest["entries"]):
        if entry.get("split") != split:
            continue
        relative = entry["file"]
        if not isinstance(relative, str):
            raise ValueError("manifest file entry must be a string")
        raw = json.loads((corpus / relative).read_text(encoding="utf-8"))
        runs.append(deserialise_run(raw, corpus / relative))
    return runs


def split_group_key(metadata: RunMetadata) -> str:
    return canonical_json([metadata.suite_name, metadata.user_task_id, metadata.injection_task_id])


def injection_family_group_key(metadata: RunMetadata) -> str:
    if metadata.injection_task_id is None:
        raise ValueError("no-injection runs do not have an injection family")
    return canonical_json([metadata.suite_name, metadata.injection_task_id])


def split_for_group(group_key: str) -> str:
    bucket = int(hashlib.sha256(group_key.encode()).hexdigest(), 16) % 10
    return "development" if bucket <= 6 else "holdout"


def serialise_run(run: NormalisedRun) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "events": [serialise_event(event) for event in run.events],
        "label": asdict(run.label),
        "metadata": {
            "source_entry": run.metadata.source_entry,
            "benchmark_version": run.metadata.benchmark_version,
            "agentdojo_package_version": run.metadata.agentdojo_package_version,
            "suite_name": run.metadata.suite_name,
            "pipeline_name": run.metadata.pipeline_name,
            "user_task_id": run.metadata.user_task_id,
            "injection_task_id": run.metadata.injection_task_id,
            "attack_type": run.metadata.attack_type,
        },
    }


def serialise_event(event: AgentEvent) -> dict[str, Any]:
    return {
        "session_id": event.session_id,
        "seq": event.seq,
        "observed_at": event.observed_at.isoformat() if event.observed_at else None,
        "kind": event.kind,
        "tool_name": event.tool_name,
        "tool_role": event.tool_role,
        "source_trust": event.source_trust,
        "tool_call_id": event.tool_call_id,
        "arguments": event.arguments,
        "result": event.result,
        "outcome": event.outcome,
    }


def deserialise_run(raw: Any, path: Path) -> NormalisedRun:
    if not isinstance(raw, dict) or not isinstance(raw.get("events"), list):
        raise ValueError(f"{path}: malformed replay run")
    label_raw = raw.get("label")
    metadata_raw = raw.get("metadata")
    if not isinstance(label_raw, dict) or not isinstance(metadata_raw, dict):
        raise ValueError(f"{path}: malformed replay metadata")
    events = tuple(deserialise_event(value, path) for value in raw["events"])
    label = RunLabel(
        attack_present=_bool(label_raw, "attack_present", path),
        attack_succeeded=_optional_bool(label_raw, "attack_succeeded", path),
    )
    metadata = RunMetadata(
        source_path=str(path),
        source_entry=_str(metadata_raw, "source_entry", path),
        benchmark_version=_optional_str(metadata_raw, "benchmark_version", path),
        agentdojo_package_version=_optional_str(metadata_raw, "agentdojo_package_version", path),
        suite_name=_str(metadata_raw, "suite_name", path),
        pipeline_name=_str(metadata_raw, "pipeline_name", path),
        user_task_id=_str(metadata_raw, "user_task_id", path),
        injection_task_id=_optional_str(metadata_raw, "injection_task_id", path),
        attack_type=_optional_str(metadata_raw, "attack_type", path),
    )
    return NormalisedRun(events, label, metadata)


def deserialise_event(raw: Any, path: Path) -> AgentEvent:
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: malformed event")
    observed = raw.get("observed_at")
    return AgentEvent(
        session_id=_str(raw, "session_id", path),
        seq=_int(raw, "seq", path),
        observed_at=datetime.fromisoformat(observed) if isinstance(observed, str) else None,
        kind=cast(EventKind, raw.get("kind")),
        tool_name=_optional_str(raw, "tool_name", path),
        tool_role=cast(ToolRole | None, raw.get("tool_role")),
        source_trust=cast(SourceTrust | None, raw.get("source_trust")),
        tool_call_id=_optional_str(raw, "tool_call_id", path),
        arguments=cast(dict[str, JsonValue] | None, raw.get("arguments")),
        result=cast(JsonValue, raw.get("result")),
        outcome=cast(Outcome | None, raw.get("outcome")),
    )


def _session_from_metadata(metadata: RunMetadata) -> str:
    from tripwire.adapters.agentdojo import derive_session_id

    return derive_session_id(
        benchmark_version=metadata.benchmark_version,
        suite_name=metadata.suite_name,
        pipeline_name=metadata.pipeline_name,
        user_task_id=metadata.user_task_id,
        injection_task_id=metadata.injection_task_id,
        attack_type=metadata.attack_type,
    )


def _str(raw: dict[str, Any], key: str, path: Path) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{path}: {key} must be a string")
    return value


def _optional_str(raw: dict[str, Any], key: str, path: Path) -> str | None:
    value = raw.get(key)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{path}: {key} must be a string or null")
    return value


def _int(raw: dict[str, Any], key: str, path: Path) -> int:
    value = raw.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{path}: {key} must be an integer")
    return value


def _bool(raw: dict[str, Any], key: str, path: Path) -> bool:
    value = raw.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{path}: {key} must be a boolean")
    return value


def _optional_bool(raw: dict[str, Any], key: str, path: Path) -> bool | None:
    value = raw.get(key)
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"{path}: {key} must be a boolean or null")
    return value
