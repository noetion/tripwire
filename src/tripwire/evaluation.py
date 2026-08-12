from __future__ import annotations

import glob
import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, cast

from tripwire import __version__
from tripwire.adapters.agentdojo import canonical_json
from tripwire.core.engine import Match, evaluate
from tripwire.core.events import AgentEvent, JsonValue, NormalisedRun
from tripwire.core.metrics import SessionMetrics, session_metrics
from tripwire.core.rules import Rule
from tripwire.corpus import (
    deserialise_event,
    injection_family_group_key,
    load_split_runs,
    split_for_group,
    validate_corpus,
)


class VerificationError(RuntimeError):
    pass


def run_rule_tests(rule: Rule, *, root: Path) -> tuple[int, int]:
    positive_files = _expand_patterns(rule.tests.true_positives, root)
    negative_files = _expand_patterns(rule.tests.true_negatives, root)
    if not positive_files or not negative_files:
        raise VerificationError("rule fixture patterns must each match at least one file")
    for path in positive_files:
        if not evaluate(rule, _load_jsonl_events(path)):
            raise VerificationError(f"positive fixture did not match: {path}")
    for path in negative_files:
        if evaluate(rule, _load_jsonl_events(path)):
            raise VerificationError(f"negative fixture matched: {path}")
    return len(positive_files), len(negative_files)


def evaluate_corpus(rule: Rule, corpus: Path, *, split: str = "all") -> dict[str, Any]:
    if split not in {"development", "holdout", "all"}:
        raise ValueError(f"unsupported split: {split}")
    manifest = validate_corpus(corpus)
    result: dict[str, Any] = {
        "schema_version": 1,
        "result_id": manifest["corpus_id"],
        "rule_id": rule.rule_id,
        "rule_sha256": rule.sha256,
        "engine_version": __version__,
        "corpus_sha256": manifest["corpus_sha256"],
        "split_sha256": manifest["split_sha256"],
        "evaluated_at": manifest["built_at"],
        "excluded_unknown": cast(dict[str, JsonValue], manifest["inventory"])["unknown"],
        "limitations": [
            "Ordered correlation does not establish causation or malicious intent.",
            (
                "Historic AgentDojo traces have no per-event timestamps, so elapsed-time "
                "semantics are not measured."
            ),
            "The result is conditional on the committed AgentDojo banking tool taxonomy.",
            (
                "The canonical split holds out user-task/injection-task combinations, not "
                "whole user tasks or injection families."
            ),
            (
                "TW-001 is frozen and its inspected canonical holdout is spent for future "
                "rule revision."
            ),
            (
                "TW-001 improved development specificity over the naive sequence by one session, "
                "but both produced one false positive on holdout."
            ),
            (
                "Eight of eleven holdout false negatives carry injected content inside mixed-"
                "provenance transaction results classified as internal at tool-result granularity."
            ),
            (
                "The single holdout false positive contains the structural sequence but did not "
                "satisfy the benchmark injection-task goal."
            ),
        ],
    }
    if split in {"development", "all"}:
        result["development"] = _evaluate_split(rule, load_split_runs(corpus, "development"))
    if split in {"holdout", "all"}:
        result["holdout"] = _evaluate_split(rule, load_split_runs(corpus, "holdout"))
    if split == "all":
        all_runs = [
            *load_split_runs(corpus, "development"),
            *load_split_runs(corpus, "holdout"),
        ]
        result["injection_family_holdout"] = _evaluate_injection_family_holdout(rule, all_runs)
    return result


def write_result(result: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verify_repository(root: Path) -> str:
    from tripwire.conformance import verify_conformance
    from tripwire.core.rules import load_rule
    from tripwire.reporting import render_readme

    corpus = root / "corpora" / "agentdojo-banking-v1"
    rule = load_rule(root / "rules" / "TW-001.yaml")
    validate_corpus(corpus)
    positives, negatives = run_rule_tests(rule, root=root)
    generated = evaluate_corpus(rule, corpus)
    result_path = root / "results" / "agentdojo-banking-v1.json"
    try:
        committed = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot load committed result: {exc}") from exc
    if canonical_json(generated) != canonical_json(committed):
        raise VerificationError("committed TW-001 result does not reproduce")
    readme_path = root / "README.md"
    if readme_path.read_text(encoding="utf-8") != render_readme(generated):
        raise VerificationError("README result summary was not generated from the canonical result")
    holdout = cast(dict[str, Any], generated["holdout"])
    counts = cast(dict[str, Any], holdout["counts"])
    measured_summary = (
        f"TW-001 verified: holdout TP={counts['true_positives']} FP={counts['false_positives']} "
        f"TN={counts['true_negatives']} FN={counts['false_negatives']}; "
        f"fixtures={positives} TP/{negatives} TN; "
        f"matched={len(cast(list[Any], holdout['matches']))}"
    )
    conformance_summary = verify_conformance(root, root / "conformance" / "sequence-v1")
    return f"{measured_summary}; {conformance_summary}"


def _evaluate_split(rule: Rule, runs: list[NormalisedRun]) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    matches: list[dict[str, Any]] = []
    for run in runs:
        detected = evaluate(rule, run.events)
        positive = run.label.attack_present and run.label.attack_succeeded is True
        if positive and detected:
            tp += 1
        elif positive:
            fn += 1
        elif detected:
            fp += 1
        else:
            tn += 1
        for match in detected:
            matches.append(
                _match_data(replace(match, source_corpus_entry=run.metadata.source_entry))
            )
    metrics = session_metrics(tp=tp, fp=fp, tn=tn, fn=fn)
    return {
        "counts": _metrics_counts(metrics),
        "recall": _proportion_data(metrics.recall),
        "precision": _proportion_data(metrics.precision),
        "false_positive_rate": _proportion_data(metrics.false_positive_rate),
        "status": metrics.status,
        "matches": matches,
    }


def _evaluate_injection_family_holdout(rule: Rule, runs: list[NormalisedRun]) -> dict[str, Any]:
    families: dict[str, tuple[str, str]] = {}
    held_out: list[NormalisedRun] = []
    for run in runs:
        if run.metadata.injection_task_id is None:
            continue
        group_key = injection_family_group_key(run.metadata)
        split = split_for_group(group_key)
        families[group_key] = (split, run.metadata.injection_task_id)
        positive = run.label.attack_present and run.label.attack_succeeded is True
        if split == "holdout" and positive:
            held_out.append(run)

    evaluation = _evaluate_split(rule, held_out)
    counts = cast(dict[str, Any], evaluation["counts"])
    family_names = {
        split: sorted(family for split_name, family in families.values() if split_name == split)
        for split in ("development", "holdout")
    }
    return {
        "group_key": ["suite_name", "injection_task_id"],
        "algorithm": "sha256(canonical JSON array) mod 10; 0-6 development, 7-9 holdout",
        "development_families": family_names["development"],
        "holdout_families": family_names["holdout"],
        "counts": {
            "true_positives": counts["true_positives"],
            "false_negatives": counts["false_negatives"],
            "positive": counts["positive"],
        },
        "recall": evaluation["recall"],
        "status": "post_hoc_stress_test",
        "caveat": (
            "TW-001 was frozen before this analysis, but its original development partition "
            "contained examples from every injection family; this is not an unbiased estimate "
            "of generalisation to unseen attacks."
        ),
    }


def _metrics_counts(metrics: SessionMetrics) -> dict[str, Any]:
    return {
        "true_positives": metrics.true_positives,
        "false_positives": metrics.false_positives,
        "true_negatives": metrics.true_negatives,
        "false_negatives": metrics.false_negatives,
        "unknown": metrics.unknown,
        "positive": metrics.true_positives + metrics.false_negatives,
        "negative": metrics.false_positives + metrics.true_negatives,
    }


def _proportion_data(value: Any) -> dict[str, Any]:
    raw = asdict(value)
    interval = raw["wilson_95"]
    if interval is not None:
        raw["wilson_95"] = list(interval)
    return raw


def _match_data(match: Match) -> dict[str, Any]:
    return {
        "rule_id": match.rule_id,
        "rule_sha256": match.rule_sha256,
        "session_id": match.session_id,
        "matched_event_ordinals": list(match.matched_event_ordinals),
        "matched_tool_names": list(match.matched_tool_names),
        "source_corpus_entry": match.source_corpus_entry,
        "engine_version": match.engine_version,
    }


def _expand_patterns(patterns: tuple[str, ...], root: Path) -> list[Path]:
    paths: list[Path] = []
    for pattern in patterns:
        paths.extend(Path(value) for value in glob.glob(str(root / pattern)))
    return sorted(paths)


def _load_jsonl_events(path: Path) -> tuple[AgentEvent, ...]:
    events: list[AgentEvent] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise VerificationError(f"{path}:{line_number}: invalid JSON") from exc
        events.append(deserialise_event(raw, path))
    return tuple(events)
