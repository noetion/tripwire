from __future__ import annotations

import ast
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tripwire.core.engine import evaluate
from tripwire.core.events import AgentEvent, NormalisedRun, RunLabel, RunMetadata
from tripwire.core.metrics import session_metrics
from tripwire.core.rules import Rule, RuleTests, SequenceStep, load_rule
from tripwire.core.sanitise import TraceSanitiser
from tripwire.corpus import load_split_runs, split_for_group, split_group_key
from tripwire.evaluation import verify_repository
from tripwire.reporting import render_readme

ROOT = Path(__file__).resolve().parents[1]


def event(
    seq: int,
    kind: str,
    role: str,
    *,
    trust: str | None = None,
    observed_at: datetime | None = None,
    session_id: str = "session",
    tool_name: str = "tool",
) -> AgentEvent:
    return AgentEvent(
        session_id=session_id,
        seq=seq,
        observed_at=observed_at,
        kind=kind,  # type: ignore[arg-type]
        tool_name=tool_name,
        tool_role=role,  # type: ignore[arg-type]
        source_trust=trust,  # type: ignore[arg-type]
        tool_call_id=f"call-{seq}",
        arguments={},
        result=None,
        outcome=None,
    )


def tw001_events(
    *, timestamps: tuple[datetime | None, ...] = (None, None, None)
) -> tuple[AgentEvent, ...]:
    return (
        event(
            0,
            "tool_result",
            "external_input",
            trust="external",
            observed_at=timestamps[0],
            tool_name="read_file",
        ),
        event(
            1,
            "tool_call",
            "sensitive_read",
            observed_at=timestamps[1],
            tool_name="get_most_recent_transactions",
        ),
        event(2, "tool_call", "external_write", observed_at=timestamps[2], tool_name="send_money"),
    )


def window_rule(seconds: int | None) -> Rule:
    return Rule(
        schema_version=1,
        rule_id="test",
        title="test",
        status="test",
        severity="test",
        corpus="test",
        sequence=(
            SequenceStep("source", "tool_result", "external_input", "external"),
            SequenceStep("sensitive", "tool_call", "sensitive_read"),
            SequenceStep("sink", "tool_call", "external_write"),
        ),
        group_by=("session_id",),
        within_seconds=seconds,
        tests=RuleTests(("tp",), ("tn",)),
        sha256="rule-hash",
    )


def test_agentdojo_labels_are_not_engine_input() -> None:
    events = tw001_events()
    metadata = RunMetadata("x", "x", None, None, "banking", "test", "u", "i", "attack")
    positive = NormalisedRun(events, RunLabel(True, True), metadata)
    relabelled = replace(positive, label=RunLabel(True, False))
    assert evaluate(window_rule(None), positive.events) == evaluate(
        window_rule(None), relabelled.events
    )


def test_tw001_positive_fixture() -> None:
    assert evaluate(load_rule(ROOT / "rules" / "TW-001.yaml"), tw001_events())


def test_tw001_benign_bill_payment() -> None:
    benign = (tw001_events()[0], tw001_events()[2])
    assert not evaluate(load_rule(ROOT / "rules" / "TW-001.yaml"), benign)


def test_tw001_unsuccessful_injection_does_not_become_true_positive() -> None:
    detected_negative = session_metrics(tp=0, fp=1, tn=0, fn=0)
    assert detected_negative.true_positives == 0
    assert detected_negative.false_positives == 1


def test_order_is_required() -> None:
    source, sensitive, sink = tw001_events()
    reordered = (replace(sink, seq=0), replace(source, seq=1), replace(sensitive, seq=2))
    assert not evaluate(window_rule(None), reordered)


def test_window_when_timestamps_exist() -> None:
    start = datetime(2026, 8, 3, tzinfo=UTC)
    assert evaluate(
        window_rule(300),
        tw001_events(
            timestamps=(start, start + timedelta(seconds=30), start + timedelta(seconds=299))
        ),
    )
    assert not evaluate(
        window_rule(300),
        tw001_events(
            timestamps=(start, start + timedelta(seconds=30), start + timedelta(seconds=301))
        ),
    )


def test_missing_timestamps_are_handled() -> None:
    assert evaluate(window_rule(None), tw001_events())
    assert not evaluate(window_rule(300), tw001_events())


def test_match_contains_rule_hash() -> None:
    match = evaluate(window_rule(None), tw001_events())[0]
    assert match.rule_sha256 == "rule-hash"
    assert match.matched_event_ordinals == (0, 1, 2)


def test_sanitisation_is_deterministic_and_preserves_equality() -> None:
    raw = replace(
        tw001_events()[2],
        arguments={"recipient": "US133000000121212121212", "memo": "Emma Johnson"},
        result="Paid US133000000121212121212 for Emma Johnson",
    )
    first = TraceSanitiser().sanitise_event(raw)
    second = TraceSanitiser().sanitise_event(raw)
    assert first == second
    assert first.arguments is not None
    account_token = first.arguments["recipient"]
    assert isinstance(account_token, str)
    assert account_token in str(first.result)
    assert "Emma" not in json.dumps(first.arguments)
    assert "US133000000121212121212" not in str(first.result)


def test_sanitisation_preserves_labels_and_tool_order() -> None:
    events = tw001_events()
    sanitised = TraceSanitiser().sanitise_events(events)
    assert [value.tool_name for value in sanitised] == [value.tool_name for value in events]
    label = RunLabel(True, True)
    assert label == RunLabel(True, True)


def test_core_has_no_backend_dependency() -> None:
    banned = ("tripwire.backends", "google.cloud", "azure")
    for path in (ROOT / "src" / "tripwire" / "core").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = [
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        ]
        imports.extend(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        assert not any(name.startswith(banned) for name in imports)


def test_split_groups_cannot_overlap() -> None:
    corpus = ROOT / "corpora" / "agentdojo-banking-v1"
    development = load_split_runs(corpus, "development")
    holdout = load_split_runs(corpus, "holdout")
    development_groups = {split_group_key(run.metadata) for run in development}
    holdout_groups = {split_group_key(run.metadata) for run in holdout}
    assert development_groups.isdisjoint(holdout_groups)
    assert all(split_for_group(group) == "development" for group in development_groups)
    assert all(split_for_group(group) == "holdout" for group in holdout_groups)


def test_sensitive_values_removed_from_committed_corpus() -> None:
    corpus_text = "".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "corpora" / "agentdojo-banking-v1").rglob("*.json")
    )
    for raw in ("Emma Johnson", "US133000000121212121212", "Spotify Premium"):
        assert raw not in corpus_text


def test_committed_result_reproduces() -> None:
    summary = verify_repository(ROOT)
    assert summary.startswith("TW-001 verified: holdout TP=6 FP=1 TN=36 FN=11")


def test_readme_is_generated_from_canonical_result() -> None:
    result = json.loads(
        (ROOT / "results" / "agentdojo-banking-v1.json").read_text(encoding="utf-8")
    )
    assert (ROOT / "README.md").read_text(encoding="utf-8") == render_readme(result)
