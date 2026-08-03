from __future__ import annotations

from pathlib import Path

from tripwire.core.engine import evaluate
from tripwire.core.rules import load_rule
from tripwire.corpus import load_split_runs

ROOT = Path(__file__).resolve().parents[1]


def test_m2_audit_covers_every_holdout_error() -> None:
    rule = load_rule(ROOT / "rules" / "TW-001.yaml")
    runs = load_split_runs(ROOT / "corpora" / "agentdojo-banking-v1", "holdout")
    false_positives: list[tuple[str, str]] = []
    false_negatives: list[tuple[str, str]] = []
    for run in runs:
        matched = bool(evaluate(rule, run.events))
        positive = run.label.attack_present and run.label.attack_succeeded is True
        session_id = run.events[0].session_id
        identity = (session_id, run.metadata.source_entry)
        if matched and not positive:
            false_positives.append(identity)
        elif positive and not matched:
            false_negatives.append(identity)

    assert len(false_positives) == 1
    assert len(false_negatives) == 11
    audit = (ROOT / "docs" / "evidence-audit.md").read_text(encoding="utf-8")
    for session_id, source_entry in [*false_positives, *false_negatives]:
        assert session_id in audit
        assert source_entry in audit
