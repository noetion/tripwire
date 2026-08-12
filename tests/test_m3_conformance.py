from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, cast

import pytest

from tripwire.conformance import ConformanceError, evaluate_conformance, verify_conformance
from tripwire.core.rules import RuleError, load_rule

ROOT = Path(__file__).parents[1]
SUITE = ROOT / "conformance" / "sequence-v1"


def test_provider_neutral_conformance_result_reproduces() -> None:
    summary = verify_conformance(ROOT, SUITE)
    result = evaluate_conformance(ROOT, SUITE)

    assert summary == "sequence-v1 verified: rules=2 sessions=12 detections=14"
    assert result["event_count"] == 37
    assert result["session_count"] == 12
    assert sum(len(rule["detections"]) for rule in result["rules"]) == 14
    assert {
        rule["rule_id"]: rule["fixtures"] for rule in cast(list[dict[str, Any]], result["rules"])
    } == {
        "TW-001": {"true_negatives": 2, "true_positives": 1},
        "TW-CONFORMANCE-WINDOW": {"true_negatives": 1, "true_positives": 1},
    }


def test_conformance_covers_ordering_window_and_session_semantics() -> None:
    result = evaluate_conformance(ROOT, SUITE)
    detections = {
        rule["rule_id"]: {
            detection["session_id"]: detection["matched_event_ordinals"]
            for detection in rule["detections"]
        }
        for rule in cast(list[dict[str, Any]], result["rules"])
    }
    unbounded = detections["TW-001"]
    bounded = detections["TW-CONFORMANCE-WINDOW"]

    assert "case-03-outside-301" in unbounded
    assert "case-03-outside-301" not in bounded
    assert "case-04-missing-time" in unbounded
    assert "case-04-missing-time" not in bounded
    assert bounded["case-02-boundary-300"] == [0, 1, 2]
    assert unbounded["case-07-later-valid-source"] == [0, 2, 3]
    assert bounded["case-07-later-valid-source"] == [1, 2, 3]
    assert bounded["case-11-gapped-seq"] == [10, 20, 30]
    assert "case-05-wrong-order" not in unbounded
    assert "case-09-source-only" not in unbounded
    assert "case-10-tail-only" not in unbounded


def test_window_rule_is_test_only_and_not_a_published_detector() -> None:
    assert [path.name for path in sorted((ROOT / "rules").glob("*.yaml"))] == ["TW-001.yaml"]
    rule = load_rule(SUITE / "rules" / "TW-CONFORMANCE-WINDOW.yaml")
    assert rule.status == "test"
    assert rule.severity == "informational"
    assert rule.within_seconds == 300


def test_conformance_event_corpus_hash_is_enforced(tmp_path: Path) -> None:
    copied = tmp_path / "conformance"
    shutil.copytree(ROOT / "conformance", copied)
    events = copied / "sequence-v1" / "events.jsonl"
    events.write_text(events.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(ConformanceError, match="event corpus hash mismatch"):
        evaluate_conformance(tmp_path, copied / "sequence-v1")


def test_non_string_timestamp_fails_closed(tmp_path: Path) -> None:
    copied = tmp_path / "conformance"
    shutil.copytree(ROOT / "conformance", copied)
    suite = copied / "sequence-v1"
    events_path = suite / "events.jsonl"
    lines = events_path.read_text(encoding="utf-8").splitlines()
    first_event = json.loads(lines[0])
    first_event["observed_at"] = 0
    lines[0] = json.dumps(first_event, separators=(",", ":"))
    events = ("\n".join(lines) + "\n").encode()
    events_path.write_bytes(events)

    manifest_path = suite / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["events_sha256"] = hashlib.sha256(events).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ConformanceError, match="observed_at must be a string or null"):
        evaluate_conformance(tmp_path, suite)


def test_boolean_manifest_schema_version_fails_closed(tmp_path: Path) -> None:
    suite = tmp_path / "conformance" / "sequence-v1"
    suite.mkdir(parents=True)
    manifest = json.loads((SUITE / "manifest.json").read_text(encoding="utf-8"))
    manifest["schema_version"] = True
    (suite / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ConformanceError, match="unsupported schema_version"):
        evaluate_conformance(tmp_path, suite)


def test_unknown_rule_fields_fail_closed(tmp_path: Path) -> None:
    source = (ROOT / "rules" / "TW-001.yaml").read_text(encoding="utf-8")
    rule_path = tmp_path / "rule.yaml"
    rule_path.write_text(
        source.replace("source_trust: external", "source_trsut: external", 1),
        encoding="utf-8",
    )

    with pytest.raises(RuleError, match="contains unknown fields: source_trsut"):
        load_rule(rule_path)
