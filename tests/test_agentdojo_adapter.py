from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from tripwire.adapters.agentdojo import ToolSemantics, ToolTaxonomy, derive_session_id, parse_run


@pytest.fixture
def taxonomy() -> ToolTaxonomy:
    return ToolTaxonomy(
        schema_version=1,
        suite="banking",
        benchmark_version="v1.2.2",
        tools={"read_file": ToolSemantics("external_input", "external")},
    )


def write_run(tmp_path: Path, messages: list[object], **overrides: object) -> Path:
    raw: dict[str, object] = {
        "suite_name": "banking",
        "pipeline_name": "test",
        "user_task_id": "user_task_1",
        "injection_task_id": "injection_task_2",
        "attack_type": "tool_knowledge",
        "messages": messages,
        "error": None,
        "security": True,
    }
    raw.update(overrides)
    path = tmp_path / "run.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def test_agentdojo_old_content_format(tmp_path: Path, taxonomy: ToolTaxonomy) -> None:
    path = write_run(
        tmp_path,
        [
            {"role": "user", "content": "read it"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [{"function": "read_file", "args": {"file_path": "x"}, "id": "c1"}],
            },
            {
                "role": "tool",
                "content": "value",
                "tool_call_id": "c1",
                "tool_call": {"function": "read_file", "args": {"file_path": "x"}, "id": "c1"},
                "error": None,
            },
        ],
    )
    run = parse_run(path, taxonomy)
    assert [event.kind for event in run.events] == ["user_input", "tool_call", "tool_result"]
    assert run.events[-1].source_trust == "external"
    assert run.events[-1].outcome == "success"


def test_agentdojo_current_content_format(tmp_path: Path, taxonomy: ToolTaxonomy) -> None:
    path = write_run(
        tmp_path, [{"role": "user", "content": [{"type": "text", "content": "hello"}]}]
    )
    run = parse_run(path, taxonomy)
    assert run.events[0].result == [{"type": "text", "content": "hello"}]


def test_security_is_renamed_attack_succeeded(tmp_path: Path, taxonomy: ToolTaxonomy) -> None:
    run = parse_run(write_run(tmp_path, [], security=False), taxonomy)
    assert run.label.attack_succeeded is False
    assert "security" not in asdict(run.label)


def test_session_id_is_stable() -> None:
    values = dict(
        benchmark_version="v1.2.2",
        suite_name="banking",
        pipeline_name="model",
        user_task_id="user_task_1",
        injection_task_id="injection_task_2",
        attack_type="tool_knowledge",
    )
    assert derive_session_id(**values) == derive_session_id(**dict(reversed(list(values.items()))))


def test_unknown_tool_role_is_explicit(tmp_path: Path, taxonomy: ToolTaxonomy) -> None:
    path = write_run(
        tmp_path,
        [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [{"function": "new_tool", "args": {}, "id": "c1"}],
            }
        ],
    )
    run = parse_run(path, taxonomy)
    assert run.events[0].tool_role == "unknown"
