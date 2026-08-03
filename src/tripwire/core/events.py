from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, TypeAlias

JsonValue: TypeAlias = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
EventKind: TypeAlias = Literal["user_input", "agent_output", "tool_call", "tool_result"]
ToolRole: TypeAlias = Literal[
    "external_input", "sensitive_read", "external_write", "state_change", "other", "unknown"
]
SourceTrust: TypeAlias = Literal["external", "internal", "unknown"]
Outcome: TypeAlias = Literal["success", "failure", "refused", "unknown"]


@dataclass(frozen=True)
class AgentEvent:
    session_id: str
    seq: int
    observed_at: datetime | None
    kind: EventKind
    tool_name: str | None
    tool_role: ToolRole | None
    source_trust: SourceTrust | None
    tool_call_id: str | None
    arguments: dict[str, JsonValue] | None
    result: JsonValue | str | None
    outcome: Outcome | None


@dataclass(frozen=True)
class RunLabel:
    attack_present: bool
    attack_succeeded: bool | None
    source: Literal["agentdojo"] = "agentdojo"


@dataclass(frozen=True)
class RunMetadata:
    source_path: str
    source_entry: str
    benchmark_version: str | None
    agentdojo_package_version: str | None
    suite_name: str
    pipeline_name: str
    user_task_id: str
    injection_task_id: str | None
    attack_type: str | None


@dataclass(frozen=True)
class NormalisedRun:
    events: tuple[AgentEvent, ...]
    label: RunLabel
    metadata: RunMetadata
