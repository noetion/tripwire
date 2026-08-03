from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Never, cast

import yaml

from tripwire.core.events import (
    AgentEvent,
    JsonValue,
    NormalisedRun,
    Outcome,
    RunLabel,
    RunMetadata,
    SourceTrust,
    ToolRole,
)


class AgentDojoParseError(ValueError):
    """A trace cannot be interpreted without guessing."""

    def __init__(self, path: Path, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"{path}: {reason}")


@dataclass(frozen=True)
class ToolSemantics:
    role: ToolRole
    result_trust: SourceTrust


@dataclass(frozen=True)
class ToolTaxonomy:
    schema_version: int
    suite: str
    benchmark_version: str
    tools: dict[str, ToolSemantics]

    def semantics_for(self, tool_name: str) -> ToolSemantics:
        return self.tools.get(tool_name, ToolSemantics("unknown", "unknown"))


def load_taxonomy(path: Path) -> ToolTaxonomy:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AgentDojoParseError(path, f"cannot load taxonomy: {exc}") from exc
    if not isinstance(raw, dict):
        raise AgentDojoParseError(path, "taxonomy root must be an object")
    tools_raw = raw.get("tools")
    if not isinstance(tools_raw, dict):
        raise AgentDojoParseError(path, "taxonomy tools must be an object")
    valid_roles = {
        "external_input",
        "sensitive_read",
        "external_write",
        "state_change",
        "other",
        "unknown",
    }
    valid_trust = {"external", "internal", "unknown"}
    tools: dict[str, ToolSemantics] = {}
    for name, value in tools_raw.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            raise AgentDojoParseError(path, "each taxonomy entry must map a tool name to an object")
        role = value.get("role")
        trust = value.get("result_trust")
        if role not in valid_roles or trust not in valid_trust:
            raise AgentDojoParseError(path, f"invalid taxonomy entry for {name}")
        tools[name] = ToolSemantics(cast(ToolRole, role), cast(SourceTrust, trust))
    return ToolTaxonomy(
        schema_version=_required_int(raw, "schema_version", path),
        suite=_required_str(raw, "suite", path),
        benchmark_version=_required_str(raw, "benchmark_version", path),
        tools=tools,
    )


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def derive_session_id(
    *,
    benchmark_version: str | None,
    suite_name: str,
    pipeline_name: str,
    user_task_id: str,
    injection_task_id: str | None,
    attack_type: str | None,
) -> str:
    identity = {
        "attack_type": attack_type,
        "benchmark_version": benchmark_version,
        "injection_task_id": injection_task_id,
        "pipeline_name": pipeline_name,
        "suite_name": suite_name,
        "user_task_id": user_task_id,
    }
    return hashlib.sha256(canonical_json(identity).encode()).hexdigest()


def parse_run(
    path: Path, taxonomy: ToolTaxonomy, *, source_root: Path | None = None
) -> NormalisedRun:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AgentDojoParseError(path, f"invalid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise AgentDojoParseError(path, "run root must be an object")

    suite_name = _required_str(raw, "suite_name", path)
    if suite_name != taxonomy.suite:
        raise AgentDojoParseError(
            path, f"suite {suite_name!r} does not match taxonomy {taxonomy.suite!r}"
        )
    pipeline_name = _required_str(raw, "pipeline_name", path)
    user_task_id = _required_str(raw, "user_task_id", path)
    injection_task_id = _optional_str(raw, "injection_task_id", path, required=True)
    attack_type = _optional_str(raw, "attack_type", path, required=True)
    benchmark_version = _optional_str(raw, "benchmark_version", path)
    package_version = _optional_str(raw, "agentdojo_package_version", path)

    label = _parse_label(raw, path, injection_task_id)
    session_id = derive_session_id(
        benchmark_version=benchmark_version,
        suite_name=suite_name,
        pipeline_name=pipeline_name,
        user_task_id=user_task_id,
        injection_task_id=injection_task_id,
        attack_type=attack_type,
    )
    messages = raw.get("messages")
    if not isinstance(messages, list):
        raise AgentDojoParseError(path, "messages must be an array")
    if raw.get("error") not in (None, ""):
        raise AgentDojoParseError(path, "run has a top-level execution error")

    events: list[AgentEvent] = []
    calls: dict[str, tuple[str, dict[str, JsonValue]]] = {}
    for message_index, message in enumerate(messages):
        if not isinstance(message, dict):
            raise AgentDojoParseError(path, f"message {message_index} must be an object")
        role = message.get("role")
        if role == "system":
            _normalise_content(message.get("content"), path, message_index)
            continue
        if role == "user":
            content = _normalise_content(message.get("content"), path, message_index)
            events.append(_plain_event(session_id, len(events), "user_input", content))
            continue
        if role == "assistant":
            _parse_assistant(message, path, message_index, taxonomy, session_id, events, calls)
            continue
        if role == "tool":
            _parse_tool_result(message, path, message_index, taxonomy, session_id, events, calls)
            continue
        raise AgentDojoParseError(path, f"message {message_index} has unsupported role {role!r}")

    source_entry = path.name
    if source_root is not None:
        try:
            source_entry = path.resolve().relative_to(source_root.resolve()).as_posix()
        except ValueError as exc:
            raise AgentDojoParseError(path, "source path is outside source root") from exc
    metadata = RunMetadata(
        source_path=str(path),
        source_entry=source_entry,
        benchmark_version=benchmark_version,
        agentdojo_package_version=package_version,
        suite_name=suite_name,
        pipeline_name=pipeline_name,
        user_task_id=user_task_id,
        injection_task_id=injection_task_id,
        attack_type=attack_type,
    )
    return NormalisedRun(tuple(events), label, metadata)


def _parse_label(raw: dict[str, Any], path: Path, injection_task_id: str | None) -> RunLabel:
    if injection_task_id is None:
        return RunLabel(attack_present=False, attack_succeeded=None)
    value = raw.get("security")
    if not isinstance(value, bool):
        raise AgentDojoParseError(path, "injected run requires a boolean benchmark outcome")
    return RunLabel(attack_present=True, attack_succeeded=value)


def _parse_assistant(
    message: dict[str, Any],
    path: Path,
    message_index: int,
    taxonomy: ToolTaxonomy,
    session_id: str,
    events: list[AgentEvent],
    calls: dict[str, tuple[str, dict[str, JsonValue]]],
) -> None:
    content = _normalise_content(message.get("content"), path, message_index)
    tool_calls = message.get("tool_calls")
    if content not in (None, "", []):
        events.append(_plain_event(session_id, len(events), "agent_output", content))
    if tool_calls is None:
        return
    if not isinstance(tool_calls, list):
        raise AgentDojoParseError(path, f"message {message_index} tool_calls must be an array")
    for call_index, call in enumerate(tool_calls):
        if not isinstance(call, dict):
            raise AgentDojoParseError(
                path, f"message {message_index} tool call {call_index} must be an object"
            )
        name = call.get("function")
        if not isinstance(name, str) or not name:
            raise AgentDojoParseError(
                path, f"message {message_index} tool call {call_index} lacks function"
            )
        arguments = _json_object(
            call.get("args", {}), path, f"message {message_index} tool call {call_index} args"
        )
        call_id = call.get("id")
        if call_id is not None and not isinstance(call_id, str):
            raise AgentDojoParseError(
                path, f"message {message_index} tool call {call_index} has invalid id"
            )
        if call_id:
            calls[call_id] = (name, arguments)
        semantics = taxonomy.semantics_for(name)
        events.append(
            AgentEvent(
                session_id=session_id,
                seq=len(events),
                observed_at=None,
                kind="tool_call",
                tool_name=name,
                tool_role=semantics.role,
                source_trust=None,
                tool_call_id=call_id,
                arguments=arguments,
                result=None,
                outcome=None,
            )
        )


def _parse_tool_result(
    message: dict[str, Any],
    path: Path,
    message_index: int,
    taxonomy: ToolTaxonomy,
    session_id: str,
    events: list[AgentEvent],
    calls: dict[str, tuple[str, dict[str, JsonValue]]],
) -> None:
    result = _normalise_content(message.get("content"), path, message_index)
    call_id = message.get("tool_call_id")
    if call_id is not None and not isinstance(call_id, str):
        raise AgentDojoParseError(path, f"message {message_index} has invalid tool_call_id")
    embedded = message.get("tool_call")
    name: str | None = None
    arguments: dict[str, JsonValue] | None = None
    if isinstance(embedded, dict):
        embedded_name = embedded.get("function")
        if isinstance(embedded_name, str):
            name = embedded_name
        arguments = _json_object(
            embedded.get("args", {}), path, f"message {message_index} tool_call args"
        )
    elif embedded is not None:
        raise AgentDojoParseError(path, f"message {message_index} tool_call must be an object")
    if name is None and call_id in calls:
        name, arguments = calls[call_id]
    if name is None:
        raise AgentDojoParseError(
            path, f"message {message_index} tool result cannot be linked to a tool call"
        )
    semantics = taxonomy.semantics_for(name)
    events.append(
        AgentEvent(
            session_id=session_id,
            seq=len(events),
            observed_at=None,
            kind="tool_result",
            tool_name=name,
            tool_role=semantics.role,
            source_trust=semantics.result_trust,
            tool_call_id=call_id,
            arguments=arguments,
            result=result,
            outcome=_tool_outcome(message),
        )
    )


def _tool_outcome(message: dict[str, Any]) -> Outcome:
    if "error" not in message:
        return "unknown"
    error = message["error"]
    return "failure" if error not in (None, "", [], {}) else "success"


def _plain_event(session_id: str, seq: int, kind: str, result: JsonValue) -> AgentEvent:
    if kind not in {"user_input", "agent_output"}:
        raise AssertionError(kind)
    return AgentEvent(
        session_id=session_id,
        seq=seq,
        observed_at=None,
        kind=cast(Any, kind),
        tool_name=None,
        tool_role=None,
        source_trust=None,
        tool_call_id=None,
        arguments=None,
        result=result,
        outcome=None,
    )


def _normalise_content(value: Any, path: Path, message_index: int) -> JsonValue:
    if value is None or isinstance(value, str | bool | int | float):
        return cast(JsonValue, value)
    if isinstance(value, list):
        parts: list[JsonValue] = []
        for block_index, block in enumerate(value):
            if not isinstance(block, dict):
                raise AgentDojoParseError(
                    path, f"message {message_index} content block {block_index} is invalid"
                )
            block_type = block.get("type")
            block_content = block.get("content", block.get("text"))
            if block_type != "text" or not isinstance(block_content, str):
                raise AgentDojoParseError(
                    path,
                    f"message {message_index} content block {block_index} is not supported text",
                )
            parts.append({"type": "text", "content": block_content})
        return parts
    raise AgentDojoParseError(path, f"message {message_index} content has unsupported type")


def _json_object(value: Any, path: Path, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or not _is_json(value):
        raise AgentDojoParseError(path, f"{label} must be a JSON object")
    return cast(dict[str, JsonValue], value)


def _is_json(value: Any) -> bool:
    if value is None or isinstance(value, bool | int | float | str):
        return True
    if isinstance(value, list):
        return all(_is_json(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _is_json(item) for key, item in value.items())
    return False


def _required_str(raw: dict[str, Any], key: str, path: Path) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        _fail(path, f"{key} must be a non-empty string")
    return value


def _required_int(raw: dict[str, Any], key: str, path: Path) -> int:
    value = raw.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(path, f"{key} must be an integer")
    return value


def _optional_str(
    raw: dict[str, Any], key: str, path: Path, *, required: bool = False
) -> str | None:
    if required and key not in raw:
        _fail(path, f"{key} is required")
    value = raw.get(key)
    if value is not None and not isinstance(value, str):
        _fail(path, f"{key} must be a string or null")
    return value


def _fail(path: Path, reason: str) -> Never:
    raise AgentDojoParseError(path, reason)
