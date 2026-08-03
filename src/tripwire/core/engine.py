from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from tripwire import __version__
from tripwire.core.events import AgentEvent
from tripwire.core.rules import Rule, SequenceStep


@dataclass(frozen=True)
class Match:
    rule_id: str
    rule_sha256: str
    session_id: str
    matched_event_ordinals: tuple[int, ...]
    matched_tool_names: tuple[str | None, ...]
    source_corpus_entry: str | None
    engine_version: str


def evaluate(rule: Rule, events: Sequence[AgentEvent]) -> tuple[Match, ...]:
    if not events:
        return ()
    session_id = events[0].session_id
    if any(event.session_id != session_id for event in events):
        raise ValueError("events from multiple sessions cannot be evaluated together")
    positions: list[int] = []
    cursor = 0
    for step in rule.sequence:
        position = _find_next(step, events, cursor)
        if position is None:
            return ()
        positions.append(position)
        cursor = position + 1
    if rule.within_seconds is not None and not _within_window(
        events, positions, rule.within_seconds
    ):
        return ()
    return (
        Match(
            rule_id=rule.rule_id,
            rule_sha256=rule.sha256,
            session_id=session_id,
            matched_event_ordinals=tuple(events[position].seq for position in positions),
            matched_tool_names=tuple(events[position].tool_name for position in positions),
            source_corpus_entry=None,
            engine_version=__version__,
        ),
    )


def _find_next(step: SequenceStep, events: Sequence[AgentEvent], start: int) -> int | None:
    for position in range(start, len(events)):
        event = events[position]
        if event.kind != step.kind:
            continue
        if step.tool_role is not None and event.tool_role != step.tool_role:
            continue
        if step.source_trust is not None and event.source_trust != step.source_trust:
            continue
        return position
    return None


def _within_window(events: Sequence[AgentEvent], positions: list[int], seconds: int) -> bool:
    timestamps: list[datetime] = []
    for position in positions:
        timestamp = events[position].observed_at
        if timestamp is None:
            return False
        timestamps.append(timestamp)
    return (timestamps[-1] - timestamps[0]).total_seconds() <= seconds
