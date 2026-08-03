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
    positions = _find_sequence(rule, events)
    if positions is None:
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


def _find_sequence(rule: Rule, events: Sequence[AgentEvent]) -> tuple[int, ...] | None:
    def search(step_index: int, start: int, positions: tuple[int, ...]) -> tuple[int, ...] | None:
        if step_index == len(rule.sequence):
            return positions
        step = rule.sequence[step_index]
        for position in _matching_positions(step, events, start):
            candidate = (*positions, position)
            if rule.within_seconds is not None and not _window_candidate(
                events, candidate, rule.within_seconds
            ):
                continue
            found = search(step_index + 1, position + 1, candidate)
            if found is not None:
                return found
        return None

    return search(0, 0, ())


def _matching_positions(
    step: SequenceStep, events: Sequence[AgentEvent], start: int
) -> tuple[int, ...]:
    matches: list[int] = []
    for position in range(start, len(events)):
        event = events[position]
        if event.kind != step.kind:
            continue
        if step.tool_role is not None and event.tool_role != step.tool_role:
            continue
        if step.source_trust is not None and event.source_trust != step.source_trust:
            continue
        matches.append(position)
    return tuple(matches)


def _window_candidate(
    events: Sequence[AgentEvent], positions: tuple[int, ...], seconds: int
) -> bool:
    timestamps: list[datetime] = []
    for position in positions:
        timestamp = events[position].observed_at
        if timestamp is None:
            return False
        timestamps.append(timestamp)
    elapsed = (timestamps[-1] - timestamps[0]).total_seconds()
    return 0 <= elapsed <= seconds
