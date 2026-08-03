from __future__ import annotations

import re
from dataclasses import replace
from typing import cast

from tripwire.core.events import AgentEvent, JsonValue

_LEXEME = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._:/+\\-]*")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ACCOUNT = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{8,30}$")
_PHONE = re.compile(r"^\+?\d[\d -]{7,}$")
_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|[./~]|[^\s]+\.[A-Za-z0-9]{1,8}$)")
_SENSITIVE_NUMBER_KEYS = {"id", "transaction_id", "account_id", "phone", "phone_number"}


class TraceSanitiser:
    """Deterministically replaces every free-text lexeme within one trace."""

    def __init__(self) -> None:
        self._tokens: dict[tuple[str, str], str] = {}
        self._counts: dict[str, int] = {}

    def sanitise_events(self, events: tuple[AgentEvent, ...]) -> tuple[AgentEvent, ...]:
        return tuple(self.sanitise_event(event) for event in events)

    def sanitise_event(self, event: AgentEvent) -> AgentEvent:
        arguments = None
        if event.arguments is not None:
            arguments = cast(dict[str, JsonValue], self.sanitise_value(event.arguments))
        call_id = self._token("CALL", event.tool_call_id) if event.tool_call_id else None
        return replace(
            event,
            tool_call_id=call_id,
            arguments=arguments,
            result=self.sanitise_value(event.result),
        )

    def sanitise_value(self, value: JsonValue, *, key: str | None = None) -> JsonValue:
        if isinstance(value, str):
            return _LEXEME.sub(
                lambda match: self._token(self._category(match.group()), match.group()), value
            )
        if isinstance(value, list):
            return [self.sanitise_value(item, key=key) for item in value]
        if isinstance(value, dict):
            return {name: self.sanitise_value(item, key=name) for name, item in value.items()}
        if (
            key in _SENSITIVE_NUMBER_KEYS
            and isinstance(value, int | float)
            and not isinstance(value, bool)
        ):
            return self._token("NUMBER", str(value))
        return value

    def _category(self, raw: str) -> str:
        if _EMAIL.match(raw):
            return "EMAIL"
        if _ACCOUNT.match(raw):
            return "ACCOUNT"
        if _PHONE.match(raw):
            return "PHONE"
        if _PATH.match(raw):
            return "PATH"
        return "VALUE"

    def _token(self, category: str, raw: str) -> str:
        key = (category, raw)
        existing = self._tokens.get(key)
        if existing is not None:
            return existing
        number = self._counts.get(category, 0) + 1
        self._counts[category] = number
        token = f"{category}_{number:03d}"
        self._tokens[key] = token
        return token
