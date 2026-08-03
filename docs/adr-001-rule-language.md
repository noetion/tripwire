# ADR-001: A narrow Tripwire rule format

Tripwire uses a small YAML sequence format for agent event kinds, semantic tool roles, source trust, rule-owned fixtures and explicit ordering. Sigma correlation was considered, but its event vocabulary does not natively express these agent-specific fields or the required fixture contract without a translation layer that would be larger than the first rule.

This is not a general policy language. V1 accepts only ordered, session-grouped sequences with an optional elapsed-time limit. A new consumer must justify any extension.

