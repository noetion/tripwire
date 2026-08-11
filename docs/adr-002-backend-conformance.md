# ADR-002: Local-engine backend conformance contract

## Status

Accepted on 2026-08-11.

## Context

The measured `TW-001` result uses historic AgentDojo events without per-event timestamps. It
establishes ordering behaviour, but it cannot establish elapsed-time behaviour. A future provider
query also needs an exact reference result before its status can move from rendered or executed to
conformant.

## Decision

The local engine is the reference implementation. The fixed `sequence-v1` suite supplies 37
synthetic, normalised events across 12 sessions and commits the exact local result for two rules:

- the unchanged, measured `TW-001` rule for ordering parity;
- a test-only 300-second rule for timestamp-window parity.

The test-only rule is not a published detector and carries no effectiveness or performance claim.
It exists outside `rules/` so that `TW-001` remains the only measured rule.

Conformance is exact. A provider implementation must reproduce each rule identifier and hash,
session identifier, matched event ordinal and matched tool name. The suite also fixes these
semantics:

- events are partitioned by session and ordered by non-negative `seq` values;
- sequence order is strict, while ordinal values may contain gaps;
- a window includes its exact boundary;
- missing timestamps fail a bounded match;
- candidate search may skip an expired earlier event to find a later valid sequence;
- events from different sessions cannot complete one sequence.

Rules and suite inputs reject unknown fields. This prevents a misspelled field from silently
broadening a rendered query.

No provider interface or placeholder backend is added now. The first real provider consumer will
define its mapping and rendering contract. Backend status remains per rule: `unsupported`,
`rendered`, `executed` or `conformant`. Only exact parity on this fixed suite permits `conformant`.

## Consequences

`uv run tripwire verify` now checks both the frozen AgentDojo measurement and the provider-neutral
conformance result without credentials. Provider-specific rendering, ingestion, execution,
alerting, latency and cost evidence remain later work.
