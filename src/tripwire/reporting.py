# ruff: noqa: E501 -- README paragraphs and table rows are intentionally rendered as single lines.

from __future__ import annotations

from typing import Any


def render_readme(result: dict[str, Any]) -> str:
    holdout = result["holdout"]
    counts = holdout["counts"]
    recall = holdout["recall"]
    precision = holdout["precision"]
    false_positive_rate = holdout["false_positive_rate"]
    return f"""# Tripwire

Tripwire evaluates deterministic sequence rules over AI-agent tool-call traces. Its first measured rule, `TW-001`, looks for an external tool result followed by a sensitive read and then an external write in one session.

## Reproduce the committed result

```console
uv sync --frozen
uv run tripwire verify
```

No model API key or cloud credential is required. Verification checks corpus hashes, runs rule-owned fixtures, evaluates the frozen holdout, and compares the generated result with [`results/agentdojo-banking-v1.json`](results/agentdojo-banking-v1.json).

## AgentDojo banking holdout

| Measure | Result | Wilson 95% interval |
|---|---:|---:|
| Recall | {recall["numerator"]}/{recall["denominator"]} ({_percent(recall["value"])}) | {_interval(recall["wilson_95"])} |
| Precision | {precision["numerator"]}/{precision["denominator"]} ({_percent(precision["value"])}) | {_interval(precision["wilson_95"])} |
| False-positive rate | {false_positive_rate["numerator"]}/{false_positive_rate["denominator"]} ({_percent(false_positive_rate["value"])}) | {_interval(false_positive_rate["wilson_95"])} |

Confusion counts: TP {counts["true_positives"]}, FP {counts["false_positives"]}, TN {counts["true_negatives"]}, FN {counts["false_negatives"]}. The holdout contains {counts["positive"]} positive and {counts["negative"]} negative sessions.

This result classifies successful prompt-injection outcomes in the committed AgentDojo banking corpus under the documented tool taxonomy. It does not establish causation, malicious intent, prevention, general prompt-injection detection, real-time operation, or production readiness. Historic traces test order but not elapsed-time semantics. See [`LIMITATIONS.md`](LIMITATIONS.md).

## Evidence

- Rule: [`rules/TW-001.yaml`](rules/TW-001.yaml)
- Tool taxonomy: [`config/agentdojo-banking-tools.yaml`](config/agentdojo-banking-tools.yaml)
- Corpus manifest: [`corpora/agentdojo-banking-v1/manifest.json`](corpora/agentdojo-banking-v1/manifest.json)
- Ground truth: [`docs/ground-truth.md`](docs/ground-truth.md)
- Data handling: [`docs/data-handling.md`](docs/data-handling.md)

Licensed under Apache-2.0. The derived corpus retains its upstream AgentDojo attribution and MIT licence notice.
"""


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _interval(value: list[float] | None) -> str:
    if value is None:
        return "n/a"
    return f"{value[0] * 100:.1f}%–{value[1] * 100:.1f}%"
