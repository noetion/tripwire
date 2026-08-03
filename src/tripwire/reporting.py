# ruff: noqa: E501 -- README paragraphs and table rows are intentionally rendered as single lines.

from __future__ import annotations

from typing import Any


def render_readme(result: dict[str, Any]) -> str:
    holdout = result["holdout"]
    counts = holdout["counts"]
    recall = holdout["recall"]
    precision = holdout["precision"]
    false_positive_rate = holdout["false_positive_rate"]
    family_holdout = result["injection_family_holdout"]
    family_recall = family_holdout["recall"]
    family_names = ", ".join(f"`{name}`" for name in family_holdout["holdout_families"])
    return f"""# Tripwire

Tripwire evaluates deterministic sequence rules over AI-agent tool-call traces. Its first measured rule, `TW-001`, looks for an external tool result followed by a sensitive read and then an external write in one session.

The main finding is a provenance failure, not a new attack signature. Eight of the eleven canonical holdout false negatives received attacker-controlled strings inside transaction records returned by banking tools classified as internal. Tool-result-level provenance is too coarse when a trusted tool returns mixed-trust records; item-level provenance is required to distinguish the injected content without distrusting the entire result.

## Reproduce the committed result

```console
uv sync --frozen
uv run tripwire verify
```

No model API key or cloud credential is required. Verification checks corpus hashes, runs rule-owned fixtures, evaluates the frozen holdout, and compares the generated result with [`results/agentdojo-banking-v1.json`](results/agentdojo-banking-v1.json).

## Canonical combination holdout

| Measure | Result | Wilson 95% interval |
|---|---:|---:|
| Recall | {recall["numerator"]}/{recall["denominator"]} ({_percent(recall["value"])}) | {_interval(recall["wilson_95"])} |
| Precision | {precision["numerator"]}/{precision["denominator"]} ({_percent(precision["value"])}) | {_interval(precision["wilson_95"])} |
| False-positive rate | {false_positive_rate["numerator"]}/{false_positive_rate["denominator"]} ({_percent(false_positive_rate["value"])}) | {_interval(false_positive_rate["wilson_95"])} |

Confusion counts: TP {counts["true_positives"]}, FP {counts["false_positives"]}, TN {counts["true_negatives"]}, FN {counts["false_negatives"]}. The holdout contains {counts["positive"]} positive and {counts["negative"]} negative sessions.

The canonical split hashes `(suite, user task, injection task)` tuples. It measures generalisation to unseen combinations, not unseen user tasks or attack families: some user-task identities and every injection-task identity appear on both sides.

## Injection-family stress test

A secondary deterministic split hashes `(suite, injection task)` so complete injection families stay together. It holds out {family_names} and recalls {family_recall["numerator"]}/{family_recall["denominator"]} ({_percent(family_recall["value"])}, Wilson 95%: {_interval(family_recall["wilson_95"])}). This is higher than the canonical 35.3%, not lower. It is a post-hoc stress test rather than an unbiased unseen-attack estimate because the original development partition exposed TW-001's development process to examples from every injection family.

## Specificity ceiling

Three development negatives matched TW-001. Two were benign `none/none.json` sessions whose legitimate workflow was `read_file` → `get_scheduled_transactions` → `update_scheduled_transaction`; the third was an injected run whose benchmark attack failed. The holdout false positive was also a failed injected run, and all four false positives share that scheduled-update sequence. The rule's sequence is therefore a normal banking workflow as well as an attack shape, so structure alone cannot establish malicious intent.

This result classifies successful prompt-injection outcomes in the committed AgentDojo banking corpus under the documented tool taxonomy. It does not establish causation, malicious intent, prevention, general prompt-injection detection, or real-time operation. Historic traces test order but not elapsed-time semantics. See [`LIMITATIONS.md`](LIMITATIONS.md).

## Evidence

- Rule: [`rules/TW-001.yaml`](rules/TW-001.yaml)
- Tool taxonomy: [`config/agentdojo-banking-tools.yaml`](config/agentdojo-banking-tools.yaml)
- Corpus manifest: [`corpora/agentdojo-banking-v1/manifest.json`](corpora/agentdojo-banking-v1/manifest.json)
- Ground truth: [`docs/ground-truth.md`](docs/ground-truth.md)
- Data handling: [`docs/data-handling.md`](docs/data-handling.md)
- Holdout error audit: [`docs/evidence-audit.md`](docs/evidence-audit.md)

Licensed under Apache-2.0. The derived corpus retains its upstream AgentDojo attribution and MIT licence notice.
"""


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _interval(value: list[float] | None) -> str:
    if value is None:
        return "n/a"
    return f"{value[0] * 100:.1f}%–{value[1] * 100:.1f}%"
