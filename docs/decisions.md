# Decisions

## 2026-08-03: Initial replay selection

The first corpus freezes official AgentDojo `v0.1.35` traces for the `gpt-4o-2024-05-13` banking pipeline, selecting `tool_knowledge` injected runs and the pipeline's no-injection runs. This is the narrow source directly supported by M0 evidence and provides enough cases for the required deterministic holdout split without mixing defenses, models or attack renderings.

Some historic committed traces omit benchmark and package version fields. The manifest pins the upstream tag, source revision and intended benchmark taxonomy; missing per-run metadata remains null rather than being invented.

The canonical result evaluates both development and holdout partitions even when the CLI accepts `--split holdout`. This prevents the option from changing the committed evidence schema; public claims remain scoped to holdout.

## 2026-08-03: Naive-sequence stop-condition check

The naive external-result then external-write diagnostic matched 4 of 74 development negatives and 1 of 37 holdout negatives. `TW-001` matched 3 of 74 and 1 of 37 respectively. The documented stop condition was not reached because `TW-001` has better specificity on the frozen development data, although the improvement did not repeat on holdout. This limitation is reported without changing the rule after holdout evaluation.
