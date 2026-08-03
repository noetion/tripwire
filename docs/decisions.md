# Decisions

## 2026-08-03: Initial replay selection

The first corpus freezes official AgentDojo `v0.1.35` traces for the `gpt-4o-2024-05-13` banking pipeline, selecting `tool_knowledge` injected runs and the pipeline's no-injection runs. This is the narrow source directly supported by M0 evidence and provides enough cases for the required deterministic holdout split without mixing defenses, models or attack renderings.

Some historic committed traces omit benchmark and package version fields. The manifest pins the upstream tag, source revision and intended benchmark taxonomy; missing per-run metadata remains null rather than being invented.

The canonical verifier evaluates both development and holdout partitions. The evaluation CLI's `--split` option limits a standalone output to the selected partition; public claims remain scoped to holdout.

The canonical split groups by `(suite, user task, injection task)`, so it isolates unseen combinations rather than unseen user tasks or injection families. A secondary post-hoc stress test hashes `(suite, injection task)` with the same deterministic 70/30 algorithm. It holds out complete `injection_task_7` and `injection_task_8` families and reports recall only over successful attacks in those families. It is not described as a clean unseen-family estimate because the original development partition exposed the rule-development process to every injection family.

## 2026-08-04: TW-001 freeze after holdout audit

`TW-001` is frozen after the M2 audit inspected every canonical holdout error. The current holdout remains valid only for the unchanged rule. A successor rule must use a fresh split or corpus for an uncontaminated holdout claim; otherwise its result must be labelled contaminated. The family stress test reports recall only because benign no-injection negatives have no injection family, and its interval overlaps the canonical recall interval.

## 2026-08-03: Naive-sequence stop-condition check

The naive external-result then external-write diagnostic matched 4 of 74 development negatives and 1 of 37 holdout negatives. `TW-001` matched 3 of 74 and 1 of 37 respectively. The documented stop condition was not reached because `TW-001` has better specificity on the frozen development data, although the improvement did not repeat on holdout. This limitation is reported without changing the rule after holdout evaluation.
