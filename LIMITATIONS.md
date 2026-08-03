# Limitations

`TW-001` is ordered behavioural correlation. A match does not establish that retrieved content caused later actions, that the action was malicious, that sensitive data was copied into outbound arguments, or that the user did not authorise it.

The measured result applies only to the committed AgentDojo banking replay corpus under the documented tool taxonomy. Historic traces have event order but no per-event timestamps, so this corpus does not test elapsed-time semantics. The tool taxonomy is adapter-supplied because AgentDojo does not provide trusted provenance labels.

Tripwire does not prevent attacks, prove safety, or operate in real time.

The canonical split groups by `(suite, user task, injection task)`. It prevents an exact combination from crossing partitions, but the same user task and the same injection family can occur on both sides. Its 35.3% recall therefore measures generalisation to unseen combinations, not unseen attacks.

A deterministic secondary split groups successful attacks by `(suite, injection task)` and holds out complete `injection_task_7` and `injection_task_8` families. TW-001 recalls 6 of 13 successful attacks there (46.2%, Wilson 95%: 23.2%–70.9%). This is a post-hoc stress test, not an unbiased unseen-family holdout: the original development partition contained examples from every injection family before this analysis was added.

On the frozen development partition, `TW-001` produced 3 false positives among 74 negative sessions, compared with 4 for the naive external-read/external-write sequence. On holdout, both sequences produced 1 false positive among 37 negative sessions. The extra sensitive-read stage therefore showed a small development specificity improvement that did not repeat on holdout.

Two of the three development false positives are benign no-injection runs. Their legitimate workflow is the same structural sequence as the rule: `read_file`, `get_scheduled_transactions`, then `update_scheduled_transaction`. The third development false positive and the one holdout false positive are injected runs whose benchmark attack goal failed, and both share that scheduled-update sequence. TW-001 cannot distinguish these normal or unsuccessful workflows from successful attacks by sequence shape alone.

## Holdout error audit

The one holdout false positive contains the full structural sequence, but AgentDojo's injection-task goal did not succeed. The sequence cannot distinguish a failed benchmark attack from an authorised or differently motivated workflow.

Eight of eleven false negatives received injected content inside incoming transaction data returned by tools classified as internal sensitive reads. Historic AgentDojo traces do not provide item-level provenance, and marking an entire mixed transaction result as external would overstate trust information. One other false negative performs direct money movement without a sensitive read; two perform account state changes rather than external writes.

Every error and its observed tool sequence is recorded in [`docs/evidence-audit.md`](docs/evidence-audit.md). The rule was not changed after holdout inspection.
