# Limitations

`TW-001` is ordered behavioural correlation. A match does not establish that retrieved content caused later actions, that the action was malicious, that sensitive data was copied into outbound arguments, or that the user did not authorise it.

The measured result applies only to the committed AgentDojo banking replay corpus under the documented tool taxonomy. Historic traces have event order but no per-event timestamps, so this corpus does not test elapsed-time semantics. The tool taxonomy is adapter-supplied because AgentDojo does not provide trusted provenance labels.

Tripwire does not prevent attacks, prove safety, operate in real time, or claim production readiness.

On the frozen development partition, `TW-001` produced 3 false positives among 74 negative sessions, compared with 4 for the naive external-read/external-write sequence. On holdout, both sequences produced 1 false positive among 37 negative sessions. The extra sensitive-read stage therefore showed a small development specificity improvement that did not repeat on holdout.
