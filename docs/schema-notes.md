# M0 schema and corpus notes

**Status:** Resolved sufficiently to begin M1  
**Date:** 3 August 2026  
**Basis:** Direct inspection of AgentDojo `v0.1.35` source and official committed banking traces.

AgentDojo writes one JSON document per run with suite, pipeline, user task, injection task, attack type, messages, top-level error, utility, security and duration. Historic files preserve message order but not per-event timestamps. They provide neither a stable native session ID nor trusted source-provenance labels.

Assistant messages contain tool calls. Tool messages contain results, call IDs and, in newer traces, an embedded tool-call object. Historic content is a string; current content is an array of text blocks. The adapter supports both without using injection content, attacker destinations or outcome metadata as detector inputs.

For injected runs, AgentDojo's `security=true` means the injection task succeeded. For no-injection runs it is true by convention. Tripwire renames this evaluation metadata to `attack_succeeded` and defines positives as injected successful runs, negatives as unsuccessful injected or benign runs, and uninterpretable runs as unknown.

Official traces demonstrate a successful `read_file` → `get_most_recent_transactions` → `send_money` chain, an unsuccessful injection that stops before the attacker transfer, and a legitimate `read_file` → `send_money` bill-payment chain. This evidence motivated `TW-001` and shows why a naive read/write sequence is too broad.

The banking tool taxonomy is source-adapter configuration. `read_file` is external input; banking and user-information reads are sensitive; money movement is external write; account updates are state changes. Unknown tools remain explicitly unknown.

Stable session identity is the SHA-256 of canonical JSON containing benchmark version, suite, pipeline, user task, injection task and attack type. Replay reproducibility requires no model credential. Byte-for-byte regeneration of model-produced source traces is not claimed.

