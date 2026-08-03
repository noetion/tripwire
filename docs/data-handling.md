# Data handling

The replay corpus is derived from synthetic AgentDojo traces and does not contain raw upstream runs. During construction, every free-text lexeme is replaced by a deterministic per-trace token. Tool-call identifiers and numeric identifiers in sensitive fields are also replaced. Equal source values receive equal tokens inside a trace, preserving equality while removing names, account identifiers, emails, paths, instructions and model-supplied secrets.

The committed records retain only normalised events, evaluation labels and non-sensitive source attribution. Raw traces live only in the ignored `.upstream/` directory and are never printed by verification.

