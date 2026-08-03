# Tripwire repository guidance

The defining acceptance check is `uv run tripwire verify`. Do not treat component checks as proof that the committed measurement reproduces.

Do not commit raw AgentDojo traces or print their content. Keep evaluation labels outside the rule engine. Do not add cloud backends, extra rules or performance claims until the clean-checkout M1 journey passes.

