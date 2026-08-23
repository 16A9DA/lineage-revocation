# Delegation Corroboration: 33 Raw Traces

## Method

Ran `measurement.adapters.smolagents_adapter.adapt_file` once for every
`artifacts/raw_traces/*.json` file. The separate preserved failure record in
`artifacts/raw_traces/failed/` is not a collected raw trace and was excluded.
The validator raises `DelegationValidationError` whenever a detected delegation
has no timed activity from its child agent.

## Exact Result

- Raw traces validated: 33
- Total delegation events: 21
- Corroborated delegation events: 21
- Uncorroborated delegation events: 0
- Traces with validation failures: 0

Result: **21/21 corroborated**.

Machine-readable counterpart:
`artifacts/validation/delegation-corroboration-33.json`.
