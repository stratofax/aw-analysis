# Release Notes

## v0.1.0 — 2026-02-28

First release. Analyzes ActivityWatch data with AFK-filtered active time.

### Features

- **AFK-filtered active time** — intersects window events with not-afk intervals to compute actual keyboard time
- **App breakdown** — active time per application with visual bars
- **Browser detail** — breaks down browser time by domain using the AW web extension
- **Editor detail** — categorizes editor time by file extension (writing, code, config, web)
- **Flexible time ranges** — `--period day|week|month` or `--start`/`--end` for custom ranges
- **Auto-discovery** — finds buckets by type and matches to local hostname automatically
- **JSON output** — `--json` flag for machine-readable output
- **Zero dependencies** — Python 3.7+ stdlib only

### Security & Correctness (from 32-agent red team analysis)

- Hostname matching uses exact suffix equality, not substring matching (#1)
- Overlapping not-afk intervals are merged before intersection (#3)
- AFK summary durations are clipped to the requested time range (#7)
- Domain extraction uses `urlparse` instead of string splitting (#4)
- Date input validated before API request (#10)

### Robustness

- Warns when event limit (10,000) is reached, indicating possible truncation (#2)
- Clear error messages for connection failures and timeouts (#8)
- Explicit message when bucket has no events for the requested period (#9)

### Cross-Platform

- Windows backslash paths normalized for editor categorization (#5)
- Extension-based editor categories work across all platforms (#6)

### Testing

- 91 tests with 97% coverage
- All tests mock the AW API — no running ActivityWatch instance needed
