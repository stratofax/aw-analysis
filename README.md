# aw-analysis

Analyze [ActivityWatch](https://activitywatch.net/) data with AFK-filtered active time.

ActivityWatch tracks which app is in the foreground and whether the user is active or idle (AFK). Naively summing window event durations overcounts dramatically — it includes idle time, login screens, and overlapping watchers. This tool intersects window events with not-afk intervals to compute **actual active time**, then enriches the data with browser tab URLs and editor file paths.

## Features

- **AFK-filtered active time** — only counts time when you were actually at the keyboard
- **App breakdown** — active time per application with visual bars
- **Browser detail** — breaks down browser time by domain (requires the [ActivityWatch web extension](https://docs.activitywatch.net/en/latest/getting-started.html))
- **Editor detail** — categorizes editor time by file path (supports Obsidian, VS Code, and other editor watchers)
- **Flexible time ranges** — daily, weekly, monthly, or arbitrary date ranges
- **Auto-discovery** — finds the right buckets automatically, no configuration needed
- **Zero dependencies** — Python 3.7+ stdlib only, runs anywhere Python does
- **JSON output** — machine-readable output for integration with other tools

## Installation

```bash
git clone https://github.com/stratofax/aw-analysis.git
cd aw-analysis
```

No dependencies to install. Just Python 3.7+.

## Usage

```bash
# Today's activity
./aw-analysis.py

# This week (Monday through Sunday)
./aw-analysis.py --period week

# This month
./aw-analysis.py --period month

# Custom date range
./aw-analysis.py --start 2026-02-22 --end 2026-02-28

# JSON output for scripting
./aw-analysis.py --period week --json

# Specify AW port (if not default 5600)
./aw-analysis.py --port 5601

# Prefer a specific hostname's buckets
./aw-analysis.py --hostname MyMachine.local
```

## How It Works

### The Overlap Problem

ActivityWatch runs multiple watchers simultaneously:

| Watcher | What It Tracks |
|---------|---------------|
| `currentwindow` | Which app is in the foreground + window title |
| `afkstatus` | Whether the user is active (keyboard/mouse) or idle |
| `web.tab.current` | Active browser tab URL and title |
| `app.editor.activity` | Which file is open in the editor |

Naively summing any single watcher's durations produces wildly inaccurate results. The window watcher, for example, generates events even when the user is away — you'll see hours of "loginwindow" or "lock screen" time that isn't real usage.

### The Solution: AFK Intersection

The AFK watcher is the authoritative signal for whether a human was present. This tool:

1. Fetches window events (app + title + duration)
2. Fetches AFK events, filters for `status == "not-afk"`
3. For each window event, computes its overlap with not-afk intervals
4. Sums overlapping durations by app

The result is **actual active time** — only the time you were at the keyboard using each app.

### Browser and Editor Enrichment

For browser apps, the tool cross-references the `web.tab.current` bucket to break down time by domain (e.g., `github.com`, `mail.google.com`, `reddit.com`).

For editor apps, it cross-references the `app.editor.activity` bucket to categorize time by file path (writing, notes, project management, etc.).

## Bucket Auto-Discovery

The script queries `/api/0/buckets/` and picks buckets by type, not by hardcoded name. This means it works regardless of your hostname, machine name changes, or synced data from other machines.

If multiple buckets of the same type exist, it picks the alphabetically last one (which tends to be the current hostname). You can override this with `--hostname`.

## Multi-Machine Usage

Install and run separately on each machine. Each instance analyzes its own local ActivityWatch data. To combine results across machines, use `--json` and aggregate externally.

## Compatibility

- **ActivityWatch:** v0.12+ (tested on v0.13.2)
- **Python:** 3.7+
- **Platforms:** macOS, Linux, Windows — anywhere ActivityWatch and Python run

## License

MIT
