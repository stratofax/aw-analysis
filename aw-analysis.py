#!/usr/bin/env python3
"""
aw-analysis — ActivityWatch time analysis with AFK-filtered active time.

Analyzes ActivityWatch data by intersecting window events with not-afk
intervals to compute accurate active time. Supports daily, weekly, monthly,
and arbitrary date ranges.

Requires: Python 3.7+, ActivityWatch running on localhost (or specify --port).
No external dependencies — stdlib only.

Usage:
    aw-analysis.py                        # Today's activity
    aw-analysis.py --period week          # This week (Mon-Sun)
    aw-analysis.py --period month         # This month
    aw-analysis.py --start 2026-02-22 --end 2026-02-28  # Custom range
    aw-analysis.py --json                 # Machine-readable output
"""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone

__version__ = "0.1.0"

# AW bucket type constants
TYPE_WINDOW = "currentwindow"
TYPE_AFK = "afkstatus"
TYPE_BROWSER = "web.tab.current"
TYPE_EDITOR = "app.editor.activity"


def fetch_json(url):
    """Fetch JSON from a URL, return parsed data or None on error."""
    try:
        resp = urllib.request.urlopen(url, timeout=10)
        return json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        print(f"  Warning: could not fetch {url}: {e}", file=sys.stderr)
        return None


def discover_buckets(base_url):
    """Auto-discover available buckets grouped by type.

    Returns dict of {type: [{id, hostname, client}, ...]} for known types.
    When multiple buckets of the same type exist (e.g., synced from other
    machines), all are returned — the caller decides which to use.
    """
    data = fetch_json(f"{base_url}/api/0/buckets/")
    if not data:
        print("Error: could not connect to ActivityWatch API.", file=sys.stderr)
        print(f"Is ActivityWatch running? Tried: {base_url}", file=sys.stderr)
        sys.exit(1)

    buckets = defaultdict(list)
    for bucket_id, info in data.items():
        btype = info.get("type", "")
        if btype in (TYPE_WINDOW, TYPE_AFK, TYPE_BROWSER, TYPE_EDITOR):
            buckets[btype].append({
                "id": bucket_id,
                "hostname": info.get("hostname", "unknown"),
                "client": info.get("client", "unknown"),
            })
    return dict(buckets)


def pick_bucket(buckets, btype, hostname=None):
    """Pick the best bucket for a given type.

    Prefers buckets matching the given hostname. If no hostname specified,
    picks the one with the most recent-looking ID (alphabetically last,
    which tends to be the current hostname).
    """
    candidates = buckets.get(btype, [])
    if not candidates:
        return None

    if hostname:
        for b in candidates:
            if hostname.lower() in b["id"].lower():
                return b["id"]

    # Fall back to alphabetically last (often the current hostname)
    return sorted(candidates, key=lambda b: b["id"])[-1]["id"]


def fetch_events(base_url, bucket_id, start, end, limit=10000):
    """Fetch events from a bucket within a time range."""
    start_str = urllib.parse.quote(start.isoformat())
    end_str = urllib.parse.quote(end.isoformat())
    url = (
        f"{base_url}/api/0/buckets/{bucket_id}/events"
        f"?limit={limit}&start={start_str}&end={end_str}"
    )
    return fetch_json(url) or []


def parse_timestamp(ts_str):
    """Parse an ISO 8601 timestamp string to a datetime object."""
    # Handle various AW timestamp formats
    ts_str = ts_str.replace("Z", "+00:00")
    # Python 3.7+ fromisoformat doesn't handle all formats, so normalize
    if "+" not in ts_str and "-" not in ts_str[10:]:
        ts_str += "+00:00"
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        # Fallback: strip microseconds if parsing fails
        base = ts_str[:19]
        tz = ts_str[19:] if len(ts_str) > 19 else "+00:00"
        return datetime.fromisoformat(f"{base}{tz}")


def compute_active_time(window_events, afk_events):
    """Intersect window events with not-afk intervals.

    Returns list of (app, title, duration_seconds) tuples representing
    active (non-AFK) time for each window event.
    """
    # Build not-afk intervals
    not_afk = []
    for e in afk_events:
        status = e.get("data", {}).get("status", "")
        if status == "not-afk":
            start = parse_timestamp(e["timestamp"])
            duration = e.get("duration", 0)
            end = start + timedelta(seconds=duration)
            not_afk.append((start, end))

    # Sort by start time
    not_afk.sort(key=lambda x: x[0])

    # Intersect each window event with not-afk intervals
    active = []
    for we in window_events:
        data = we.get("data", {})
        app = data.get("app", "unknown")
        title = data.get("title", "")
        w_start = parse_timestamp(we["timestamp"])
        w_end = w_start + timedelta(seconds=we.get("duration", 0))

        for naf_start, naf_end in not_afk:
            # Skip intervals that can't overlap
            if naf_end <= w_start:
                continue
            if naf_start >= w_end:
                break

            overlap_start = max(w_start, naf_start)
            overlap_end = min(w_end, naf_end)
            if overlap_start < overlap_end:
                secs = (overlap_end - overlap_start).total_seconds()
                active.append((app, title, secs))

    return active


def categorize_browser(browser_events, start, end):
    """Build a domain -> total seconds mapping from browser tab events."""
    domains = defaultdict(float)
    for e in browser_events:
        ts = parse_timestamp(e["timestamp"])
        if ts < start or ts > end:
            continue
        data = e.get("data", {})
        url = data.get("url", "")
        duration = e.get("duration", 0)
        if "://" in url:
            domain = url.split("://")[1].split("/")[0]
            # Strip www. for cleaner grouping
            if domain.startswith("www."):
                domain = domain[4:]
            domains[domain] += duration
        elif url:
            domains["(other)"] += duration
    return dict(domains)


def categorize_editor(editor_events, start, end):
    """Build a category -> total seconds mapping from editor events."""
    categories = defaultdict(float)
    files = defaultdict(float)
    for e in editor_events:
        ts = parse_timestamp(e["timestamp"])
        if ts < start or ts > end:
            continue
        data = e.get("data", {})
        filepath = data.get("file", "")
        duration = e.get("duration", 0)

        files[filepath] += duration

        # Categorize by path components
        parts = filepath.lower().split("/")
        if "diary" in parts or "journal" in parts:
            categories["writing/diary"] += duration
        elif "pages" in parts:
            categories["writing/pages"] += duration
        elif "projects" in parts:
            categories["project-mgmt"] += duration
        elif "tasks" in parts or "todo" in parts:
            categories["task-mgmt"] += duration
        elif "notes" in parts:
            categories["notes"] += duration
        else:
            categories["other"] += duration

    return dict(categories), dict(files)


def format_duration(seconds):
    """Format seconds as human-readable duration."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f}min"
    hours = minutes / 60
    return f"{hours:.1f}h"


def format_pct(part, total):
    """Format a percentage."""
    if total == 0:
        return "0%"
    return f"{part / total * 100:.1f}%"


def get_period_range(period, ref_date=None):
    """Compute start/end datetimes for a named period.

    All times are in the local system timezone.
    """
    local_tz = datetime.now().astimezone().tzinfo
    if ref_date is None:
        ref_date = datetime.now(tz=local_tz)

    # Start of today in local time
    today_start = ref_date.replace(hour=0, minute=0, second=0, microsecond=0)

    if period == "day":
        return today_start, today_start + timedelta(days=1)
    elif period == "week":
        # Monday-based week
        weekday = today_start.weekday()  # 0=Monday
        week_start = today_start - timedelta(days=weekday)
        return week_start, week_start + timedelta(days=7)
    elif period == "month":
        month_start = today_start.replace(day=1)
        # Next month
        if month_start.month == 12:
            month_end = month_start.replace(year=month_start.year + 1, month=1)
        else:
            month_end = month_start.replace(month=month_start.month + 1)
        return month_start, month_end
    else:
        raise ValueError(f"Unknown period: {period}")


def print_summary(results, args):
    """Print human-readable summary."""
    local_tz = datetime.now().astimezone().tzinfo

    start_local = results["start"].astimezone(local_tz)
    end_local = results["end"].astimezone(local_tz)

    print(f"\n{'=' * 60}")
    print(f"  ActivityWatch Analysis — {start_local.strftime('%Y-%m-%d')} to "
          f"{end_local.strftime('%Y-%m-%d')}")
    print(f"{'=' * 60}")

    # AFK summary
    afk = results.get("afk_summary", {})
    if afk:
        active = afk.get("active_seconds", 0)
        total = afk.get("total_seconds", 0)
        print(f"\n  Active (not-afk): {format_duration(active)}"
              f"  |  AFK: {format_duration(afk.get('afk_seconds', 0))}"
              f"  |  Active ratio: {format_pct(active, total)}")

    # Active time by app
    apps = results.get("active_by_app", {})
    total_active = sum(apps.values())
    if apps:
        print(f"\n  Active Time by App ({format_duration(total_active)} total):")
        print(f"  {'-' * 56}")
        for app, secs in sorted(apps.items(), key=lambda x: -x[1]):
            bar_len = int(secs / total_active * 30) if total_active else 0
            bar = "█" * bar_len
            print(f"    {app:<24} {format_duration(secs):>8}  "
                  f"({format_pct(secs, total_active):>5})  {bar}")

    # Browser detail
    browser = results.get("browser_domains", {})
    browser_apps = [a for a in apps if "brave" in a.lower() or "firefox" in a.lower()
                    or "chrome" in a.lower() or "safari" in a.lower()]
    if browser:
        browser_total = sum(browser.values())
        print(f"\n  Browser Breakdown ({format_duration(browser_total)} tab time):")
        print(f"  {'-' * 56}")
        for domain, secs in sorted(browser.items(), key=lambda x: -x[1])[:15]:
            print(f"    {domain:<36} {format_duration(secs):>8}  "
                  f"({format_pct(secs, browser_total):>5})")
        remaining = len(browser) - 15
        if remaining > 0:
            print(f"    ... and {remaining} more domains")

    # Editor detail
    editor_cats = results.get("editor_categories", {})
    if editor_cats:
        editor_total = sum(editor_cats.values())
        print(f"\n  Editor Breakdown ({format_duration(editor_total)} editor time):")
        print(f"  {'-' * 56}")
        for cat, secs in sorted(editor_cats.items(), key=lambda x: -x[1]):
            print(f"    {cat:<36} {format_duration(secs):>8}  "
                  f"({format_pct(secs, editor_total):>5})")

    # Buckets used
    print(f"\n  Buckets: {', '.join(results.get('buckets_used', []))}")
    print(f"  Hostname: {results.get('hostname', 'auto-detected')}")
    print(f"{'=' * 60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze ActivityWatch data with AFK-filtered active time.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--period", choices=["day", "week", "month"], default="day",
        help="Time period to analyze (default: day)",
    )
    parser.add_argument(
        "--start", type=str, default=None,
        help="Start date (YYYY-MM-DD). Overrides --period.",
    )
    parser.add_argument(
        "--end", type=str, default=None,
        help="End date (YYYY-MM-DD). Overrides --period.",
    )
    parser.add_argument(
        "--port", type=int, default=5600,
        help="ActivityWatch server port (default: 5600)",
    )
    parser.add_argument(
        "--hostname", type=str, default=None,
        help="Prefer buckets matching this hostname (auto-detected if omitted)",
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output machine-readable JSON",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}",
    )
    args = parser.parse_args()

    base_url = f"http://localhost:{args.port}"
    local_tz = datetime.now().astimezone().tzinfo

    # Determine time range
    if args.start or args.end:
        if not args.start or not args.end:
            parser.error("--start and --end must both be specified")
        start = datetime.fromisoformat(args.start).replace(
            hour=0, minute=0, second=0, microsecond=0, tzinfo=local_tz
        )
        end = datetime.fromisoformat(args.end).replace(
            hour=23, minute=59, second=59, microsecond=999999, tzinfo=local_tz
        )
    else:
        start, end = get_period_range(args.period)

    # Discover buckets
    if not args.json_output:
        print(f"Connecting to ActivityWatch at {base_url}...")
    buckets = discover_buckets(base_url)

    if not args.json_output:
        total = sum(len(v) for v in buckets.values())
        print(f"Found {total} relevant buckets across {len(buckets)} types")

    # Pick best buckets for each type
    window_id = pick_bucket(buckets, TYPE_WINDOW, args.hostname)
    afk_id = pick_bucket(buckets, TYPE_AFK, args.hostname)
    browser_id = pick_bucket(buckets, TYPE_BROWSER, args.hostname)
    editor_id = pick_bucket(buckets, TYPE_EDITOR, args.hostname)

    if not window_id or not afk_id:
        print("Error: could not find window and AFK buckets.", file=sys.stderr)
        print("Available buckets:", file=sys.stderr)
        for btype, blist in buckets.items():
            for b in blist:
                print(f"  [{btype}] {b['id']}", file=sys.stderr)
        sys.exit(1)

    buckets_used = [window_id, afk_id]

    # Fetch core events
    if not args.json_output:
        print(f"Fetching events for {start.strftime('%Y-%m-%d')} to "
              f"{end.strftime('%Y-%m-%d')}...")

    window_events = fetch_events(base_url, window_id, start, end)
    afk_events = fetch_events(base_url, afk_id, start, end)

    if not args.json_output:
        print(f"  Window events: {len(window_events)}")
        print(f"  AFK events: {len(afk_events)}")

    # Compute AFK summary
    active_secs = 0
    afk_secs = 0
    for e in afk_events:
        status = e.get("data", {}).get("status", "")
        duration = e.get("duration", 0)
        if status == "not-afk":
            active_secs += duration
        elif status == "afk":
            afk_secs += duration

    # Compute active time by app (AFK-filtered)
    active_events = compute_active_time(window_events, afk_events)
    active_by_app = defaultdict(float)
    for app, title, secs in active_events:
        active_by_app[app] += secs

    # Browser categorization (optional)
    browser_domains = {}
    if browser_id:
        buckets_used.append(browser_id)
        browser_events = fetch_events(base_url, browser_id, start, end)
        if not args.json_output:
            print(f"  Browser events: {len(browser_events)}")
        browser_domains = categorize_browser(browser_events, start, end)

    # Editor categorization (optional)
    editor_categories = {}
    editor_files = {}
    if editor_id:
        buckets_used.append(editor_id)
        editor_events = fetch_events(base_url, editor_id, start, end)
        if not args.json_output:
            print(f"  Editor events: {len(editor_events)}")
        editor_categories, editor_files = categorize_editor(
            editor_events, start, end
        )

    # Determine hostname from the window bucket
    hostname = "unknown"
    for b in buckets.get(TYPE_WINDOW, []):
        if b["id"] == window_id:
            hostname = b["hostname"]
            break

    results = {
        "start": start,
        "end": end,
        "hostname": hostname,
        "buckets_used": buckets_used,
        "afk_summary": {
            "active_seconds": active_secs,
            "afk_seconds": afk_secs,
            "total_seconds": active_secs + afk_secs,
            "active_ratio": active_secs / (active_secs + afk_secs)
            if (active_secs + afk_secs) > 0
            else 0,
        },
        "active_by_app": dict(active_by_app),
        "browser_domains": browser_domains,
        "editor_categories": editor_categories,
        "editor_files": editor_files,
    }

    if args.json_output:
        # Serialize with datetime conversion
        output = dict(results)
        output["start"] = start.isoformat()
        output["end"] = end.isoformat()
        print(json.dumps(output, indent=2))
    else:
        print_summary(results, args)


if __name__ == "__main__":
    main()
