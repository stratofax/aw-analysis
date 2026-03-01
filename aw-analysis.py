#!/usr/bin/env python3
"""
aw-analysis — ActivityWatch time analysis with AFK-filtered active time.

Analyzes ActivityWatch data by intersecting window events with not-afk
intervals to compute accurate active time. Supports daily, weekly, monthly,
and arbitrary date ranges. Multi-device support via SSH tunnels.

Requires: Python 3.7+, ActivityWatch running (local or remote via --host).
No external dependencies — stdlib only.

Usage:
    aw-analysis.py                        # Today's activity
    aw-analysis.py --period week          # This week (Mon-Sun)
    aw-analysis.py --period month         # This month
    aw-analysis.py --start 2026-02-22 --end 2026-02-28  # Custom range
    aw-analysis.py --json                 # Machine-readable output
    aw-analysis.py --host localhost --port 5601  # Remote server via SSH tunnel
    aw-analysis.py --hostname "Host1,Host2"      # Multi-hostname consolidation
    aw-analysis.py --export-dir ./data --start 2026-02-01 --end 2026-02-28
    aw-analysis.py --devices "localhost:5600,localhost:5601"  # Multi-device
"""

import argparse
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone

__version__ = "0.2.0"

# AW bucket type constants
TYPE_WINDOW = "currentwindow"
TYPE_AFK = "afkstatus"
TYPE_BROWSER = "web.tab.current"
TYPE_EDITOR = "app.editor.activity"


def fetch_json(url, timeout=30):
    """Fetch JSON from a URL, return parsed data or None on error."""
    try:
        resp = urllib.request.urlopen(url, timeout=timeout)
        return json.loads(resp.read())
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        print(f"  Error: could not connect — {reason}", file=sys.stderr)
        print(f"  Is ActivityWatch running? URL: {url}", file=sys.stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"  Error: invalid JSON response from {url}: {e}", file=sys.stderr)
        return None
    except OSError as e:
        print(f"  Error: {e}", file=sys.stderr)
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


def get_local_hostname():
    """Get the local hostname as ActivityWatch would see it."""
    hostname = socket.gethostname()
    # AW typically uses the full hostname (e.g., "Air4.local" on macOS)
    if "." not in hostname:
        # Try to get the FQDN
        fqdn = socket.getfqdn()
        if fqdn and fqdn != hostname:
            hostname = fqdn
    return hostname


def _hostname_matches(bucket_id, hostname):
    """Check if a bucket ID ends with the given hostname (after _ or - delimiter).

    Uses suffix matching on AW's bucket naming convention:
    'aw-watcher-window_MyHost.local' -> matches 'MyHost.local'
    Prevents 'air' from matching 'air4' (substring false positive).
    """
    bid = bucket_id.lower()
    host = hostname.lower()
    # AW convention: hostname is after underscore (e.g., aw-watcher-window_MyHost)
    # Hyphens are part of the watcher name, NOT hostname delimiters
    idx = bid.rfind("_")
    if idx >= 0 and bid[idx + 1:] == host:
        return True
    return False


def pick_bucket(buckets, btype, hostname=None):
    """Pick the best bucket for a given type.

    Priority: 1) explicit --hostname match, 2) local hostname match,
    3) first candidate (fallback).
    """
    candidates = buckets.get(btype, [])
    if not candidates:
        return None

    # 1. Explicit hostname override
    if hostname:
        for b in candidates:
            if _hostname_matches(b["id"], hostname):
                return b["id"]

    # 2. Match local machine hostname
    local_host = get_local_hostname()
    for b in candidates:
        if _hostname_matches(b["id"], local_host):
            return b["id"]

    # 3. Fall back: prefer candidates with known hostnames over "unknown"
    known = [b for b in candidates if b["hostname"] != "unknown"]
    if known:
        return known[0]["id"]
    return candidates[0]["id"]


def fetch_events(base_url, bucket_id, start, end, limit=10000):
    """Fetch events from a bucket within a time range.

    Warns on stderr if the number of returned events equals the limit,
    which indicates the results may be truncated.
    """
    start_str = urllib.parse.quote(start.isoformat())
    end_str = urllib.parse.quote(end.isoformat())
    url = (
        f"{base_url}/api/0/buckets/{bucket_id}/events"
        f"?limit={limit}&start={start_str}&end={end_str}"
    )
    events = fetch_json(url) or []
    if len(events) == limit:
        print(
            f"  Warning: {limit} events returned from {bucket_id} — "
            f"results may be incomplete. Try a shorter time range.",
            file=sys.stderr,
        )
    return events


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


def _merge_intervals(intervals):
    """Merge overlapping or adjacent time intervals.

    Takes a sorted list of (start, end) tuples and returns a new list
    with overlapping intervals merged. O(n) after sort.
    """
    if not intervals:
        return []
    merged = [intervals[0]]
    for start, end in intervals[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end:
            # Overlapping or adjacent — extend
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


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

    # Sort by start time and merge overlapping intervals to prevent
    # double-counting when the AFK watcher produces duplicate events
    not_afk.sort(key=lambda x: x[0])
    not_afk = _merge_intervals(not_afk)

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
        parsed = urllib.parse.urlparse(url)
        domain = parsed.hostname
        if domain:
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

        # Categorize by file extension (cross-platform)
        # Normalize path separators for Windows compatibility
        normalized = filepath.replace("\\", "/").lower()
        ext = normalized.rsplit(".", 1)[-1] if "." in normalized else ""
        if ext in ("md", "txt", "rst", "adoc", "org"):
            categories["writing"] += duration
        elif ext in ("py", "js", "ts", "tsx", "jsx", "rs", "go", "java",
                      "c", "cpp", "h", "rb", "sh", "bash", "zsh"):
            categories["code"] += duration
        elif ext in ("json", "yaml", "yml", "toml", "ini", "cfg", "conf",
                      "xml", "env"):
            categories["config"] += duration
        elif ext in ("html", "css", "scss", "less", "svelte", "vue"):
            categories["web"] += duration
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


def pick_buckets_multi(buckets, btype, hostnames):
    """Pick all buckets matching any of the given hostnames for a type.

    Returns list of bucket IDs. Used for multi-hostname consolidation.
    """
    candidates = buckets.get(btype, [])
    if not candidates:
        return []
    matched = []
    for hostname in hostnames:
        for b in candidates:
            if _hostname_matches(b["id"], hostname) and b["id"] not in matched:
                matched.append(b["id"])
    return matched


def fetch_events_multi(base_url, bucket_ids, start, end, limit=10000):
    """Fetch and merge events from multiple buckets."""
    all_events = []
    for bid in bucket_ids:
        all_events.extend(fetch_events(base_url, bid, start, end, limit))
    return all_events


def analyze_range(base_url, start, end, hostname=None, quiet=True):
    """Analyze a time range on a single AW server.

    Returns a results dict, or None if no window events found.
    When hostname is a comma-separated string, uses multi-hostname matching.
    """
    buckets = discover_buckets(base_url)

    if not quiet:
        total = sum(len(v) for v in buckets.values())
        print(f"Found {total} relevant buckets across {len(buckets)} types")

    # Multi-hostname support: comma-separated values
    hostnames = None
    if hostname and "," in hostname:
        hostnames = [h.strip() for h in hostname.split(",")]

    # Pick buckets — multi or single
    if hostnames:
        window_ids = pick_buckets_multi(buckets, TYPE_WINDOW, hostnames)
        afk_ids = pick_buckets_multi(buckets, TYPE_AFK, hostnames)
        browser_ids = pick_buckets_multi(buckets, TYPE_BROWSER, hostnames)
        editor_ids = pick_buckets_multi(buckets, TYPE_EDITOR, hostnames)

        if not window_ids or not afk_ids:
            print("Error: could not find window and AFK buckets.", file=sys.stderr)
            return None

        buckets_used = window_ids + afk_ids
        window_events = fetch_events_multi(base_url, window_ids, start, end)
        afk_events = fetch_events_multi(base_url, afk_ids, start, end)

        if not window_events:
            return None

        browser_domains = {}
        if browser_ids:
            buckets_used.extend(browser_ids)
            browser_events = fetch_events_multi(
                base_url, browser_ids, start, end
            )
            browser_domains = categorize_browser(browser_events, start, end)

        editor_categories = {}
        editor_files = {}
        if editor_ids:
            buckets_used.extend(editor_ids)
            editor_events = fetch_events_multi(
                base_url, editor_ids, start, end
            )
            editor_categories, editor_files = categorize_editor(
                editor_events, start, end
            )

        resolved_hostname = hostnames[0]
    else:
        window_id = pick_bucket(buckets, TYPE_WINDOW, hostname)
        afk_id = pick_bucket(buckets, TYPE_AFK, hostname)
        browser_id = pick_bucket(buckets, TYPE_BROWSER, hostname)
        editor_id = pick_bucket(buckets, TYPE_EDITOR, hostname)

        if not window_id or not afk_id:
            print("Error: could not find window and AFK buckets.", file=sys.stderr)
            print("Available buckets:", file=sys.stderr)
            for btype, blist in buckets.items():
                for b in blist:
                    print(f"  [{btype}] {b['id']}", file=sys.stderr)
            sys.exit(1)

        buckets_used = [window_id, afk_id]
        window_events = fetch_events(base_url, window_id, start, end)
        afk_events = fetch_events(base_url, afk_id, start, end)

        if not quiet:
            print(f"  Window events: {len(window_events)}")
            print(f"  AFK events: {len(afk_events)}")

        if not window_events:
            return None

        browser_domains = {}
        if browser_id:
            buckets_used.append(browser_id)
            browser_events = fetch_events(base_url, browser_id, start, end)
            if not quiet:
                print(f"  Browser events: {len(browser_events)}")
            browser_domains = categorize_browser(browser_events, start, end)

        editor_categories = {}
        editor_files = {}
        if editor_id:
            buckets_used.append(editor_id)
            editor_events = fetch_events(base_url, editor_id, start, end)
            if not quiet:
                print(f"  Editor events: {len(editor_events)}")
            editor_categories, editor_files = categorize_editor(
                editor_events, start, end
            )

        # Determine hostname from the window bucket
        resolved_hostname = "unknown"
        for b in buckets.get(TYPE_WINDOW, []):
            if b["id"] == window_id:
                resolved_hostname = b["hostname"]
                break

    # Compute AFK summary (clipped to requested time range)
    active_secs = 0
    afk_secs = 0
    for e in afk_events:
        status = e.get("data", {}).get("status", "")
        e_start = parse_timestamp(e["timestamp"])
        e_end = e_start + timedelta(seconds=e.get("duration", 0))
        clipped_start = max(e_start, start)
        clipped_end = min(e_end, end)
        if clipped_start >= clipped_end:
            continue
        duration = (clipped_end - clipped_start).total_seconds()
        if status == "not-afk":
            active_secs += duration
        elif status == "afk":
            afk_secs += duration

    # Compute active time by app (AFK-filtered)
    active_events = compute_active_time(window_events, afk_events)
    active_by_app = defaultdict(float)
    for app, title, secs in active_events:
        active_by_app[app] += secs

    return {
        "start": start,
        "end": end,
        "hostname": resolved_hostname,
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


def merge_results(results_list):
    """Merge multiple analyze_range results into a combined summary.

    Combines active_by_app, browser_domains, editor_categories, editor_files
    by summing durations. Returns a merged results dict with a 'devices' array.
    """
    if not results_list:
        return None

    combined_apps = defaultdict(float)
    combined_browser = defaultdict(float)
    combined_editor_cats = defaultdict(float)
    combined_editor_files = defaultdict(float)
    combined_active = 0
    combined_afk = 0
    all_buckets = []
    devices = []

    for r in results_list:
        for app, secs in r.get("active_by_app", {}).items():
            combined_apps[app] += secs
        for domain, secs in r.get("browser_domains", {}).items():
            combined_browser[domain] += secs
        for cat, secs in r.get("editor_categories", {}).items():
            combined_editor_cats[cat] += secs
        for f, secs in r.get("editor_files", {}).items():
            combined_editor_files[f] += secs
        afk = r.get("afk_summary", {})
        combined_active += afk.get("active_seconds", 0)
        combined_afk += afk.get("afk_seconds", 0)
        all_buckets.extend(r.get("buckets_used", []))
        devices.append({
            "hostname": r.get("hostname", "unknown"),
            "active_seconds": afk.get("active_seconds", 0),
            "afk_seconds": afk.get("afk_seconds", 0),
            "buckets_used": r.get("buckets_used", []),
        })

    total = combined_active + combined_afk
    return {
        "start": results_list[0]["start"],
        "end": results_list[0]["end"],
        "hostname": "multi-device",
        "buckets_used": all_buckets,
        "afk_summary": {
            "active_seconds": combined_active,
            "afk_seconds": combined_afk,
            "total_seconds": total,
            "active_ratio": combined_active / total if total > 0 else 0,
        },
        "active_by_app": dict(combined_apps),
        "browser_domains": dict(combined_browser),
        "editor_categories": dict(combined_editor_cats),
        "editor_files": dict(combined_editor_files),
        "devices": devices,
    }


def export_days(base_url, start, end, export_dir, hostname=None):
    """Export day-by-day JSON files to a directory.

    Creates one YYYY-MM-DD.json per day. Skips empty days.
    Returns count of files written.
    """
    os.makedirs(export_dir, exist_ok=True)

    local_tz = start.tzinfo
    current = start
    written = 0

    while current < end:
        day_start = current.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = current.replace(
            hour=23, minute=59, second=59, microsecond=999999
        )
        date_str = current.strftime("%Y-%m-%d")

        print(f"  {date_str}...", end=" ", flush=True)
        results = analyze_range(base_url, day_start, day_end, hostname)

        if results is None:
            print("no data, skipping")
        else:
            output = dict(results)
            output["start"] = results["start"].isoformat()
            output["end"] = results["end"].isoformat()
            filepath = os.path.join(export_dir, f"{date_str}.json")
            with open(filepath, "w") as f:
                json.dump(output, f, indent=2)
            active = results["afk_summary"]["active_seconds"]
            print(f"wrote {filepath} ({format_duration(active)} active)")
            written += 1

        current += timedelta(days=1)

    return written


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
        "--host", type=str, default="localhost",
        help="ActivityWatch server host (default: localhost)",
    )
    parser.add_argument(
        "--port", type=int, default=5600,
        help="ActivityWatch server port (default: 5600)",
    )
    parser.add_argument(
        "--hostname", type=str, default=None,
        help="Prefer buckets matching this hostname. Comma-separated for "
             "multi-hostname consolidation (auto-detected if omitted)",
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output machine-readable JSON",
    )
    parser.add_argument(
        "--export-dir", type=str, default=None, dest="export_dir",
        help="Export day-by-day JSON files to this directory. "
             "Requires --start and --end.",
    )
    parser.add_argument(
        "--devices", type=str, default=None,
        help='Query multiple AW servers: "host:port,host:port". '
             "Mutually exclusive with --host.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}",
    )
    args = parser.parse_args()

    # Validate mutual exclusivity
    if args.devices and args.host != "localhost":
        parser.error("--devices and --host are mutually exclusive")

    # Validate --export-dir requires date range
    if args.export_dir and (not args.start or not args.end):
        parser.error("--export-dir requires --start and --end")

    local_tz = datetime.now().astimezone().tzinfo

    # Determine time range
    if args.start or args.end:
        if not args.start or not args.end:
            parser.error("--start and --end must both be specified")
        try:
            start = datetime.strptime(args.start, "%Y-%m-%d").replace(
                tzinfo=local_tz
            )
        except ValueError:
            parser.error(f"Invalid start date: '{args.start}'. Expected format: YYYY-MM-DD")
        try:
            end = datetime.strptime(args.end, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, microsecond=999999, tzinfo=local_tz
            )
        except ValueError:
            parser.error(f"Invalid end date: '{args.end}'. Expected format: YYYY-MM-DD")
    else:
        start, end = get_period_range(args.period)

    # Export mode
    if args.export_dir:
        base_url = f"http://{args.host}:{args.port}"
        print(f"Exporting to {args.export_dir}...")
        written = export_days(base_url, start, end, args.export_dir, args.hostname)
        print(f"Done: {written} files written to {args.export_dir}")
        return

    # Multi-device mode
    if args.devices:
        device_specs = [d.strip() for d in args.devices.split(",")]
        results_list = []
        for spec in device_specs:
            if ":" in spec:
                dhost, dport = spec.rsplit(":", 1)
            else:
                dhost, dport = spec, "5600"
            device_url = f"http://{dhost}:{dport}"
            if not args.json_output:
                print(f"Querying {device_url}...")
            try:
                result = analyze_range(
                    device_url, start, end, args.hostname,
                    quiet=args.json_output,
                )
                if result:
                    results_list.append(result)
                elif not args.json_output:
                    print(f"  Warning: no data from {device_url}", file=sys.stderr)
            except SystemExit:
                print(
                    f"  Warning: could not connect to {device_url}, skipping",
                    file=sys.stderr,
                )
                continue

        if not results_list:
            msg = "No data from any device."
            if args.json_output:
                print(json.dumps({"error": msg}))
            else:
                print(f"\n  {msg}")
            sys.exit(0)

        merged = merge_results(results_list)
        if args.json_output:
            output = dict(merged)
            output["start"] = merged["start"].isoformat()
            output["end"] = merged["end"].isoformat()
            print(json.dumps(output, indent=2))
        else:
            print_summary(merged, args)
        return

    # Single-server mode
    base_url = f"http://{args.host}:{args.port}"

    if not args.json_output:
        print(f"Connecting to ActivityWatch at {base_url}...")

    results = analyze_range(
        base_url, start, end, args.hostname, quiet=args.json_output
    )

    if results is None:
        msg = (f"No window events found for "
               f"{start.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')}.")
        if args.json_output:
            print(json.dumps({"error": msg}))
        else:
            print(f"\n  {msg}")
        sys.exit(0)

    if args.json_output:
        output = dict(results)
        output["start"] = results["start"].isoformat()
        output["end"] = results["end"].isoformat()
        print(json.dumps(output, indent=2))
    else:
        print_summary(results, args)


if __name__ == "__main__":
    main()
