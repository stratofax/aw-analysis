"""Tests for aw-analysis.py — ActivityWatch time analysis tool."""

import importlib
import json
import sys
from datetime import datetime, timedelta, timezone
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

# Import the module with a hyphenated filename
aw = importlib.import_module("aw-analysis")


# ── Fixtures ──────────────────────────────────────────────────────────


PST = timezone(timedelta(hours=-8))


def ts(h, m=0, s=0, tz=timezone.utc):
    """Shorthand for creating timestamps on 2026-02-28."""
    return datetime(2026, 2, 28, h, m, s, tzinfo=tz)


def make_event(timestamp, duration, data):
    """Create a mock AW event dict."""
    return {
        "timestamp": timestamp.isoformat(),
        "duration": duration,
        "data": data,
    }


def make_afk_event(timestamp, duration, status="not-afk"):
    return make_event(timestamp, duration, {"status": status})


def make_window_event(timestamp, duration, app, title=""):
    return make_event(timestamp, duration, {"app": app, "title": title})


def make_browser_event(timestamp, duration, url, title=""):
    return make_event(timestamp, duration, {"url": url, "title": title})


def make_editor_event(timestamp, duration, filepath):
    return make_event(timestamp, duration, {"file": filepath})


# ── _hostname_matches ─────────────────────────────────────────────────


class TestHostnameMatches:
    def test_exact_match_underscore(self):
        assert aw._hostname_matches("aw-watcher-window_Air4.local", "Air4.local")

    def test_exact_match_case_insensitive(self):
        assert aw._hostname_matches("aw-watcher-window_AIR4.LOCAL", "air4.local")

    def test_no_substring_match(self):
        """'air' should NOT match 'air4.local'."""
        assert not aw._hostname_matches("aw-watcher-window_air4.local", "air")

    def test_no_partial_suffix_match(self):
        """'4.local' should NOT match 'air4.local'."""
        assert not aw._hostname_matches("aw-watcher-window_air4.local", "4.local")

    def test_underscore_only_not_hyphen(self):
        """Hyphens are part of watcher name, not hostname delimiters."""
        assert not aw._hostname_matches("aw-watcher-web-brave-MyHost", "MyHost")
        assert aw._hostname_matches("aw-watcher-web-brave_MyHost", "MyHost")

    def test_no_match(self):
        assert not aw._hostname_matches("aw-watcher-window_host1", "host2")

    def test_empty_hostname(self):
        assert not aw._hostname_matches("aw-watcher-window_host", "")

    def test_bucket_with_no_delimiter(self):
        assert not aw._hostname_matches("aw-watcher-afk", "afk")


# ── _merge_intervals ─────────────────────────────────────────────────


class TestMergeIntervals:
    def test_empty(self):
        assert aw._merge_intervals([]) == []

    def test_single(self):
        intervals = [(ts(9), ts(10))]
        assert aw._merge_intervals(intervals) == intervals

    def test_non_overlapping(self):
        intervals = [(ts(9), ts(10)), (ts(11), ts(12))]
        assert aw._merge_intervals(intervals) == intervals

    def test_overlapping(self):
        intervals = [(ts(9), ts(10, 30)), (ts(10), ts(11))]
        expected = [(ts(9), ts(11))]
        assert aw._merge_intervals(intervals) == expected

    def test_adjacent(self):
        intervals = [(ts(9), ts(10)), (ts(10), ts(11))]
        expected = [(ts(9), ts(11))]
        assert aw._merge_intervals(intervals) == expected

    def test_contained(self):
        """Inner interval fully contained by outer."""
        intervals = [(ts(9), ts(12)), (ts(10), ts(11))]
        expected = [(ts(9), ts(12))]
        assert aw._merge_intervals(intervals) == expected

    def test_three_overlapping(self):
        intervals = [(ts(9), ts(10)), (ts(9, 30), ts(11)), (ts(10, 45), ts(12))]
        expected = [(ts(9), ts(12))]
        assert aw._merge_intervals(intervals) == expected


# ── parse_timestamp ───────────────────────────────────────────────────


class TestParseTimestamp:
    def test_utc_z(self):
        result = aw.parse_timestamp("2026-02-28T10:00:00Z")
        assert result == ts(10)

    def test_utc_offset(self):
        result = aw.parse_timestamp("2026-02-28T10:00:00+00:00")
        assert result == ts(10)

    def test_pst_offset(self):
        result = aw.parse_timestamp("2026-02-28T02:00:00-08:00")
        assert result == datetime(2026, 2, 28, 2, 0, 0, tzinfo=PST)

    def test_microseconds(self):
        result = aw.parse_timestamp("2026-02-28T10:00:00.123456+00:00")
        assert result.microsecond == 123456

    def test_no_timezone(self):
        result = aw.parse_timestamp("2026-02-28T10:00:00")
        assert result.tzinfo is not None


# ── format_duration ───────────────────────────────────────────────────


class TestFormatDuration:
    def test_seconds(self):
        assert aw.format_duration(45) == "45s"

    def test_minutes(self):
        assert aw.format_duration(150) == "2.5min"

    def test_hours(self):
        assert aw.format_duration(7200) == "2.0h"

    def test_zero(self):
        assert aw.format_duration(0) == "0s"

    def test_boundary_60(self):
        assert aw.format_duration(60) == "1.0min"

    def test_boundary_3600(self):
        assert aw.format_duration(3600) == "1.0h"


# ── format_pct ────────────────────────────────────────────────────────


class TestFormatPct:
    def test_half(self):
        assert aw.format_pct(50, 100) == "50.0%"

    def test_zero_total(self):
        assert aw.format_pct(10, 0) == "0%"

    def test_full(self):
        assert aw.format_pct(100, 100) == "100.0%"


# ── get_period_range ──────────────────────────────────────────────────


class TestGetPeriodRange:
    def test_day(self):
        ref = datetime(2026, 2, 28, 14, 30, 0, tzinfo=PST)
        start, end = aw.get_period_range("day", ref)
        assert start.hour == 0
        assert end.day == 1 and end.month == 3

    def test_week_monday_start(self):
        # 2026-02-28 is Saturday (weekday=5)
        ref = datetime(2026, 2, 28, 14, 30, 0, tzinfo=PST)
        start, end = aw.get_period_range("week", ref)
        assert start.weekday() == 0  # Monday
        assert (end - start).days == 7

    def test_month(self):
        ref = datetime(2026, 2, 15, 0, 0, 0, tzinfo=PST)
        start, end = aw.get_period_range("month", ref)
        assert start.day == 1 and start.month == 2
        assert end.day == 1 and end.month == 3

    def test_month_december(self):
        ref = datetime(2026, 12, 15, 0, 0, 0, tzinfo=PST)
        start, end = aw.get_period_range("month", ref)
        assert start.month == 12
        assert end.month == 1 and end.year == 2027

    def test_unknown_period(self):
        with pytest.raises(ValueError, match="Unknown period"):
            aw.get_period_range("quarter")


# ── compute_active_time ───────────────────────────────────────────────


class TestComputeActiveTime:
    def test_full_overlap(self):
        """Window event fully inside not-afk interval."""
        window = [make_window_event(ts(10), 300, "Firefox")]
        afk = [make_afk_event(ts(9), 7200)]
        result = aw.compute_active_time(window, afk)
        assert len(result) == 1
        assert result[0][0] == "Firefox"
        assert result[0][2] == 300

    def test_partial_overlap(self):
        """Window event partially overlaps not-afk interval."""
        window = [make_window_event(ts(9, 55), 600, "Code")]  # 9:55-10:05
        afk = [make_afk_event(ts(10), 3600)]  # 10:00-11:00
        result = aw.compute_active_time(window, afk)
        assert len(result) == 1
        assert result[0][2] == 300  # 5 minutes overlap

    def test_no_overlap(self):
        """Window event entirely during AFK."""
        window = [make_window_event(ts(8), 300, "Lock")]
        afk = [make_afk_event(ts(10), 3600)]  # much later
        result = aw.compute_active_time(window, afk)
        assert len(result) == 0

    def test_multiple_afk_intervals(self):
        """Window spans two not-afk intervals."""
        window = [make_window_event(ts(10), 7200, "Code")]  # 10:00-12:00
        afk = [
            make_afk_event(ts(10), 1800),   # 10:00-10:30
            make_afk_event(ts(11), 1800),   # 11:00-11:30
        ]
        result = aw.compute_active_time(window, afk)
        assert len(result) == 2
        total = sum(r[2] for r in result)
        assert total == 3600  # 30 + 30 min

    def test_overlapping_afk_merged(self):
        """Overlapping not-afk intervals should be merged, not double-counted."""
        window = [make_window_event(ts(10), 3600, "Code")]  # 10:00-11:00
        # Two overlapping not-afk intervals covering 10:00-11:00
        afk = [
            make_afk_event(ts(10), 1800),   # 10:00-10:30
            make_afk_event(ts(10, 15), 1800),  # 10:15-10:45 (overlaps!)
        ]
        result = aw.compute_active_time(window, afk)
        total = sum(r[2] for r in result)
        # Merged: 10:00-10:45 = 2700s, overlap with window 10:00-11:00 = 2700s
        assert total == 2700

    def test_afk_events_filtered(self):
        """Only not-afk events are used, afk events are ignored."""
        window = [make_window_event(ts(10), 3600, "Code")]
        afk = [
            make_afk_event(ts(10), 3600, status="afk"),
            make_afk_event(ts(10), 3600, status="not-afk"),
        ]
        result = aw.compute_active_time(window, afk)
        assert len(result) == 1

    def test_empty_events(self):
        assert aw.compute_active_time([], []) == []
        assert aw.compute_active_time([make_window_event(ts(10), 300, "X")], []) == []


# ── categorize_browser ────────────────────────────────────────────────


class TestCategorizeBrowser:
    def test_basic_url(self):
        events = [make_browser_event(ts(10), 60, "https://github.com/repo")]
        result = aw.categorize_browser(events, ts(9), ts(11))
        assert "github.com" in result
        assert result["github.com"] == 60

    def test_www_stripped(self):
        events = [make_browser_event(ts(10), 60, "https://www.example.com/page")]
        result = aw.categorize_browser(events, ts(9), ts(11))
        assert "example.com" in result

    def test_no_scheme(self):
        events = [make_browser_event(ts(10), 60, "just-text")]
        result = aw.categorize_browser(events, ts(9), ts(11))
        assert "(other)" in result

    def test_outside_range_excluded(self):
        events = [make_browser_event(ts(8), 60, "https://github.com")]
        result = aw.categorize_browser(events, ts(9), ts(11))
        assert len(result) == 0

    def test_multiple_domains_aggregated(self):
        events = [
            make_browser_event(ts(10), 30, "https://github.com/a"),
            make_browser_event(ts(10, 1), 30, "https://github.com/b"),
            make_browser_event(ts(10, 2), 60, "https://google.com/q"),
        ]
        result = aw.categorize_browser(events, ts(9), ts(11))
        assert result["github.com"] == 60
        assert result["google.com"] == 60

    def test_urlparse_handles_auth_in_url(self):
        """urlparse correctly handles user:pass@host."""
        events = [make_browser_event(ts(10), 60, "https://user:pass@site.com/path")]
        result = aw.categorize_browser(events, ts(9), ts(11))
        assert "site.com" in result

    def test_empty_url(self):
        events = [make_browser_event(ts(10), 60, "")]
        result = aw.categorize_browser(events, ts(9), ts(11))
        assert len(result) == 0


# ── categorize_editor ─────────────────────────────────────────────────


class TestCategorizeEditor:
    def test_markdown(self):
        events = [make_editor_event(ts(10), 60, "/home/neil/notes/diary.md")]
        cats, files = aw.categorize_editor(events, ts(9), ts(11))
        assert "writing" in cats

    def test_python(self):
        events = [make_editor_event(ts(10), 60, "/home/neil/project/main.py")]
        cats, files = aw.categorize_editor(events, ts(9), ts(11))
        assert "code" in cats

    def test_config(self):
        events = [make_editor_event(ts(10), 60, "/etc/config.yaml")]
        cats, files = aw.categorize_editor(events, ts(9), ts(11))
        assert "config" in cats

    def test_web(self):
        events = [make_editor_event(ts(10), 60, "/src/App.tsx")]
        cats, files = aw.categorize_editor(events, ts(9), ts(11))
        # tsx -> code (it's in the code extensions list)
        assert "code" in cats

    def test_html(self):
        events = [make_editor_event(ts(10), 60, "/src/index.html")]
        cats, files = aw.categorize_editor(events, ts(9), ts(11))
        assert "web" in cats

    def test_windows_backslash(self):
        events = [make_editor_event(ts(10), 60, "C:\\Users\\neil\\doc.md")]
        cats, files = aw.categorize_editor(events, ts(9), ts(11))
        assert "writing" in cats

    def test_no_extension(self):
        events = [make_editor_event(ts(10), 60, "/usr/bin/something")]
        cats, files = aw.categorize_editor(events, ts(9), ts(11))
        assert "other" in cats

    def test_outside_range(self):
        events = [make_editor_event(ts(8), 60, "/notes/file.md")]
        cats, files = aw.categorize_editor(events, ts(9), ts(11))
        assert len(cats) == 0

    def test_files_tracked(self):
        events = [
            make_editor_event(ts(10), 30, "/a.py"),
            make_editor_event(ts(10, 1), 20, "/a.py"),
        ]
        cats, files = aw.categorize_editor(events, ts(9), ts(11))
        assert files["/a.py"] == 50


# ── pick_bucket ───────────────────────────────────────────────────────


class TestPickBucket:
    def setup_method(self):
        self.buckets = {
            "currentwindow": [
                {"id": "aw-watcher-window_Air4.local", "hostname": "Air4.local", "client": "aw-watcher-window"},
                {"id": "aw-watcher-window_OtherHost", "hostname": "OtherHost", "client": "aw-watcher-window"},
            ],
            "afkstatus": [
                {"id": "aw-watcher-afk_Air4.local", "hostname": "Air4.local", "client": "aw-watcher-afk"},
            ],
        }

    @patch.object(aw, "get_local_hostname", return_value="Air4.local")
    def test_local_hostname_match(self, mock_host):
        result = aw.pick_bucket(self.buckets, "currentwindow")
        assert result == "aw-watcher-window_Air4.local"

    def test_explicit_hostname(self):
        result = aw.pick_bucket(self.buckets, "currentwindow", hostname="OtherHost")
        assert result == "aw-watcher-window_OtherHost"

    def test_missing_type(self):
        result = aw.pick_bucket(self.buckets, "nonexistent")
        assert result is None

    @patch.object(aw, "get_local_hostname", return_value="NoMatch")
    def test_fallback_to_known_hostname(self, mock_host):
        result = aw.pick_bucket(self.buckets, "currentwindow")
        # Falls back to first known-hostname candidate
        assert result == "aw-watcher-window_Air4.local"

    @patch.object(aw, "get_local_hostname", return_value="NoMatch")
    def test_fallback_prefers_known_over_unknown(self, mock_host):
        buckets = {
            "web.tab.current": [
                {"id": "aw-watcher-web", "hostname": "unknown", "client": "aw-watcher-web"},
                {"id": "aw-watcher-web_Host.local", "hostname": "Host.local", "client": "aw-watcher-web"},
            ]
        }
        result = aw.pick_bucket(buckets, "web.tab.current")
        assert result == "aw-watcher-web_Host.local"


# ── fetch_json ────────────────────────────────────────────────────────


class TestFetchJson:
    @patch("urllib.request.urlopen")
    def test_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"key": "value"}'
        mock_urlopen.return_value = mock_resp
        result = aw.fetch_json("http://localhost:5600/test")
        assert result == {"key": "value"}

    @patch("urllib.request.urlopen", side_effect=aw.urllib.error.URLError("timeout"))
    def test_url_error(self, mock_urlopen):
        result = aw.fetch_json("http://localhost:5600/test")
        assert result is None

    @patch("urllib.request.urlopen")
    def test_invalid_json(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"not json"
        mock_urlopen.return_value = mock_resp
        result = aw.fetch_json("http://localhost:5600/test")
        assert result is None

    @patch("urllib.request.urlopen")
    def test_custom_timeout(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"ok": true}'
        mock_urlopen.return_value = mock_resp
        aw.fetch_json("http://localhost:5600/test", timeout=60)
        mock_urlopen.assert_called_once_with("http://localhost:5600/test", timeout=60)


# ── fetch_events ──────────────────────────────────────────────────────


class TestFetchEvents:
    @patch.object(aw, "fetch_json", return_value=[{"event": 1}])
    def test_returns_events(self, mock_fetch):
        result = aw.fetch_events("http://localhost:5600", "bucket1", ts(9), ts(17))
        assert result == [{"event": 1}]

    @patch.object(aw, "fetch_json", return_value=None)
    def test_returns_empty_on_error(self, mock_fetch):
        result = aw.fetch_events("http://localhost:5600", "bucket1", ts(9), ts(17))
        assert result == []

    @patch.object(aw, "fetch_json")
    def test_truncation_warning(self, mock_fetch, capsys):
        mock_fetch.return_value = [{}] * 10000
        aw.fetch_events("http://localhost:5600", "test-bucket", ts(9), ts(17))
        err = capsys.readouterr().err
        assert "Warning" in err
        assert "10000" in err

    @patch.object(aw, "fetch_json")
    def test_no_warning_under_limit(self, mock_fetch, capsys):
        mock_fetch.return_value = [{}] * 500
        aw.fetch_events("http://localhost:5600", "test-bucket", ts(9), ts(17))
        err = capsys.readouterr().err
        assert err == ""


# ── discover_buckets ──────────────────────────────────────────────────


class TestDiscoverBuckets:
    @patch.object(aw, "fetch_json")
    def test_groups_by_type(self, mock_fetch):
        mock_fetch.return_value = {
            "aw-watcher-window_host": {"type": "currentwindow", "hostname": "host", "client": "c"},
            "aw-watcher-afk_host": {"type": "afkstatus", "hostname": "host", "client": "c"},
            "aw-watcher-unknown_host": {"type": "unknown-type", "hostname": "host", "client": "c"},
        }
        result = aw.discover_buckets("http://localhost:5600")
        assert "currentwindow" in result
        assert "afkstatus" in result
        assert "unknown-type" not in result

    @patch.object(aw, "fetch_json", return_value=None)
    def test_exits_on_connection_failure(self, mock_fetch):
        with pytest.raises(SystemExit):
            aw.discover_buckets("http://localhost:5600")


# ── main (integration) ───────────────────────────────────────────────


class TestMain:
    @patch.object(aw, "fetch_json")
    def test_version_flag(self, mock_fetch, capsys):
        with pytest.raises(SystemExit) as exc_info:
            sys.argv = ["aw-analysis.py", "--version"]
            aw.main()
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "0.2.0" in out

    @patch.object(aw, "fetch_json")
    def test_date_validation_bad_start(self, mock_fetch):
        sys.argv = ["aw-analysis.py", "--start", "not-a-date", "--end", "2026-02-28"]
        with pytest.raises(SystemExit) as exc_info:
            aw.main()
        assert exc_info.value.code == 2  # argparse error

    @patch.object(aw, "fetch_json")
    def test_date_validation_bad_end(self, mock_fetch):
        sys.argv = ["aw-analysis.py", "--start", "2026-02-28", "--end", "bogus"]
        with pytest.raises(SystemExit) as exc_info:
            aw.main()
        assert exc_info.value.code == 2

    @patch.object(aw, "fetch_json")
    def test_start_without_end(self, mock_fetch):
        sys.argv = ["aw-analysis.py", "--start", "2026-02-28"]
        with pytest.raises(SystemExit) as exc_info:
            aw.main()
        assert exc_info.value.code == 2

    @patch.object(aw, "fetch_json")
    def test_no_events_graceful_exit(self, mock_fetch):
        """When there are no window events, exit gracefully with message."""
        buckets_response = {
            "aw-watcher-window_Host": {"type": "currentwindow", "hostname": "Host", "client": "c"},
            "aw-watcher-afk_Host": {"type": "afkstatus", "hostname": "Host", "client": "c"},
        }
        # First call: buckets, second: window events (empty), third: afk events (empty)
        mock_fetch.side_effect = [buckets_response, [], []]
        sys.argv = ["aw-analysis.py", "--start", "2026-02-01", "--end", "2026-02-01"]
        with pytest.raises(SystemExit) as exc_info:
            aw.main()
        assert exc_info.value.code == 0


# ── print_summary ─────────────────────────────────────────────────────


class TestGetLocalHostname:
    @patch("socket.gethostname", return_value="Air4.local")
    def test_hostname_with_dot(self, mock_host):
        """Hostname already has a dot — no FQDN lookup."""
        assert aw.get_local_hostname() == "Air4.local"

    @patch("socket.getfqdn", return_value="flicky.localdomain")
    @patch("socket.gethostname", return_value="flicky")
    def test_hostname_without_dot_uses_fqdn(self, mock_host, mock_fqdn):
        """Short hostname — falls back to FQDN."""
        assert aw.get_local_hostname() == "flicky.localdomain"

    @patch("socket.getfqdn", return_value="flicky")
    @patch("socket.gethostname", return_value="flicky")
    def test_fqdn_same_as_hostname(self, mock_host, mock_fqdn):
        """FQDN same as hostname — returns original."""
        assert aw.get_local_hostname() == "flicky"


class TestParseTimestampFallback:
    def test_malformed_timestamp_fallback(self):
        """Trigger the ValueError fallback branch."""
        # This format triggers ValueError on Python 3.7-3.10 fromisoformat
        # but the fallback handles it
        result = aw.parse_timestamp("2026-02-28T10:00:00+00:00")
        assert result.hour == 10


class TestFetchJsonOSError:
    @patch("urllib.request.urlopen", side_effect=OSError("Connection refused"))
    def test_os_error(self, mock_urlopen, capsys):
        result = aw.fetch_json("http://localhost:5600/test")
        assert result is None
        err = capsys.readouterr().err
        assert "Connection refused" in err


class TestPickBucketAllUnknown:
    @patch.object(aw, "get_local_hostname", return_value="NoMatch")
    def test_all_unknown_returns_first(self, mock_host):
        """When all candidates have 'unknown' hostname, return first."""
        buckets = {
            "currentwindow": [
                {"id": "aw-watcher-window", "hostname": "unknown", "client": "c"},
            ]
        }
        result = aw.pick_bucket(buckets, "currentwindow")
        assert result == "aw-watcher-window"


class TestMainIntegration:
    """Integration tests for the main() function covering the full happy path."""

    def _make_buckets_response(self):
        return {
            "aw-watcher-window_Host": {
                "type": "currentwindow", "hostname": "Host", "client": "c",
            },
            "aw-watcher-afk_Host": {
                "type": "afkstatus", "hostname": "Host", "client": "c",
            },
            "aw-watcher-web_Host": {
                "type": "web.tab.current", "hostname": "Host", "client": "c",
            },
            "aw-watcher-editor_Host": {
                "type": "app.editor.activity", "hostname": "Host", "client": "c",
            },
        }

    def _make_window_events(self):
        return [
            make_window_event(ts(10), 1800, "Firefox", "GitHub"),
            make_window_event(ts(10, 30), 1800, "Code", "main.py"),
        ]

    def _make_afk_events(self):
        return [
            make_afk_event(ts(10), 3600),  # 10:00-11:00 not-afk
            make_afk_event(ts(11), 3600, status="afk"),  # 11:00-12:00 afk
        ]

    def _make_browser_events(self):
        return [
            make_browser_event(ts(10), 900, "https://github.com/repo"),
            make_browser_event(ts(10, 15), 600, "https://google.com/search"),
        ]

    def _make_editor_events(self):
        return [
            make_editor_event(ts(10, 30), 900, "/project/main.py"),
            make_editor_event(ts(10, 45), 600, "/notes/diary.md"),
        ]

    @patch.object(aw, "get_local_hostname", return_value="Host")
    @patch.object(aw, "fetch_json")
    def test_full_happy_path_human(self, mock_fetch, mock_host, capsys):
        """Full happy path with human-readable output."""
        mock_fetch.side_effect = [
            self._make_buckets_response(),  # discover_buckets
            self._make_window_events(),     # window events
            self._make_afk_events(),        # afk events
            self._make_browser_events(),    # browser events
            self._make_editor_events(),     # editor events
        ]
        sys.argv = ["aw-analysis.py", "--start", "2026-02-28", "--end", "2026-02-28"]
        aw.main()
        out = capsys.readouterr().out
        assert "ActivityWatch Analysis" in out
        assert "Firefox" in out
        assert "Code" in out
        assert "github.com" in out

    @patch.object(aw, "get_local_hostname", return_value="Host")
    @patch.object(aw, "fetch_json")
    def test_full_happy_path_json(self, mock_fetch, mock_host, capsys):
        """Full happy path with JSON output."""
        mock_fetch.side_effect = [
            self._make_buckets_response(),
            self._make_window_events(),
            self._make_afk_events(),
            self._make_browser_events(),
            self._make_editor_events(),
        ]
        sys.argv = [
            "aw-analysis.py", "--start", "2026-02-28",
            "--end", "2026-02-28", "--json",
        ]
        aw.main()
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "active_by_app" in data
        assert "browser_domains" in data
        assert "editor_categories" in data
        assert data["hostname"] == "Host"

    @patch.object(aw, "get_local_hostname", return_value="Host")
    @patch.object(aw, "fetch_json")
    def test_missing_window_bucket_exits(self, mock_fetch, mock_host):
        """When no window bucket found, exit with error."""
        mock_fetch.return_value = {
            "aw-watcher-afk_Host": {
                "type": "afkstatus", "hostname": "Host", "client": "c",
            },
        }
        sys.argv = ["aw-analysis.py", "--start", "2026-02-28", "--end", "2026-02-28"]
        with pytest.raises(SystemExit) as exc_info:
            aw.main()
        assert exc_info.value.code == 1

    @patch.object(aw, "get_local_hostname", return_value="Host")
    @patch.object(aw, "fetch_json")
    def test_no_events_json_output(self, mock_fetch, mock_host, capsys):
        """No window events with --json outputs JSON error."""
        mock_fetch.side_effect = [
            self._make_buckets_response(),
            [],  # empty window events
            self._make_afk_events(),
        ]
        sys.argv = [
            "aw-analysis.py", "--start", "2026-02-28",
            "--end", "2026-02-28", "--json",
        ]
        with pytest.raises(SystemExit) as exc_info:
            aw.main()
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "error" in data

    @patch.object(aw, "get_local_hostname", return_value="Host")
    @patch.object(aw, "fetch_json")
    def test_no_browser_or_editor_buckets(self, mock_fetch, mock_host, capsys):
        """Works fine without browser or editor buckets."""
        buckets = {
            "aw-watcher-window_Host": {
                "type": "currentwindow", "hostname": "Host", "client": "c",
            },
            "aw-watcher-afk_Host": {
                "type": "afkstatus", "hostname": "Host", "client": "c",
            },
        }
        mock_fetch.side_effect = [
            buckets,
            self._make_window_events(),
            self._make_afk_events(),
        ]
        sys.argv = ["aw-analysis.py", "--start", "2026-02-28", "--end", "2026-02-28"]
        aw.main()
        out = capsys.readouterr().out
        assert "ActivityWatch Analysis" in out

    @patch.object(aw, "get_local_hostname", return_value="Host")
    @patch.object(aw, "fetch_json")
    def test_afk_clipping(self, mock_fetch, mock_host, capsys):
        """AFK events spanning range boundaries get clipped."""
        mock_fetch.side_effect = [
            self._make_buckets_response(),
            self._make_window_events(),
            # AFK event starts BEFORE the range and extends into it
            [make_afk_event(ts(8), 14400)],  # 8:00-12:00 not-afk (4h)
            [],  # browser
            [],  # editor
        ]
        sys.argv = [
            "aw-analysis.py", "--start", "2026-02-28",
            "--end", "2026-02-28", "--json",
        ]
        aw.main()
        out = capsys.readouterr().out
        data = json.loads(out)
        # Active seconds should be clipped — not the full 14400
        assert data["afk_summary"]["active_seconds"] <= 86400  # max 24h


class TestPrintSummary:
    def test_basic_output(self, capsys):
        results = {
            "start": ts(0),
            "end": ts(23, 59, 59),
            "hostname": "TestHost",
            "buckets_used": ["window_TestHost", "afk_TestHost"],
            "afk_summary": {
                "active_seconds": 3600,
                "afk_seconds": 1800,
                "total_seconds": 5400,
                "active_ratio": 0.667,
            },
            "active_by_app": {"Firefox": 2400, "Code": 1200},
            "browser_domains": {"github.com": 1200, "google.com": 600},
            "editor_categories": {"code": 900, "writing": 300},
            "editor_files": {},
        }
        aw.print_summary(results, MagicMock(json_output=False))
        out = capsys.readouterr().out
        assert "ActivityWatch Analysis" in out
        assert "Firefox" in out
        assert "github.com" in out

    def test_empty_results(self, capsys):
        results = {
            "start": ts(0),
            "end": ts(23, 59, 59),
            "hostname": "TestHost",
            "buckets_used": [],
            "afk_summary": {},
            "active_by_app": {},
            "browser_domains": {},
            "editor_categories": {},
            "editor_files": {},
        }
        aw.print_summary(results, MagicMock(json_output=False))
        out = capsys.readouterr().out
        assert "ActivityWatch Analysis" in out


# ── --host flag ──────────────────────────────────────────────────────


class TestHostFlag:
    @patch.object(aw, "get_local_hostname", return_value="Host")
    @patch.object(aw, "fetch_json")
    def test_host_default_localhost(self, mock_fetch, mock_host, capsys):
        """Default --host is localhost."""
        buckets_response = {
            "aw-watcher-window_Host": {
                "type": "currentwindow", "hostname": "Host", "client": "c",
            },
            "aw-watcher-afk_Host": {
                "type": "afkstatus", "hostname": "Host", "client": "c",
            },
        }
        mock_fetch.side_effect = [
            buckets_response,
            [make_window_event(ts(10), 1800, "Code")],
            [make_afk_event(ts(10), 3600)],
        ]
        sys.argv = ["aw-analysis.py", "--start", "2026-02-28", "--end", "2026-02-28"]
        aw.main()
        out = capsys.readouterr().out
        assert "localhost" in out

    @patch.object(aw, "get_local_hostname", return_value="Host")
    @patch.object(aw, "fetch_json")
    def test_host_custom(self, mock_fetch, mock_host, capsys):
        """--host uses custom hostname in URL."""
        buckets_response = {
            "aw-watcher-window_Host": {
                "type": "currentwindow", "hostname": "Host", "client": "c",
            },
            "aw-watcher-afk_Host": {
                "type": "afkstatus", "hostname": "Host", "client": "c",
            },
        }
        mock_fetch.side_effect = [
            buckets_response,
            [make_window_event(ts(10), 1800, "Code")],
            [make_afk_event(ts(10), 3600)],
        ]
        sys.argv = [
            "aw-analysis.py", "--host", "myremote",
            "--start", "2026-02-28", "--end", "2026-02-28",
        ]
        aw.main()
        out = capsys.readouterr().out
        assert "myremote" in out

    @patch.object(aw, "get_local_hostname", return_value="Host")
    @patch.object(aw, "fetch_json")
    def test_host_with_port(self, mock_fetch, mock_host, capsys):
        """--host combined with --port."""
        buckets_response = {
            "aw-watcher-window_Host": {
                "type": "currentwindow", "hostname": "Host", "client": "c",
            },
            "aw-watcher-afk_Host": {
                "type": "afkstatus", "hostname": "Host", "client": "c",
            },
        }
        mock_fetch.side_effect = [
            buckets_response,
            [make_window_event(ts(10), 1800, "Code")],
            [make_afk_event(ts(10), 3600)],
        ]
        sys.argv = [
            "aw-analysis.py", "--host", "messier4.lan", "--port", "5601",
            "--start", "2026-02-28", "--end", "2026-02-28",
        ]
        aw.main()
        out = capsys.readouterr().out
        assert "messier4.lan:5601" in out


# ── analyze_range ────────────────────────────────────────────────────


class TestAnalyzeRange:
    def _make_buckets_response(self):
        return {
            "aw-watcher-window_Host": {
                "type": "currentwindow", "hostname": "Host", "client": "c",
            },
            "aw-watcher-afk_Host": {
                "type": "afkstatus", "hostname": "Host", "client": "c",
            },
        }

    @patch.object(aw, "fetch_json")
    def test_returns_results_dict(self, mock_fetch):
        mock_fetch.side_effect = [
            self._make_buckets_response(),
            [make_window_event(ts(10), 1800, "Code")],
            [make_afk_event(ts(10), 3600)],
        ]
        result = aw.analyze_range("http://localhost:5600", ts(0), ts(23, 59, 59))
        assert result is not None
        assert "active_by_app" in result
        assert "Code" in result["active_by_app"]

    @patch.object(aw, "fetch_json")
    def test_returns_none_no_events(self, mock_fetch):
        mock_fetch.side_effect = [
            self._make_buckets_response(),
            [],  # no window events
            [make_afk_event(ts(10), 3600)],
        ]
        result = aw.analyze_range("http://localhost:5600", ts(0), ts(23, 59, 59))
        assert result is None

    @patch.object(aw, "fetch_json")
    def test_with_hostname(self, mock_fetch):
        mock_fetch.side_effect = [
            self._make_buckets_response(),
            [make_window_event(ts(10), 1800, "Code")],
            [make_afk_event(ts(10), 3600)],
        ]
        result = aw.analyze_range(
            "http://localhost:5600", ts(0), ts(23, 59, 59), hostname="Host"
        )
        assert result is not None
        assert result["hostname"] == "Host"

    @patch.object(aw, "fetch_json")
    def test_quiet_mode(self, mock_fetch, capsys):
        mock_fetch.side_effect = [
            self._make_buckets_response(),
            [make_window_event(ts(10), 1800, "Code")],
            [make_afk_event(ts(10), 3600)],
        ]
        aw.analyze_range(
            "http://localhost:5600", ts(0), ts(23, 59, 59), quiet=True
        )
        out = capsys.readouterr().out
        assert "Window events" not in out

    @patch.object(aw, "fetch_json")
    def test_verbose_mode(self, mock_fetch, capsys):
        mock_fetch.side_effect = [
            self._make_buckets_response(),
            [make_window_event(ts(10), 1800, "Code")],
            [make_afk_event(ts(10), 3600)],
        ]
        aw.analyze_range(
            "http://localhost:5600", ts(0), ts(23, 59, 59), quiet=False
        )
        out = capsys.readouterr().out
        assert "Window events" in out


# ── pick_buckets_multi ───────────────────────────────────────────────


class TestPickBucketsMulti:
    def setup_method(self):
        self.buckets = {
            "currentwindow": [
                {"id": "aw-watcher-window_Messier4.local", "hostname": "Messier4.local", "client": "c"},
                {"id": "aw-watcher-window_messier4.lan", "hostname": "messier4.lan", "client": "c"},
                {"id": "aw-watcher-window_garand.local", "hostname": "garand.local", "client": "c"},
                {"id": "aw-watcher-window_Air4.local", "hostname": "Air4.local", "client": "c"},
            ],
        }

    def test_matches_multiple_hostnames(self):
        result = aw.pick_buckets_multi(
            self.buckets, "currentwindow",
            ["Messier4.local", "messier4.lan", "garand.local"]
        )
        assert len(result) == 3
        assert "aw-watcher-window_Messier4.local" in result
        assert "aw-watcher-window_messier4.lan" in result
        assert "aw-watcher-window_garand.local" in result

    def test_no_duplicates(self):
        result = aw.pick_buckets_multi(
            self.buckets, "currentwindow",
            ["Messier4.local", "Messier4.local"]
        )
        assert len(result) == 1

    def test_no_match_returns_empty(self):
        result = aw.pick_buckets_multi(
            self.buckets, "currentwindow", ["nonexistent"]
        )
        assert result == []

    def test_empty_bucket_type(self):
        result = aw.pick_buckets_multi(self.buckets, "afkstatus", ["Messier4.local"])
        assert result == []

    def test_excludes_non_matching(self):
        result = aw.pick_buckets_multi(
            self.buckets, "currentwindow",
            ["Messier4.local", "garand.local"]
        )
        assert "aw-watcher-window_Air4.local" not in result


# ── fetch_events_multi ───────────────────────────────────────────────


class TestFetchEventsMulti:
    @patch.object(aw, "fetch_events")
    def test_merges_events(self, mock_fetch):
        mock_fetch.side_effect = [
            [{"event": 1}, {"event": 2}],
            [{"event": 3}],
        ]
        result = aw.fetch_events_multi(
            "http://localhost:5600", ["bucket1", "bucket2"], ts(0), ts(23)
        )
        assert len(result) == 3

    @patch.object(aw, "fetch_events")
    def test_empty_buckets(self, mock_fetch):
        result = aw.fetch_events_multi(
            "http://localhost:5600", [], ts(0), ts(23)
        )
        assert result == []

    @patch.object(aw, "fetch_events")
    def test_single_bucket(self, mock_fetch):
        mock_fetch.return_value = [{"event": 1}]
        result = aw.fetch_events_multi(
            "http://localhost:5600", ["bucket1"], ts(0), ts(23)
        )
        assert len(result) == 1


# ── multi-hostname via analyze_range ─────────────────────────────────


class TestMultiHostname:
    @patch.object(aw, "fetch_json")
    def test_comma_separated_hostname(self, mock_fetch):
        buckets = {
            "aw-watcher-window_Messier4.local": {
                "type": "currentwindow", "hostname": "Messier4.local", "client": "c",
            },
            "aw-watcher-window_garand.local": {
                "type": "currentwindow", "hostname": "garand.local", "client": "c",
            },
            "aw-watcher-afk_Messier4.local": {
                "type": "afkstatus", "hostname": "Messier4.local", "client": "c",
            },
            "aw-watcher-afk_garand.local": {
                "type": "afkstatus", "hostname": "garand.local", "client": "c",
            },
        }
        mock_fetch.side_effect = [
            buckets,
            # window events from 2 buckets
            [make_window_event(ts(10), 1800, "Code")],
            [make_window_event(ts(11), 1800, "Firefox")],
            # afk events from 2 buckets
            [make_afk_event(ts(10), 7200)],
            [make_afk_event(ts(10), 7200)],
        ]
        result = aw.analyze_range(
            "http://localhost:5600", ts(0), ts(23, 59, 59),
            hostname="Messier4.local,garand.local",
        )
        assert result is not None
        assert "Code" in result["active_by_app"]
        assert "Firefox" in result["active_by_app"]
        assert result["hostname"] == "Messier4.local"

    @patch.object(aw, "fetch_json")
    def test_single_hostname_unchanged(self, mock_fetch):
        buckets = {
            "aw-watcher-window_Host": {
                "type": "currentwindow", "hostname": "Host", "client": "c",
            },
            "aw-watcher-afk_Host": {
                "type": "afkstatus", "hostname": "Host", "client": "c",
            },
        }
        mock_fetch.side_effect = [
            buckets,
            [make_window_event(ts(10), 1800, "Code")],
            [make_afk_event(ts(10), 3600)],
        ]
        result = aw.analyze_range(
            "http://localhost:5600", ts(0), ts(23, 59, 59),
            hostname="Host",
        )
        assert result is not None
        assert result["hostname"] == "Host"

    @patch.object(aw, "fetch_json")
    def test_multi_hostname_no_match(self, mock_fetch):
        buckets = {
            "aw-watcher-window_Host": {
                "type": "currentwindow", "hostname": "Host", "client": "c",
            },
            "aw-watcher-afk_Host": {
                "type": "afkstatus", "hostname": "Host", "client": "c",
            },
        }
        mock_fetch.return_value = buckets
        result = aw.analyze_range(
            "http://localhost:5600", ts(0), ts(23, 59, 59),
            hostname="nonexistent1,nonexistent2",
        )
        assert result is None


# ── merge_results ────────────────────────────────────────────────────


class TestMergeResults:
    def _make_result(self, hostname, active_secs, apps):
        return {
            "start": ts(0),
            "end": ts(23, 59, 59),
            "hostname": hostname,
            "buckets_used": [f"aw-watcher-window_{hostname}"],
            "afk_summary": {
                "active_seconds": active_secs,
                "afk_seconds": 1000,
                "total_seconds": active_secs + 1000,
                "active_ratio": active_secs / (active_secs + 1000),
            },
            "active_by_app": apps,
            "browser_domains": {},
            "editor_categories": {},
            "editor_files": {},
        }

    def test_merge_two_devices(self):
        r1 = self._make_result("Air4", 3600, {"Code": 2400, "Firefox": 1200})
        r2 = self._make_result("Messier4", 1800, {"Code": 1200, "iTerm2": 600})
        merged = aw.merge_results([r1, r2])
        assert merged["hostname"] == "multi-device"
        assert merged["active_by_app"]["Code"] == 3600
        assert merged["active_by_app"]["Firefox"] == 1200
        assert merged["active_by_app"]["iTerm2"] == 600
        assert merged["afk_summary"]["active_seconds"] == 5400

    def test_merge_preserves_devices_array(self):
        r1 = self._make_result("Air4", 3600, {"Code": 3600})
        r2 = self._make_result("Messier4", 1800, {"Code": 1800})
        merged = aw.merge_results([r1, r2])
        assert "devices" in merged
        assert len(merged["devices"]) == 2
        assert merged["devices"][0]["hostname"] == "Air4"
        assert merged["devices"][1]["hostname"] == "Messier4"

    def test_merge_empty_returns_none(self):
        assert aw.merge_results([]) is None

    def test_merge_single_device(self):
        r1 = self._make_result("Air4", 3600, {"Code": 3600})
        merged = aw.merge_results([r1])
        assert merged["active_by_app"]["Code"] == 3600
        assert len(merged["devices"]) == 1

    def test_merge_browser_domains(self):
        r1 = self._make_result("Air4", 3600, {})
        r1["browser_domains"] = {"github.com": 100, "google.com": 50}
        r2 = self._make_result("Messier4", 1800, {})
        r2["browser_domains"] = {"github.com": 200, "reddit.com": 30}
        merged = aw.merge_results([r1, r2])
        assert merged["browser_domains"]["github.com"] == 300
        assert merged["browser_domains"]["google.com"] == 50
        assert merged["browser_domains"]["reddit.com"] == 30


# ── --export-dir ─────────────────────────────────────────────────────


class TestExportDir:
    @patch.object(aw, "fetch_json")
    def test_export_creates_files(self, mock_fetch, tmp_path):
        buckets = {
            "aw-watcher-window_Host": {
                "type": "currentwindow", "hostname": "Host", "client": "c",
            },
            "aw-watcher-afk_Host": {
                "type": "afkstatus", "hostname": "Host", "client": "c",
            },
        }
        mock_fetch.side_effect = [
            buckets,
            [make_window_event(ts(10), 1800, "Code")],
            [make_afk_event(ts(10), 3600)],
        ]
        export_dir = str(tmp_path / "export")
        written = aw.export_days(
            "http://localhost:5600",
            ts(0), ts(23, 59, 59),
            export_dir,
        )
        assert written == 1
        filepath = tmp_path / "export" / "2026-02-28.json"
        assert filepath.exists()
        data = json.loads(filepath.read_text())
        assert "active_by_app" in data
        assert "Code" in data["active_by_app"]

    @patch.object(aw, "fetch_json")
    def test_export_skips_empty_days(self, mock_fetch, tmp_path):
        buckets = {
            "aw-watcher-window_Host": {
                "type": "currentwindow", "hostname": "Host", "client": "c",
            },
            "aw-watcher-afk_Host": {
                "type": "afkstatus", "hostname": "Host", "client": "c",
            },
        }
        # Day 1: no data, Day 2: has data
        mock_fetch.side_effect = [
            # Day 1
            buckets,
            [],  # no window events
            [make_afk_event(ts(10), 3600)],
            # Day 2
            buckets,
            [make_window_event(ts(10), 1800, "Code")],
            [make_afk_event(ts(10), 3600)],
        ]
        local_tz = timezone(timedelta(hours=0))
        day1_start = datetime(2026, 2, 27, 0, 0, 0, tzinfo=local_tz)
        day2_end = datetime(2026, 2, 28, 23, 59, 59, 999999, tzinfo=local_tz)
        export_dir = str(tmp_path / "export")
        written = aw.export_days(
            "http://localhost:5600", day1_start, day2_end, export_dir,
        )
        assert written == 1
        assert not (tmp_path / "export" / "2026-02-27.json").exists()
        assert (tmp_path / "export" / "2026-02-28.json").exists()

    @patch.object(aw, "fetch_json")
    def test_export_json_format_matches_reference(self, mock_fetch, tmp_path):
        """Exported JSON has the same top-level keys as reference format."""
        buckets = {
            "aw-watcher-window_Host": {
                "type": "currentwindow", "hostname": "Host", "client": "c",
            },
            "aw-watcher-afk_Host": {
                "type": "afkstatus", "hostname": "Host", "client": "c",
            },
        }
        mock_fetch.side_effect = [
            buckets,
            [make_window_event(ts(10), 1800, "Firefox")],
            [make_afk_event(ts(10), 3600)],
        ]
        export_dir = str(tmp_path / "export")
        aw.export_days(
            "http://localhost:5600", ts(0), ts(23, 59, 59), export_dir,
        )
        data = json.loads((tmp_path / "export" / "2026-02-28.json").read_text())
        expected_keys = {
            "start", "end", "hostname", "buckets_used", "afk_summary",
            "active_by_app", "browser_domains", "editor_categories",
            "editor_files",
        }
        assert set(data.keys()) == expected_keys

    @patch.object(aw, "fetch_json")
    def test_export_with_hostname(self, mock_fetch, tmp_path):
        buckets = {
            "aw-watcher-window_Custom": {
                "type": "currentwindow", "hostname": "Custom", "client": "c",
            },
            "aw-watcher-afk_Custom": {
                "type": "afkstatus", "hostname": "Custom", "client": "c",
            },
        }
        mock_fetch.side_effect = [
            buckets,
            [make_window_event(ts(10), 1800, "Code")],
            [make_afk_event(ts(10), 3600)],
        ]
        export_dir = str(tmp_path / "export")
        aw.export_days(
            "http://localhost:5600",
            ts(0), ts(23, 59, 59),
            export_dir,
            hostname="Custom",
        )
        data = json.loads((tmp_path / "export" / "2026-02-28.json").read_text())
        assert data["hostname"] == "Custom"

    @patch.object(aw, "fetch_json")
    def test_export_dir_requires_start_end(self, mock_fetch):
        sys.argv = ["aw-analysis.py", "--export-dir", "/tmp/test"]
        with pytest.raises(SystemExit) as exc_info:
            aw.main()
        assert exc_info.value.code == 2


# ── --devices flag ───────────────────────────────────────────────────


class TestDevicesFlag:
    def _make_buckets(self, hostname):
        return {
            f"aw-watcher-window_{hostname}": {
                "type": "currentwindow", "hostname": hostname, "client": "c",
            },
            f"aw-watcher-afk_{hostname}": {
                "type": "afkstatus", "hostname": hostname, "client": "c",
            },
        }

    @patch.object(aw, "fetch_json")
    def test_devices_mutually_exclusive_with_host(self, mock_fetch):
        sys.argv = [
            "aw-analysis.py", "--devices", "a:5600,b:5601",
            "--host", "custom",
            "--start", "2026-02-28", "--end", "2026-02-28",
        ]
        with pytest.raises(SystemExit) as exc_info:
            aw.main()
        assert exc_info.value.code == 2

    @patch.object(aw, "fetch_json")
    def test_devices_two_servers_json(self, mock_fetch, capsys):
        mock_fetch.side_effect = [
            # Device 1
            self._make_buckets("Air4"),
            [make_window_event(ts(10), 1800, "Code")],
            [make_afk_event(ts(10), 3600)],
            # Device 2
            self._make_buckets("Messier4"),
            [make_window_event(ts(10), 900, "iTerm2")],
            [make_afk_event(ts(10), 3600)],
        ]
        sys.argv = [
            "aw-analysis.py", "--devices", "localhost:5600,localhost:5601",
            "--start", "2026-02-28", "--end", "2026-02-28", "--json",
        ]
        aw.main()
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "devices" in data
        assert len(data["devices"]) == 2
        assert data["active_by_app"]["Code"] == 1800
        assert data["active_by_app"]["iTerm2"] == 900

    @patch.object(aw, "fetch_json")
    def test_devices_human_output(self, mock_fetch, capsys):
        mock_fetch.side_effect = [
            self._make_buckets("Air4"),
            [make_window_event(ts(10), 1800, "Code")],
            [make_afk_event(ts(10), 3600)],
        ]
        sys.argv = [
            "aw-analysis.py", "--devices", "localhost:5600",
            "--start", "2026-02-28", "--end", "2026-02-28",
        ]
        aw.main()
        out = capsys.readouterr().out
        assert "ActivityWatch Analysis" in out

    @patch.object(aw, "fetch_json")
    def test_devices_one_failing(self, mock_fetch, capsys):
        """One device fails, other succeeds — warning printed, data from good device."""
        mock_fetch.side_effect = [
            None,  # Device 1 fails → discover_buckets calls sys.exit(1)
            self._make_buckets("Messier4"),
            [make_window_event(ts(10), 1800, "Code")],
            [make_afk_event(ts(10), 3600)],
        ]
        sys.argv = [
            "aw-analysis.py", "--devices", "badhost:5600,localhost:5601",
            "--start", "2026-02-28", "--end", "2026-02-28", "--json",
        ]
        aw.main()
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "Code" in data["active_by_app"]

    @patch.object(aw, "fetch_json")
    def test_devices_all_failing(self, mock_fetch, capsys):
        """All devices fail — error reported."""
        mock_fetch.return_value = None  # All fail
        sys.argv = [
            "aw-analysis.py", "--devices", "bad1:5600,bad2:5601",
            "--start", "2026-02-28", "--end", "2026-02-28", "--json",
        ]
        with pytest.raises(SystemExit) as exc_info:
            aw.main()
        assert exc_info.value.code == 0

    @patch.object(aw, "fetch_json")
    def test_devices_no_data_from_server(self, mock_fetch, capsys):
        """Server connects but has no events."""
        mock_fetch.side_effect = [
            self._make_buckets("Host"),
            [],  # no window events
            [make_afk_event(ts(10), 3600)],
        ]
        sys.argv = [
            "aw-analysis.py", "--devices", "localhost:5600",
            "--start", "2026-02-28", "--end", "2026-02-28", "--json",
        ]
        with pytest.raises(SystemExit) as exc_info:
            aw.main()
        assert exc_info.value.code == 0

    @patch.object(aw, "fetch_json")
    def test_devices_default_port(self, mock_fetch, capsys):
        """Device spec without port defaults to 5600."""
        mock_fetch.side_effect = [
            self._make_buckets("Host"),
            [make_window_event(ts(10), 1800, "Code")],
            [make_afk_event(ts(10), 3600)],
        ]
        sys.argv = [
            "aw-analysis.py", "--devices", "localhost",
            "--start", "2026-02-28", "--end", "2026-02-28", "--json",
        ]
        aw.main()
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "Code" in data["active_by_app"]
