"""WAS scan-export analyzer: deterministic diagnoses and setting changes.

Fixtures are synthetic (Tenable does not publish the export schema) but follow
the documented plugin meanings; the reader is deliberately layout-tolerant.
"""
from __future__ import annotations

import io
import json
import zipfile

import pytest

from app.services.scan_analysis import analyze
from app.services.scan_export_parser import ScanExportError, as_zip, parse_export


def _zip(**files) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name.replace("__", "/").replace("_DOT_", "."), content)
    return buf.getvalue()


def _report(findings, settings=None) -> str:
    return json.dumps({"config": {"settings": settings or {}}, "findings": findings})


def _f(pid, uri="https://app.example.com/", output=""):
    return {"plugin_id": pid, "uri": uri, "output": output, "severity": "info"}


def _ids(result):
    return {r["id"] for r in result["recommendations"]}


def _changes(result, setting):
    return [c for r in result["recommendations"] for c in r["changes"] if c["setting"] == setting]


def test_failed_login_is_critical_and_selenium_errors_are_counted_not_copied():
    log = "step 3 type #password value=Hunter2!\nNoSuchElementException: #password\nTimeoutException waiting\n"
    data = _zip(report_DOT_json=_report([_f(98142)]), selenium_DOT_log=log)
    r = analyze(data)
    assert r["facts"]["authentication"] == "failed"
    assert r["recommendations"][0]["id"] == "auth_failed"
    assert {"selenium_errors"} <= _ids(r)
    assert r["facts"]["selenium_errors"] == {"NoSuchElementException": 1, "TimeoutException": 1}
    assert "Hunter2" not in json.dumps(r)


def test_logout_abort_suggests_excluding_the_signout_url_seen_in_the_sitemap():
    sitemap = "url,status,reason\nhttps://app.example.com/account/signout?t=abc,302,\nhttps://app.example.com/home,200,\n"
    r = analyze(_zip(report_DOT_json=_report([_f(98044), _f(98141)]), sitemap_DOT_csv=sitemap))
    rec = next(x for x in r["recommendations"] if x["id"] == "logged_out_abort")
    assert rec["severity"] == "critical"
    assert any(c["value"] == "/account/signout" for c in rec["changes"])
    assert "t=abc" not in json.dumps(r)  # query strings never reach the analysis


def test_pattern_found_unauthenticated():
    assert "pattern_unauthenticated" in _ids(analyze(_zip(r_DOT_json=_report([_f(114247)]))))


def test_sitemap_reasons_map_to_limits():
    rows = ["url,queued,reason"]
    rows += [f"https://app.example.com/p{i},no,queue_full" for i in range(30)]
    rows += [f"https://app.example.com/a/b/c/d/e/f/g/h/i/j/k/{i},no,directory_depth" for i in range(5)]
    rows += [f"https://app.example.com/big{i},yes,scan_timelimit_reached" for i in range(3)]
    r = analyze(_zip(sitemap_DOT_csv="\n".join(rows), report_DOT_json=_report([_f(98141)])))
    assert r["facts"]["sitemap_reasons"] == {"queue_full": 30, "directory_depth": 5, "scan_timelimit_reached": 3}
    assert _changes(r, "Number of URLS to Crawl and Browse")[0]["value"] == "20000"
    assert _changes(r, "Path Directory Depth")[0]["value"] == "15"
    assert _changes(r, "Target Scan Max Time (HH:MM:SS)")[0]["value"] == "16:00:00"


def test_current_settings_make_changes_real_changes():
    settings = {"scope": {"exclude_path_patterns": ["logout", "/account/signout"]},
                "max_spider_urls": 20000, "request_max_rate": 8, "timeout": "16:00:00", "password": "x"}
    rows = ["url,reason"] + [f"https://app.example.com/p{i},queue_full" for i in range(20)]
    rows += ["https://app.example.com/account/signout,", "https://app.example.com/z,scan_timelimit_reached"]
    findings = [_f(98043), _f(98141), _f(98137)]
    r = analyze(_zip(report_DOT_json=_report(findings, settings), sitemap_DOT_csv="\n".join(rows)))
    assert r["facts"]["current_settings"]["Max Number of HTTP Requests Per Second"] == 8
    assert "password" not in json.dumps(r["facts"]["current_settings"]).lower()
    assert not [c for c in _changes(r, "Regex for Excluded URLs") if c["value"] == "/account/signout"]  # already set
    assert _changes(r, "Number of URLS to Crawl and Browse")[0] == {
        **_changes(r, "Number of URLS to Crawl and Browse")[0], "current": "20000", "value": "40000"}
    assert _changes(r, "Max Number of HTTP Requests Per Second")[0]["value"] == "4"  # already below 10: halve
    assert _changes(r, "Target Scan Max Time (HH:MM:SS)")[0]["value"] == "32:00:00"


def test_crawl_trap_becomes_an_exclusion_regex():
    rows = ["url,reason"] + [f"https://app.example.com/calendar/{d}/view,redundant_path" for d in range(400)]
    r = analyze(_zip(sitemap_DOT_csv="\n".join(rows), report_DOT_json=_report([_f(98141)])))
    values = [c["value"] for c in _changes(r, "Regex for Excluded URLs")]
    assert r"/calendar/\d+/view" in values


def test_timeouts_waf_and_debug_traffic():
    entries = [{"request": {"url": f"https://app.example.com/{i}"}, "response": {"status": 200}} for i in range(40)]
    entries += [{"request": {"url": "https://app.example.com/x"},
                 "response": {"status": 302, "redirectURL": "https://app.example.com/login"}} for _ in range(30)]
    entries += [{"request": {"url": "https://app.example.com/y"}, "response": {"status": 429}} for _ in range(6)]
    har = json.dumps({"log": {"entries": entries}})
    r = analyze(_zip(report_DOT_json=_report([_f(98137), _f(98008), _f(98141)]), traffic_DOT_har=har))
    assert {"timeout_abort", "waf", "rate_limited", "session_died"} <= _ids(r)
    assert any(c["setting"] == "Timeout Threshold" for c in r["settings"]["Performance"])


def test_nessus_and_csv_findings_are_read():
    nessus = ('<NessusClientData_v2><Report><ReportHost name="app"><ReportItem pluginID="98044" '
              'pluginName="Scan Aborted After Being Logged Out" severity="0"><plugin_output>x</plugin_output>'
              '</ReportItem></ReportHost></Report></NessusClientData_v2>')
    assert "logged_out_abort" in _ids(analyze(_zip(scan_DOT_nessus=nessus)))
    csv_text = "Plugin ID,Plugin Name,URL,Plugin Output\n98019,Network Timeout Encountered,https://a.example.com/,\n" * 12
    assert analyze(_zip(f_DOT_csv=csv_text))["facts"]["findings"] == 12


def test_single_json_upload_is_wrapped_and_analyzed():
    parsed = parse_export(_report([_f(98142)]).encode(), "scan.json")
    assert zipfile.is_zipfile(io.BytesIO(parsed.zip_bytes))
    assert parsed.summary["analysis"]["facts"]["authentication"] == "failed"
    with pytest.raises(ScanExportError):
        as_zip(b"%PDF-1.7", "report.pdf")


def test_unrecognised_export_says_so():
    r = analyze(_zip(readme_DOT_txt="hello"))
    assert r["recognised"] is False and r["recommendations"] == []
