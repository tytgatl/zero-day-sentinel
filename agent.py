#!/usr/bin/env python3
"""Zero-Day Sentinel: defensive vulnerability intelligence monitor.

Collects CISA KEV, recent NVD CVE records, and configured RSS/Atom feeds.
Stores findings in SQLite, assigns transparent triage scores, and sends email
alerts for new high-priority findings. Does not download or execute exploit code.
"""
from __future__ import annotations
import argparse, email.utils, hashlib, json, logging, os, re, smtplib, sqlite3, ssl, sys, time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("ZDS_DATA_DIR", str(APP_DIR / "data"))).resolve()
DB_PATH = DATA_DIR / "sentinel.sqlite3"
REPORT_DIR = DATA_DIR / "reports"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "ZeroDaySentinel/1.0 (defensive vulnerability intelligence; contact configured by operator)"

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("zero-day-sentinel")

ZERO_DAY_TERMS = ("zero-day", "zero day", "0-day", "0day", "unpatched", "no patch available", "actively exploited", "exploited in the wild", "in-the-wild exploitation")
EXPLOIT_CLAIM_TERMS = ("exploit for sale", "private exploit", "working exploit", "remote code execution", "pre-authentication", "pre-auth auth bypass")
CRITICAL_TERMS = ("remote code execution", "arbitrary code execution", "authentication bypass", "unauthenticated", "wormable", "privilege escalation")

@dataclass
class Finding:
    finding_id: str
    source: str
    title: str
    url: str
    published: str
    summary: str
    products: str = ""
    cve: str = ""
    cvss: float | None = None
    kev_listed: bool = False
    zero_day_signal: bool = False
    exploit_claim: bool = False
    confidence: str = "low"
    score: int = 0
    severity: str = "Informational"
    first_seen: str = ""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_text(value: Any, limit: int = 1800) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()[:limit]


def http_get(url: str, headers: dict[str, str] | None = None, timeout: int = 20) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"Only HTTPS source URLs are allowed: {url}")
    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json, application/atom+xml, application/rss+xml, application/xml, text/xml"}
    if headers:
        req_headers.update(headers)
    req = Request(url, headers=req_headers)
    with urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status} for {url}")
        data = resp.read(8_000_000 + 1)
        if len(data) > 8_000_000:
            raise ValueError("Source response exceeded 8 MB safety limit")
        return data


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as con:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("""CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY, source TEXT NOT NULL, title TEXT NOT NULL,
            url TEXT NOT NULL, published TEXT, summary TEXT, products TEXT, cve TEXT,
            cvss REAL, kev_listed INTEGER, zero_day_signal INTEGER, exploit_claim INTEGER,
            confidence TEXT, score INTEGER, severity TEXT, first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL, emailed INTEGER NOT NULL DEFAULT 0, raw_json TEXT
        )""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_findings_score ON findings(score DESC)")


def load_feed_urls() -> list[str]:
    raw = os.getenv("ZDS_RSS_FEEDS", "")
    return [u.strip() for u in raw.split(",") if u.strip()]


def get_cisa_kev() -> tuple[set[str], list[Finding]]:
    findings: list[Finding] = []
    kev_ids: set[str] = set()
    try:
        payload = json.loads(http_get(KEV_URL))
        for item in payload.get("vulnerabilities", []):
            cve = safe_text(item.get("cveID"))
            if not cve:
                continue
            kev_ids.add(cve.upper())
            title = f"CISA KEV: {safe_text(item.get('vendorProject'))} {safe_text(item.get('product'))} â€” {cve}"
            summary = " ".join(filter(None, [safe_text(item.get("vulnerabilityName")), safe_text(item.get("shortDescription")), "Required action: " + safe_text(item.get("requiredAction"))]))
            findings.append(Finding(
                finding_id=f"KEV:{cve.upper()}", source="CISA KEV", title=title,
                url=f"https://nvd.nist.gov/vuln/detail/{cve.upper()}",
                published=safe_text(item.get("dateAdded")), summary=summary,
                products=f"{safe_text(item.get('vendorProject'))} {safe_text(item.get('product'))}",
                cve=cve.upper(), kev_listed=True, confidence="high"))
        log.info("Loaded %d CISA KEV entries", len(findings))
    except Exception as exc:
        log.warning("CISA KEV collection failed: %s", exc)
    return kev_ids, findings


def get_nvd(days: int = 3) -> list[Finding]:
    end = utcnow()
    start = end - timedelta(days=days)
    params = f"?lastModStartDate={start.strftime('%Y-%m-%dT%H:%M:%S.000Z')}&lastModEndDate={end.strftime('%Y-%m-%dT%H:%M:%S.000Z')}&resultsPerPage=100"
    headers = {}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    try:
        payload = json.loads(http_get(NVD_URL + params, headers=headers))
    except Exception as exc:
        log.warning("NVD collection failed: %s", exc)
        return []
    findings: list[Finding] = []
    for row in payload.get("vulnerabilities", []):
        cve_obj = row.get("cve", {})
        cve = safe_text(cve_obj.get("id")).upper()
        if not cve:
            continue
        descriptions = cve_obj.get("descriptions", [])
        desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve_obj.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                data = entries[0].get("cvssData", {})
                try: cvss = float(data.get("baseScore"))
                except (TypeError, ValueError): pass
                if cvss is not None: break
        refs = cve_obj.get("references", [])
        ref_url = next((r.get("url") for r in refs if str(r.get("url", "")).startswith("https://")), f"https://nvd.nist.gov/vuln/detail/{cve}")
        title = f"NVD update: {cve}"
        findings.append(Finding(finding_id=f"NVD:{cve}", source="NVD", title=title, url=ref_url,
            published=safe_text(cve_obj.get("published")), summary=safe_text(desc), cve=cve, cvss=cvss,
            confidence="medium" if desc else "low"))
    log.info("Loaded %d recent NVD records", len(findings))
    return findings


def get_rss(url: str) -> list[Finding]:
    out: list[Finding] = []
    try:
        root = ET.fromstring(http_get(url))
        # RSS 2.0 and Atom; use local tag names to avoid namespace assumptions.
        for item in list(root.iter()):
            tag = item.tag.rsplit("}", 1)[-1].lower()
            if tag not in ("item", "entry"):
                continue
            fields: dict[str, str] = {}
            for child in list(item):
                name = child.tag.rsplit("}", 1)[-1].lower()
                if name == "link":
                    fields[name] = child.attrib.get("href") or (child.text or "")
                elif name in ("title", "description", "summary", "content", "pubdate", "published", "updated", "id"):
                    fields[name] = " ".join(child.itertext())
            title = safe_text(fields.get("title"))
            link = safe_text(fields.get("link") or fields.get("id"))
            summary = safe_text(fields.get("summary") or fields.get("description") or fields.get("content"))
            if not title or not link.startswith("https://"):
                continue
            ident = hashlib.sha256((url + "|" + link + "|" + title).encode()).hexdigest()[:24]
            out.append(Finding(finding_id=f"RSS:{ident}", source=f"RSS: {urlparse(url).hostname}", title=title,
                url=link, published=safe_text(fields.get("published") or fields.get("pubdate") or fields.get("updated")),
                summary=summary, confidence="low"))
        log.info("Loaded %d items from RSS source %s", len(out), urlparse(url).hostname)
    except Exception as exc:
        log.warning("RSS collection failed for %s: %s", url, exc)
    return out


def score_finding(f: Finding) -> Finding:
    text = (f.title + " " + f.summary + " " + f.products).lower()
    f.zero_day_signal = any(term in text for term in ZERO_DAY_TERMS)
    f.exploit_claim = any(term in text for term in EXPLOIT_CLAIM_TERMS)
    score = 0
    if f.cvss is not None:
        score += round(f.cvss / 10 * 35)
    if f.kev_listed:
        score += 40
    if f.zero_day_signal:
        score += 20
    if f.exploit_claim:
        score += 10
    if any(term in text for term in CRITICAL_TERMS):
        score += 5
    f.score = min(100, score)
    if f.score >= 80: f.severity = "Critical"
    elif f.score >= 60: f.severity = "High"
    elif f.score >= 35: f.severity = "Medium"
    elif f.score >= 15: f.severity = "Low"
    else: f.severity = "Informational"
    # Confidence reflects evidence source, not severity.
    if f.kev_listed: f.confidence = "high"
    elif f.source == "NVD" and f.cve: f.confidence = "medium"
    elif f.source.startswith("RSS:"): f.confidence = "low â€” verify claim"
    f.first_seen = f.first_seen or iso(utcnow())
    return f


def upsert(f: Finding) -> tuple[bool, bool]:
    """Return (is_new, should_email). Existing findings can be rescored but aren't re-emailed."""
    now = iso(utcnow())
    raw = json.dumps(asdict(f), ensure_ascii=False)
    with sqlite3.connect(DB_PATH) as con:
        row = con.execute("SELECT finding_id, emailed, score FROM findings WHERE finding_id=?", (f.finding_id,)).fetchone()
        if row:
            con.execute("""UPDATE findings SET last_seen=?, title=?, summary=?, cvss=?, kev_listed=?, zero_day_signal=?, exploit_claim=?, confidence=?, score=?, severity=?, raw_json=? WHERE finding_id=?""",
                (now, f.title, f.summary, f.cvss, int(f.kev_listed), int(f.zero_day_signal), int(f.exploit_claim), f.confidence, f.score, f.severity, raw, f.finding_id))
            return False, False
        con.execute("""INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (f.finding_id, f.source, f.title, f.url, f.published, f.summary, f.products, f.cve, f.cvss,
             int(f.kev_listed), int(f.zero_day_signal), int(f.exploit_claim), f.confidence, f.score,
             f.severity, f.first_seen, now, 0, raw))
    # Email new High/Critical and any potential zero-day signal for analyst triage.
    return True, f.score >= 80 or f.zero_day_signal


def email_enabled() -> bool:
    return all(os.getenv(k, "").strip() for k in ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "ALERT_FROM", "ALERT_TO"))


def send_email(findings: list[Finding]) -> bool:
    if not findings:
        return True
    if not email_enabled():
        log.warning("Email not configured; findings saved locally. Copy .env.example to .env and set SMTP values.")
        return False
    msg = EmailMessage()
    msg["Subject"] = f"[Zero-Day Sentinel] {len(findings)} new security intelligence alert(s)"
    msg["From"] = os.environ["ALERT_FROM"]
    msg["To"] = os.environ["ALERT_TO"]
    lines = ["Zero-Day Sentinel â€” defensive intelligence alerts", "", "These are triage leads, not proof that every reported claim is valid.", ""]
    for f in sorted(findings, key=lambda x: x.score, reverse=True):
        lines += [f"[{f.severity} | score {f.score}/100 | confidence: {f.confidence}] {f.title}",
                  f"Source: {f.source} | CVE: {f.cve or 'not assigned'} | CVSS: {f.cvss if f.cvss is not None else 'unknown'}",
                  f"CISA KEV: {'yes' if f.kev_listed else 'no'} | Possible zero-day language: {'yes' if f.zero_day_signal else 'no'} | Exploit claim language: {'yes' if f.exploit_claim else 'no'}",
                  f"Published: {f.published or 'unknown'}", f"Evidence: {f.url}", f"Summary: {f.summary[:1000]}",
                  "Recommended action: verify vendor advisory and affected versions; check asset exposure; apply vendor mitigation/patch; add detection and monitor logs. Do not execute untrusted code.", ""]
    msg.set_content("\n".join(lines))
    host, port = os.environ["SMTP_HOST"], int(os.environ["SMTP_PORT"])
    context = ssl.create_default_context()
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=context, timeout=20) as smtp:
                smtp.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=20) as smtp:
                smtp.ehlo(); smtp.starttls(context=context); smtp.ehlo()
                smtp.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
                smtp.send_message(msg)
        log.info("Sent email alert with %d finding(s)", len(findings))
        return True
    except Exception as exc:
        log.error("Email delivery failed: %s", exc)
        return False


def export_report(findings: list[Finding]) -> Path:
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    path = REPORT_DIR / f"report-{stamp}.json"
    path.write_text(json.dumps({"generated_at": iso(utcnow()), "count": len(findings), "findings": [asdict(f) for f in sorted(findings, key=lambda x: x.score, reverse=True)]}, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def run_once(days: int = 3, send: bool = True) -> int:
    init_db()
    kev_ids, kev_findings = get_cisa_kev()
    findings = kev_findings + get_nvd(days=days)
    for url in load_feed_urls():
        findings.extend(get_rss(url))
    # Merge KEV evidence into NVD entries for the same CVE.
    for f in findings:
        if f.cve and f.cve.upper() in kev_ids:
            f.kev_listed = True
        score_finding(f)
    new_alerts: list[Finding] = []
    new_count = 0
    for f in findings:
        is_new, should_email = upsert(f)
        if is_new: new_count += 1
        if is_new and should_email: new_alerts.append(f)
    report = export_report(findings)
    log.info("Cycle complete: %d collected, %d new, %d alert candidates; report=%s", len(findings), new_count, len(new_alerts), report)
    if send and new_alerts:
        if send_email(new_alerts):
            with sqlite3.connect(DB_PATH) as con:
                con.executemany("UPDATE findings SET emailed=1 WHERE finding_id=?", [(f.finding_id,) for f in new_alerts])
    print(f"Collected: {len(findings)} | New: {new_count} | New alert candidates: {len(new_alerts)} | Report: {report}")
    return 0


def show_top(limit: int = 20) -> int:
    init_db()
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute("SELECT severity,score,confidence,cve,title,url,source,first_seen FROM findings ORDER BY score DESC, first_seen DESC LIMIT ?", (limit,)).fetchall()
    if not rows:
        print("No findings yet. Run: python agent.py once")
        return 0
    for sev, score, conf, cve, title, url, source, seen in rows:
        print(f"[{sev:13} {score:3}/100] {cve or '-':12} {title}\n  source={source} confidence={conf} first_seen={seen}\n  {url}\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Local defensive zero-day and vulnerability intelligence monitor")
    sub = parser.add_subparsers(dest="command", required=True)
    once = sub.add_parser("once", help="collect sources once, save findings, and send eligible alerts")
    once.add_argument("--days", type=int, default=3, help="NVD lookback in days (1â€“7; default 3)")
    once.add_argument("--no-email", action="store_true", help="do not send email")
    sub.add_parser("test-email", help="send a configuration test email")
    top = sub.add_parser("top", help="show highest-scoring stored findings")
    top.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()
    if args.command == "once":
        if not 1 <= args.days <= 7:
            parser.error("--days must be between 1 and 7")
        return run_once(days=args.days, send=not args.no_email)
    if args.command == "top": return show_top(max(1, min(args.limit, 100)))
    if args.command == "test-email":
        if not email_enabled():
            print("Email not configured. Copy .env.example to .env and set SMTP variables.", file=sys.stderr); return 2
        msg = EmailMessage(); msg["Subject"] = "[Zero-Day Sentinel] Email configuration test"; msg["From"] = os.environ["ALERT_FROM"]; msg["To"] = os.environ["ALERT_TO"]
        msg.set_content("Zero-Day Sentinel email delivery test succeeded. This agent sends defensive vulnerability intelligence alerts only.")
        # Reuse SMTP settings without adding a fake finding.
        host, port = os.environ["SMTP_HOST"], int(os.environ["SMTP_PORT"]); ctx = ssl.create_default_context()
        try:
            if port == 465:
                with smtplib.SMTP_SSL(host, port, context=ctx, timeout=20) as s: s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"]); s.send_message(msg)
            else:
                with smtplib.SMTP(host, port, timeout=20) as s: s.ehlo(); s.starttls(context=ctx); s.ehlo(); s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"]); s.send_message(msg)
            print("Test email sent."); return 0
        except Exception as e:
            print(f"Email failed: {e}", file=sys.stderr); return 1
    return 2

if __name__ == "__main__":
    raise SystemExit(main())

