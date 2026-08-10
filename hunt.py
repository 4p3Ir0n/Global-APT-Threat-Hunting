#!/usr/bin/env python3
"""
Global APT Threat Hunting — daily OSINT -> candidate KQL detections.

Pulls open-source threat intelligence (CISA advisories + KEV, vendor threat-intel
RSS, SANS ISC), filters to APT-relevant items from the last ~30 hours, then asks
Claude (as a detection engineer) to write candidate Microsoft Sentinel / Defender
XDR KQL hunting queries grounded in that reporting. The queries are appended to
the hand-curated playbook under a dedicated auto-generated section — the curated
content is never edited, only appended after.

The generated queries are CANDIDATES: structurally linted but NOT semantically
validated. Review, tune, and test against your schema before deploying.

Environment:
  ANTHROPIC_API_KEY   required — the Claude API key
  CLAUDE_MODEL        optional — defaults to claude-sonnet-5
  LOOKBACK_HOURS      optional — defaults to 30
"""
from __future__ import annotations

import datetime as dt
import os
import re
import sys
from dataclasses import dataclass

import feedparser
import requests

UTC = dt.timezone.utc
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "30"))
MODEL = os.environ.get("CLAUDE_MODEL") or "claude-sonnet-5"
USER_AGENT = "Global-APT-Threat-Hunting/1.0 (+https://github.com/4p3Ir0n/Global-APT-Threat-Hunting)"
HTTP_TIMEOUT = 30
PLAYBOOK = os.path.join("Global-APT-Threat-Hunting", "global-apt-threat-hunting-kql.md")

AUTOGEN_HEADER = "## 🤖 Auto-Generated Daily Detections (OSINT-derived)"
AUTOGEN_INTRO = (
    "> ⚠️ **These queries are machine-generated from open-source reporting and are NOT "
    "validated.** They are structurally linted only. Review, tune thresholds, confirm "
    "table/column names against your schema, and test before deploying to production. "
    "Newest entries are appended at the end.\n"
)

# --- Sources -----------------------------------------------------------------

RSS_FEEDS: list[tuple[str, str]] = [
    ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Unit 42 (Palo Alto)", "https://unit42.paloaltonetworks.com/feed/"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/"),
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("Google TAG / Mandiant", "https://cloud.google.com/blog/topics/threat-intelligence/rss/"),
    ("The DFIR Report", "https://thedfirreport.com/feed/"),
    ("SANS ISC Diary", "https://isc.sans.edu/rssfeed_full.xml"),
    ("Securelist (Kaspersky)", "https://securelist.com/feed/"),
]

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

APT_KEYWORDS = [
    "apt", "nation-state", "nation state", "state-sponsored", "state sponsored",
    "threat actor", "threat group", "espionage", "cyber-espionage", "cyberespionage",
    "targeted attack", "targeted intrusion", "advanced persistent",
    "lazarus", "kimsuky", "andariel", "bluenoroff", "scarcruft",
    "apt28", "apt29", "fancy bear", "cozy bear", "sandworm", "turla", "gamaredon",
    "apt10", "apt40", "apt41", "volt typhoon", "salt typhoon", "silk typhoon",
    "flax typhoon", "mustang panda", "storm-", "typhoon", "panda", "winnti",
    "apt33", "apt34", "apt35", "charming kitten", "muddywater", "oilrig",
    "sidewinder", "transparent tribe", "patchwork", "bitter", "head mare",
    "unc", "fin7", "fin8", "cl-sta", "earth ",
    "backdoor", "implant", "supply chain", "watering hole", "zero-day", "0-day",
    "living off the land", "lotl", "webshell", "cobalt strike",
]
KEYWORD_RE = re.compile("|".join(re.escape(k) for k in APT_KEYWORDS), re.IGNORECASE)


@dataclass
class Item:
    source: str
    title: str
    link: str
    published: dt.datetime | None
    summary: str

    def matches_apt(self) -> bool:
        return bool(KEYWORD_RE.search(f"{self.title}\n{self.summary}"))


def _now() -> dt.datetime:
    return dt.datetime.now(tz=UTC)


def _entry_datetime(entry) -> dt.datetime | None:
    for attr in ("published_parsed", "updated_parsed"):
        val = getattr(entry, attr, None)
        if val:
            try:
                return dt.datetime(*val[:6], tzinfo=UTC)
            except (TypeError, ValueError):
                continue
    return None


def _clean(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    return re.sub(r"\s+", " ", text).strip()


def fetch_rss(cutoff: dt.datetime) -> list[Item]:
    items: list[Item] = []
    for name, url in RSS_FEEDS:
        try:
            resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            parsed = feedparser.parse(resp.content)
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] {name}: failed to fetch/parse ({exc})", file=sys.stderr)
            continue
        for entry in parsed.entries:
            published = _entry_datetime(entry)
            if published is not None and published < cutoff:
                continue
            items.append(
                Item(
                    source=name,
                    title=_clean(getattr(entry, "title", "")),
                    link=getattr(entry, "link", ""),
                    published=published,
                    summary=_clean(getattr(entry, "summary", ""))[:1500],
                )
            )
    return items


def fetch_kev(cutoff: dt.datetime) -> list[Item]:
    try:
        resp = requests.get(CISA_KEV_URL, headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] CISA KEV: failed to fetch ({exc})", file=sys.stderr)
        return []
    cutoff_date = cutoff.date()
    items: list[Item] = []
    for vuln in data.get("vulnerabilities", []):
        try:
            added = dt.date.fromisoformat(vuln.get("dateAdded", ""))
        except ValueError:
            continue
        if added < cutoff_date:
            continue
        cve = vuln.get("cveID", "")
        items.append(
            Item(
                source="CISA KEV",
                title=f"{cve} — {vuln.get('vendorProject','')} {vuln.get('product','')}: {vuln.get('vulnerabilityName','')}",
                link=f"https://nvd.nist.gov/vuln/detail/{cve}",
                published=dt.datetime.combine(added, dt.time(), tzinfo=UTC),
                summary=(
                    f"{_clean(vuln.get('shortDescription',''))} "
                    f"[Ransomware use: {vuln.get('knownRansomwareCampaignUse','Unknown')}] "
                    f"Required action: {_clean(vuln.get('requiredAction',''))}"
                )[:1500],
            )
        )
    return items


def collect() -> list[Item]:
    cutoff = _now() - dt.timedelta(hours=LOOKBACK_HOURS)
    print(f"[info] collecting OSINT since {cutoff.isoformat()} (lookback {LOOKBACK_HOURS}h)")
    raw = fetch_rss(cutoff) + fetch_kev(cutoff)
    print(f"[info] {len(raw)} items in window")
    relevant = [it for it in raw if it.source == "CISA KEV" or it.matches_apt()]
    seen: set[tuple[str, str]] = set()
    items: list[Item] = []
    for it in relevant:
        key = (it.title.lower(), it.link)
        if key in seen:
            continue
        seen.add(key)
        items.append(it)
    items.sort(key=lambda x: x.published or _now(), reverse=True)
    print(f"[info] {len(items)} APT-relevant items after filtering + de-dupe")
    return items


def build_context(items: list[Item]) -> str:
    out = []
    for i, it in enumerate(items, 1):
        when = it.published.strftime("%Y-%m-%d") if it.published else "date-unknown"
        out.append(f"[{i}] ({it.source}, {when}) {it.title}\n    {it.summary}\n    URL: {it.link}")
    return "\n".join(out)


# --- KQL generation ----------------------------------------------------------

SYSTEM_PROMPT = """You are a senior detection engineer writing KQL hunting queries for \
Microsoft Sentinel and Defender XDR (Advanced Hunting). You turn open-source APT / \
nation-state threat reporting into practical, defensible detections.

Hard rules:
- Ground every query in the provided source items. Cite the item number(s) as [n] for \
each detection. Never invent IOCs (hashes, IPs, domains, file names) that are not in the \
sources; if the reporting gives no concrete IOCs, write behavioral/TTP-based queries and \
say so.
- Use real Defender XDR / Sentinel table and column names (e.g. DeviceProcessEvents, \
DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceImageLoadEvents, \
IdentityLogonEvents, EmailEvents, SecurityEvent, SigninLogs, ThreatIntelligenceIndicator). \
If unsure of a column, choose the closest correct one and add a comment.
- Prefer specific, low-false-positive logic. Add `| take 100` or time bounds where sensible.
- These are CANDIDATE detections. Where a query is heuristic or needs environment-specific \
tuning, say so in the note.

Output format — Markdown only, no top-level heading (the date heading is added for you). \
For each detection use exactly this shape:

#### <Short detection title>
- **Actor / Campaign:** <name or "unattributed">
- **MITRE ATT&CK:** <Txxxx[.xxx] — technique name>
- **Data source:** <table name(s)>
- **Source:** [n]

```kql
<the KQL query>
```

*Note:* <false-positive / tuning guidance in one or two sentences>

Produce between 1 and 8 detections depending on how much detectable material the reporting \
contains. Use `####` (or deeper) for headings only — never `###` or `##`. If the reporting \
contains nothing detectable, output a single line: `_No detectable material in today's reporting._`"""

USER_TEMPLATE = """Today is {date}. Below are {count} open-source threat-intel items from \
the last {hours} hours. Write candidate KQL hunting detections per the format in your \
instructions, grounded in and citing these items.

Source items:

{context}

At the very end, add a Markdown block quote listing the sources you cited, one per line as \
`> [n] Title — URL`."""


def generate_kql(items: list[Item], today: dt.date) -> str:
    import anthropic  # lazy import so --dry-run works without the SDK/key

    client = anthropic.Anthropic()
    user = USER_TEMPLATE.format(
        date=today.isoformat(), count=len(items), hours=LOOKBACK_HOURS,
        context=build_context(items),
    )
    resp = client.messages.create(
        model=MODEL,
        max_tokens=16000,
        thinking={"type": "adaptive"},
        output_config={"effort": "high"},
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user}],
    )
    if resp.stop_reason == "refusal":
        raise RuntimeError(f"Model refused: {getattr(resp, 'stop_details', None)}")
    return "".join(b.text for b in resp.content if b.type == "text").strip()


# --- Structural lint ---------------------------------------------------------

_PLACEHOLDER_RE = re.compile(r"<[^>\n]{1,40}>|\bTODO\b|\bPLACEHOLDER\b|\bINSERT_[A-Z_]+\b|x{6,}", re.IGNORECASE)


def lint_kql(markdown: str) -> str:
    """Structural sanity check of fenced ```kql blocks. Returns a one-line summary."""
    blocks = re.findall(r"```kql\s*\n(.*?)```", markdown, re.DOTALL | re.IGNORECASE)
    if not blocks:
        return "_Lint: no KQL blocks detected._"
    issues: list[str] = []
    for i, q in enumerate(blocks, 1):
        for open_c, close_c in (("(", ")"), ("[", "]"), ("{", "}")):
            if q.count(open_c) != q.count(close_c):
                issues.append(f"query {i}: unbalanced '{open_c}{close_c}'")
        if not q.strip():
            issues.append(f"query {i}: empty")
        placeholder = _PLACEHOLDER_RE.search(q)
        if placeholder:
            issues.append(f"query {i}: placeholder-like token '{placeholder.group(0)[:20]}'")
    status = "structural checks passed" if not issues else "; ".join(issues)
    return f"_Lint: {len(blocks)} KQL block(s) — {status}. All queries are CANDIDATES; validate before use._"


# --- Playbook append ---------------------------------------------------------

def append_to_playbook(path: str, kql_md: str, today: dt.date) -> None:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()

    if AUTOGEN_HEADER not in text:
        text = text.rstrip() + "\n\n---\n\n" + AUTOGEN_HEADER + "\n\n" + AUTOGEN_INTRO + "\n"

    lint = lint_kql(kql_md)
    day_header = f"### {today.isoformat()}"
    block = (
        f"{day_header}\n\n"
        f"*Generated {_now().strftime('%Y-%m-%d %H:%M UTC')} · model `{MODEL}`*\n\n"
        f"{lint}\n\n"
        f"{kql_md.strip()}\n"
    )

    # Replace today's block if it already exists (idempotent re-runs), else append.
    pattern = re.compile(rf"(?ms)^{re.escape(day_header)}[ \t]*\n.*?(?=^### |\Z)")
    if pattern.search(text):
        text = pattern.sub(block + "\n", text)
        print(f"[ok] replaced existing {today.isoformat()} block in playbook")
    else:
        text = text.rstrip() + "\n\n" + block
        print(f"[ok] appended {today.isoformat()} block to playbook")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def main() -> int:
    dry_run = "--dry-run" in sys.argv
    today = _now().date()
    items = collect()

    if dry_run:
        for it in items:
            when = it.published.date().isoformat() if it.published else "?"
            print(f"  - ({it.source}, {when}) {it.title}")
        return 0

    if not items:
        kql_md = "_No APT-relevant open-source items in the collection window; no detections generated._"
    else:
        kql_md = generate_kql(items, today)

    if not os.path.exists(PLAYBOOK):
        print(f"[error] playbook not found at {PLAYBOOK}", file=sys.stderr)
        return 1

    append_to_playbook(PLAYBOOK, kql_md, today)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
