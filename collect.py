#!/usr/bin/env python3
"""보안 취약점 소식 수집기.

여러 소스에서 소식을 받아 docs/data.json 에 누적 저장한다.
- 표준 라이브러리만 사용 (pip 설치 불필요)
- 소스 하나가 실패해도 나머지는 계속 수집
- 이미 저장된 항목(id 기준)은 다시 저장하지 않음
"""
import html
import json
import os
import re
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

# ───────────── 설정 ─────────────
RETENTION_DAYS = 60          # 이 기간보다 오래된 항목은 지운다
TIMEOUT = 40                 # 소스별 요청 제한 시간(초)
USER_AGENT = "Mozilla/5.0 (compatible; vuln-watch/1.0)"

URL_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
URL_KISA = "https://www.boho.or.kr/kr/rss.do?bbsId=B0000133"
URL_KISA_VIEW = "https://www.boho.or.kr/kr/bbs/view.do?bbsId=B0000133&menuNo=205020&nttId={}"
URL_BLEEPING = "https://www.bleepingcomputer.com/feed/"
URL_THN = "https://feeds.feedburner.com/TheHackersNews"
URL_MSRC = "https://api.msrc.microsoft.com/update-guide/rss"
URL_CHROME = "https://chromereleases.googleblog.com/feeds/posts/default"
URL_GHSA = "https://api.github.com/advisories?type=reviewed&per_page=100&sort=published&direction=desc"

# 영역 분류 키워드 (소문자). 제목·요약·제품명에 들어 있으면 해당 영역으로 분류한다.
AREA_KEYWORDS = {
    "server": [
        "nginx", "apache", "linux", "kernel", "vmware", "esxi", "vcenter", "kubernetes",
        "docker", "postgresql", "mysql", "mariadb", "mongodb", "redis", "openssh", "openssl",
        "cisco", "fortinet", "fortigate", "fortios", "palo alto", "pan-os", "ivanti", "citrix",
        "netscaler", "f5", "big-ip", "juniper", "sonicwall", "windows server", "exchange",
        "active directory", "hyper-v", "sql server", "sharepoint", "router", "firewall", "vpn",
        "qnap", "synology", "veeam", "zabbix", "jenkins", "gitlab", "oracle", "sap", "samba",
        "haproxy", "tomcat", "weblogic", "proxmox", "azure", "aws", "ubuntu", "red hat",
        "debian", "hypervisor", "서버", "방화벽", "라우터", "네트워크 장비",
    ],
    "web": [
        "php", "wordpress", "laravel", "symfony", "node.js", "nodejs", "npm", "django", "flask",
        "spring", "java", "python", "pypi", "ruby", "rails", "composer", "react", "next.js",
        "vue", "angular", "xss", "cross-site", "sql injection", "csrf", "ssrf", "drupal",
        "joomla", "struts", "log4j", "jquery", "maven", "nuget", "golang", "rust", "crates.io",
        "tomcat", "웹", "플러그인", "plugin",
    ],
    "pc": [
        "windows", "office", "outlook", "excel", "word", "powerpoint", "chrome", "edge",
        "firefox", "safari", "macos", "ios", "android", "adobe", "acrobat", "zoom", "teams",
        "7-zip", "winrar", "browser", "한컴", "한글", "알집", "알약", "v3", "notepad++",
        "visual studio code", "브라우저", "윈도우",
    ],
}
# ────────────────────────────────

ROOT = Path(__file__).resolve().parent
DATA_FILE = ROOT / "docs" / "data.json"
STATUS_FILE = ROOT / "docs" / "status.json"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
KST = timezone(timedelta(hours=9))
NOW = datetime.now(timezone.utc)
CUTOFF = NOW - timedelta(days=RETENTION_DAYS)

KEV_CVES = None  # KEV 수집에 성공하면 CVE 집합이 들어간다


def _area_patterns():
    out = {}
    for area, words in AREA_KEYWORDS.items():
        alt = "|".join(re.escape(w) for w in sorted(words, key=len, reverse=True))
        out[area] = re.compile(r"(?<![a-z0-9])(?:" + alt + r")(?![a-z0-9])")
    return out


AREA_RE = _area_patterns()


def fetch(url, headers=None):
    """URL 내용을 bytes 로 받는다. 한 번 실패하면 잠시 뒤 한 번 더 시도."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    last = None
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as res:
                return res.read()
        except Exception as e:  # noqa: BLE001
            last = e
            if attempt == 0:
                time.sleep(3)
    raise last


def clean(text):
    """HTML 태그를 지우고 공백을 정리한다."""
    text = re.sub(r"<(script|style)\b.*?</\1>", " ", text or "", flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def parse_date(value, default_tz=timezone.utc):
    value = (value or "").strip()
    dt = None
    for parser in (
        lambda v: datetime.fromisoformat(v.replace("Z", "+00:00")),
        parsedate_to_datetime,
        lambda v: datetime.strptime(v, "%Y-%m-%d"),
    ):
        try:
            dt = parser(value)
            break
        except Exception:  # noqa: BLE001
            continue
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz)
    return dt.astimezone(timezone.utc)


def find_cves(*texts):
    found = {m.upper() for t in texts for m in CVE_RE.findall(t or "")}
    return sorted(found)


def classify(text, always=()):
    low = text.lower()
    areas = [a for a, rx in AREA_RE.items() if a in always or rx.search(low)]
    return areas


def make_item(source, uid, title, link, date, text="", product="", cves=None, always=()):
    """화면에 쓰는 공통 형식으로 만든다. 쓸 수 없는 항목이면 None."""
    title = clean(title)
    link = (link or "").strip()
    if not title or not link.startswith(("http://", "https://")):
        return None
    if date is None:
        date = NOW
    if date < CUTOFF:
        return None
    summary = clean(text)
    return {
        "id": f"{source}:{uid}",
        "source": source,
        "title": title,
        "link": link,
        "date": date.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cves": cves if cves is not None else find_cves(title, summary),
        "areas": classify(f"{title} {summary} {product}", always),
        "kev": False,
        "product": product,
        "summary": summary[:220],
    }


def parse_feed(raw):
    """RSS / Atom 을 구분 없이 읽어 항목 목록으로 돌려준다."""
    root = ET.fromstring(raw.strip())
    entries = []
    for el in root.iter():
        if el.tag.rsplit("}", 1)[-1] not in ("item", "entry"):
            continue
        d = {"categories": [], "attrs": dict(el.attrib)}
        for c in el:
            tag = c.tag.rsplit("}", 1)[-1]
            text = (c.text or "").strip()
            if tag == "link":
                href = c.get("href")
                if href is None:
                    d["link"] = text
                elif c.get("rel", "alternate") == "alternate":
                    d["link"] = href
            elif tag == "category":
                d["categories"].append(c.get("term") or text)
            else:
                d.setdefault(tag, text)
        entries.append(d)
    return entries


def entry_date(e, tz=timezone.utc):
    return parse_date(e.get("pubDate") or e.get("published") or e.get("updated"), tz)


def entry_text(e):
    return e.get("encoded") or e.get("content") or e.get("description") or e.get("summary") or ""


# ───────────── 소스별 수집 ─────────────
def collect_kev(known):
    global KEV_CVES
    data = json.loads(fetch(URL_KEV))
    vulns = data["vulnerabilities"]
    items = []
    for v in vulns:
        cve = v["cveID"].upper()
        product = f"{v.get('vendorProject', '')} {v.get('product', '')}".strip()
        items.append(make_item(
            "CISA KEV", cve, v.get("vulnerabilityName") or cve,
            f"https://nvd.nist.gov/vuln/detail/{cve}",
            parse_date(v.get("dateAdded")),
            text=v.get("shortDescription", ""), product=product, cves=[cve],
        ))
    KEV_CVES = {v["cveID"].upper() for v in vulns}
    return items


def collect_kisa(known):
    items = []
    for e in parse_feed(fetch(URL_KISA)):
        m = re.search(r"nttId=(\d+)", e.get("link", "") + e.get("guid", ""))
        if not m:
            continue
        ntt = m.group(1)
        link = URL_KISA_VIEW.format(ntt)
        text = ""
        if f"KISA:{ntt}" not in known:
            # RSS 에는 제목만 있어서, 새 항목만 본문을 읽어 CVE 번호를 찾는다.
            try:
                text = clean(fetch(link).decode("utf-8", "replace"))
            except Exception as err:  # noqa: BLE001
                print(f"   (KISA 본문 읽기 실패 {ntt}: {err})")
        item = make_item("KISA", ntt, e.get("title", ""), link, entry_date(e, KST),
                         cves=find_cves(e.get("title", ""), text))
        items.append(item)
    return items


def collect_news(source, url):
    def run(known):
        return [
            make_item(source, e.get("guid") or e.get("link", ""), e.get("title", ""),
                      e.get("link", ""), entry_date(e), text=e.get("description", ""))
            for e in parse_feed(fetch(url))
        ]
    return run


def collect_msrc(known):
    items = []
    for e in parse_feed(fetch(URL_MSRC)):
        # 수정 이력(1.1, 2.0 …)은 대부분 안내 문구 변경이라 최초 공개(1.0)만 받는다.
        if not e["attrs"].get("Revision", "1.0").startswith("1.0"):
            continue
        guid = e.get("guid") or e.get("link", "")
        title = e.get("title", "")
        # 제목이 "CVE-2026-1234 제품명 ..." 형태라 제목에서만 CVE 를 뽑는다.
        items.append(make_item("Microsoft", guid, title, e.get("link", ""), entry_date(e),
                               product="Microsoft", cves=find_cves(title, guid)))
    return items


def collect_chrome(known):
    items = []
    for e in parse_feed(fetch(URL_CHROME)):
        body = entry_text(e)
        cves = find_cves(e.get("title", ""), body)
        # 보안과 무관한 Dev/Beta 공지는 빼고, 정식 채널 공지와 CVE 가 있는 글만 남긴다.
        if "Stable updates" not in e["categories"] and not cves:
            continue
        item = make_item("Chrome Releases", e.get("id") or e.get("link", ""),
                         e.get("title", ""), e.get("link", "").replace("http://", "https://", 1),
                         entry_date(e), text=body, product="Google Chrome", cves=cves)
        if item:
            item["areas"] = ["pc"]  # 본문에 Linux 등이 언급돼도 브라우저 소식은 사내 PC 로만 분류
        items.append(item)
    return items


def collect_ghsa(known):
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    items = []
    for a in json.loads(fetch(URL_GHSA, headers)):
        if a.get("withdrawn_at"):
            continue
        pkgs = sorted({
            f"{(v.get('package') or {}).get('ecosystem', '')}:{(v.get('package') or {}).get('name', '')}"
            for v in a.get("vulnerabilities") or []
        })
        severity = a.get("severity") or ""
        item = make_item(
            "GitHub Advisory", a["ghsa_id"], a.get("summary") or a["ghsa_id"], a.get("html_url", ""),
            parse_date(a.get("published_at")), product=" ".join(pkgs),
            cves=[a["cve_id"].upper()] if a.get("cve_id") else [], always=("web",),
        )
        if item:
            item["severity"] = severity
            item["summary"] = " · ".join(x for x in (severity, ", ".join(pkgs)) if x)[:220]
        items.append(item)
    return items


SOURCES = [
    ("CISA KEV", collect_kev),
    ("KISA", collect_kisa),
    ("BleepingComputer", collect_news("BleepingComputer", URL_BLEEPING)),
    ("The Hacker News", collect_news("The Hacker News", URL_THN)),
    ("Microsoft", collect_msrc),
    ("Chrome Releases", collect_chrome),
    ("GitHub Advisory", collect_ghsa),
]
# ────────────────────────────────


def load_items():
    try:
        return {i["id"]: i for i in json.loads(DATA_FILE.read_text(encoding="utf-8"))["items"]}
    except FileNotFoundError:
        return {}


def save(items, status):
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    rows = ",\n".join(json.dumps(i, ensure_ascii=False, separators=(",", ":")) for i in items)
    DATA_FILE.write_text('{"items":[\n' + rows + "\n]}\n", encoding="utf-8")
    STATUS_FILE.write_text(json.dumps(
        {"updated": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"), "sources": status},
        ensure_ascii=False, indent=1), encoding="utf-8")


def main():
    items = load_items()
    known = set(items)
    status = []
    for name, collect in SOURCES:
        try:
            got = [i for i in collect(known) if i]
            new = [i for i in got if i["id"] not in items]
            for i in new:
                items[i["id"]] = i
            print(f"[성공] {name}: {len(got)}건 확인, 새 항목 {len(new)}건")
            status.append({"name": name, "ok": True, "new": len(new)})
        except Exception as e:  # noqa: BLE001 - 소스 하나의 실패가 전체를 멈추지 않게 한다
            print(f"[실패] {name}: {type(e).__name__}: {e}")
            status.append({"name": name, "ok": False, "error": f"{type(e).__name__}: {e}"[:200]})

    cutoff = CUTOFF.strftime("%Y-%m-%dT%H:%M:%SZ")
    kept = [i for i in items.values() if i["date"] >= cutoff]
    if KEV_CVES is not None:  # KEV 수집에 실패한 회차에는 기존 표시를 그대로 둔다
        for i in kept:
            i["kev"] = any(c in KEV_CVES for c in i["cves"])
    kept.sort(key=lambda i: (i["date"], i["id"]), reverse=True)
    save(kept, status)
    print(f"저장 완료: 총 {len(kept)}건 → {DATA_FILE.relative_to(ROOT)}")

    if not any(s["ok"] for s in status):
        sys.exit("모든 소스 수집에 실패했습니다.")


if __name__ == "__main__":
    main()
