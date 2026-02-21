import re
import time
import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse, urljoin
from collections import defaultdict
import dns.resolver

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# Prototype Pollution Engine
# =========================

SOURCE_PATTERNS = [
    r"URLSearchParams",
    r"location\.search",
    r"location\.hash",
    r"addEventListener\s*\(\s*['\"]message['\"]",
    r"onmessage\s*=",
    r"JSON\.parse",
]

GADGET_PATTERNS = [
    r"\|\|\s*defaults\.",
    r"\b(isAdmin|role|permissions|auth|token)\b",
    r"\bmerge\s*\(",
    r"\bdeepMerge\b",
    r"\bextend\s*\(",
    r"__proto__",
    r"\bconstructor\b",
    r"\bprototype\b",
]

SINK_PATTERNS = [
    r"\binnerHTML\b",
    r"\binsertAdjacentHTML\b",
    r"\bdocument\.write\b",
    r"\beval\s*\(",
    r"\bnew Function\b",
    r"\bsetTimeout\s*\(\s*['\"]",
    r"\bsetInterval\s*\(\s*['\"]",
]


def scan_code(content: str, location: str):
    findings = []
    lines = content.split("\n")

    for idx, line in enumerate(lines, start=1):
        for pattern in SOURCE_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    "category": "Source",
                    "label": pattern,
                    "location": location,
                    "line": idx,
                    "snippet": line.strip()
                })

        for pattern in GADGET_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    "category": "Gadget",
                    "label": pattern,
                    "location": location,
                    "line": idx,
                    "snippet": line.strip()
                })

        for pattern in SINK_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    "category": "Sink",
                    "label": pattern,
                    "location": location,
                    "line": idx,
                    "snippet": line.strip()
                })

    return findings


def prototype_pollution_analysis(base_url: str, soup: BeautifulSoup):
    findings = []
    script_tags = soup.find_all("script")

    # Inline scripts
    for script in script_tags:
        if script.string and script.string.strip():
            findings.extend(scan_code(script.string, "inline"))

    # External scripts (limit to 8; cap bytes to avoid huge bundles)
    external_count = 0
    for script in script_tags:
        if script.get("src") and external_count < 8:
            try:
                script_url = urljoin(base_url, script.get("src"))
                resp = requests.get(script_url, timeout=6, headers={"User-Agent": "SiteInspector/1.0"})
                if resp.ok and resp.text:
                    findings.extend(scan_code(resp.text[:75000], script_url))
                external_count += 1
            except Exception:
                pass

    # Count categories
    counts_raw = defaultdict(int)
    for f in findings:
        counts_raw[f["category"]] += 1

    confidence = "Low"
    if counts_raw["Source"] and counts_raw["Gadget"] and counts_raw["Sink"]:
        confidence = "High"
    elif counts_raw["Source"] and (counts_raw["Gadget"] or counts_raw["Sink"]):
        confidence = "Medium"

    # Make counts UI-friendly (your revised UI expects sources/gadgets/sinks)
    counts = {
        "sources": int(counts_raw["Source"]),
        "gadgets": int(counts_raw["Gadget"]),
        "sinks": int(counts_raw["Sink"]),
    }

    return {
        "confidence": confidence,
        "counts": counts,
        "findings": findings,
        "hardening": [
            "Sanitize object keys before deep merges (__proto__, constructor, prototype).",
            "Use Object.create(null) for config/config-like objects to avoid prototype inheritance.",
            "Validate postMessage origins with strict allowlists (exact match), and validate message schemas.",
            "Avoid unsafe sinks like innerHTML/eval; prefer textContent and safe DOM APIs.",
        ],
        "notes": "Static heuristic scan only (script sampling). Runtime instrumentation is required to confirm exploitability."
    }


# =========================
# Support functions
# =========================

def safe_resolve(hostname: str, rtype: str):
    try:
        return [str(r) for r in dns.resolver.resolve(hostname, rtype)]
    except Exception:
        return []


def build_attack_surface(hostname: str, integrations: list[str]):
    # Simple graph compatible with ForceGraph
    root = hostname
    nodes = [{"id": root, "color": "#6366f1"}]
    links = []

    # A few common subdomain hints (non-invasive)
    subdomains = ["www", "api", "cdn", "static", "mail"]
    for s in subdomains:
        sid = f"{s}.{hostname}"
        nodes.append({"id": sid, "color": "#818cf8"})
        links.append({"source": root, "target": sid})

    # Integrations discovered from script/img/link external hosts
    for host in integrations[:12]:
        if host == hostname or host.endswith("." + hostname):
            continue
        nodes.append({"id": host, "color": "#a855f7"})
        links.append({"source": root, "target": host})

    # Deduplicate nodes by id
    seen = set()
    uniq_nodes = []
    for n in nodes:
        if n["id"] not in seen:
            seen.add(n["id"])
            uniq_nodes.append(n)

    return {"nodes": uniq_nodes, "links": links}


def derive_accessibility(soup: BeautifulSoup):
    images = soup.find_all("img")
    images_missing_alt = sum(1 for img in images if not img.get("alt"))

    # Very light heuristics (not a full WCAG engine)
    links = soup.find_all("a")
    vague_anchor = 0
    for a in links:
        txt = (a.get_text() or "").strip().lower()
        if txt in {"click here", "read more", "learn more", "here"}:
            vague_anchor += 1

    # “interaction density” heuristic: interactive elements per 1000 chars
    text_len = len((soup.get_text(" ", strip=True) or ""))
    interactive = len(soup.find_all(["a", "button", "input", "select", "textarea"]))
    interaction_density = round((interactive / max(text_len, 1)) * 1000, 2)

    # “reading complexity” heuristic: avg word length
    words = re.findall(r"[A-Za-z]{2,}", soup.get_text(" ", strip=True) or "")
    avg_word_len = round(sum(len(w) for w in words) / max(len(words), 1), 2)

    return {
        "images_missing_alt": images_missing_alt,
        "vague_links": vague_anchor,
        "cognitive": {
            "interaction_density": interaction_density,
            "reading_complexity": avg_word_len
        }
    }


def posture_score_from_findings(security_vulns: list[dict]):
    # Start at 100 and subtract by risk
    score = 100
    for v in security_vulns:
        r = v.get("risk", "Low")
        if r == "High":
            score -= 18
        elif r == "Medium":
            score -= 10
        else:
            score -= 4
    return max(0, min(100, score))


def build_security_vulns(headers: dict, parsed: urlparse):
    vulns = []

    def add(name, desc, risk):
        vulns.append({"name": name, "desc": desc, "risk": risk})

    if "Content-Security-Policy" not in headers:
        add("Missing Content-Security-Policy", "CSP helps mitigate XSS and injection risks.", "High")

    if "Strict-Transport-Security" not in headers:
        add("Missing HSTS", "HSTS enforces HTTPS and reduces downgrade/SSL-stripping risk.", "Medium")

    if "X-Frame-Options" not in headers and "Content-Security-Policy" not in headers:
        add("Missing Clickjacking Protection", "No X-Frame-Options and no CSP frame-ancestors policy detected.", "Medium")

    if "X-Content-Type-Options" not in headers:
        add("Missing X-Content-Type-Options", "Can reduce MIME-sniffing attacks in some browsers.", "Low")

    if parsed.scheme != "https":
        add("Unencrypted Transport", "Target is not using HTTPS as the requested scheme.", "High")

    return vulns


def extract_integrations(base_url: str, soup: BeautifulSoup):
    hosts = set()
    # scripts
    for s in soup.find_all("script"):
        src = s.get("src")
        if not src:
            continue
        u = urljoin(base_url, src)
        try:
            p = urlparse(u)
            if p.hostname:
                hosts.add(p.hostname)
        except Exception:
            pass
    # css
    for l in soup.find_all("link"):
        href = l.get("href")
        if not href:
            continue
        u = urljoin(base_url, href)
        try:
            p = urlparse(u)
            if p.hostname:
                hosts.add(p.hostname)
        except Exception:
            pass
    # images
    for img in soup.find_all("img"):
        src = img.get("src")
        if not src:
            continue
        u = urljoin(base_url, src)
        try:
            p = urlparse(u)
            if p.hostname:
                hosts.add(p.hostname)
        except Exception:
            pass

    return sorted(hosts)


# =========================
# API models
# =========================

class AnalyzeRequest(BaseModel):
    url: str


# =========================
# Core Analyzer (POST for your UI)
# =========================

@app.post("/analyze")
def analyze_post(req: AnalyzeRequest):
    return _analyze(req.url)


# Optional GET for debugging
@app.get("/analyze")
def analyze_get(url: str):
    return _analyze(url)


def _analyze(url: str):
    if not url:
        return {"error": "Missing url"}

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    headers = {"User-Agent": "SiteInspector/1.0"}
    start = time.perf_counter()

    try:
        response = requests.get(url, timeout=10, headers=headers, allow_redirects=True)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        html = response.text or ""
        soup = BeautifulSoup(html, "html.parser")
    except Exception as e:
        return {"error": str(e)}

    parsed = urlparse(response.url if response.url else url)
    hostname = parsed.hostname or ""

    # Overview
    size_kb = round(len(response.content or b"") / 1024, 2)
    overview = {
        "ttfb": elapsed_ms,
        "size_kb": size_kb,
        "final_url": response.url,
        "status": response.status_code,
    }

    # Tech placeholder (keep your UI stable)
    tech = {}  # you can later populate via builtwith, wappalyzer, etc.

    # Security
    hdrs = dict(response.headers)
    vulns = build_security_vulns(hdrs, parsed)

    security = {
        "cves": [],     # keep stable (you can integrate real correlation later)
        "vulns": vulns,
    }

    # Metadata / posture score
    posture = posture_score_from_findings(vulns)
    metadata = {
        "posture_score": posture
    }

    # Accessibility
    accessibility = derive_accessibility(soup)

    # DNS Ops (your UI expects MX)
    dns_data = {
        "A": safe_resolve(hostname, "A") if hostname else [],
        "AAAA": safe_resolve(hostname, "AAAA") if hostname else [],
        "CNAME": safe_resolve(hostname, "CNAME") if hostname else [],
        "MX": safe_resolve(hostname, "MX") if hostname else [],
        "NS": safe_resolve(hostname, "NS") if hostname else [],
        "TXT": safe_resolve(hostname, "TXT") if hostname else [],
        # Optional placeholders if you later add whois:
        "registrar": None,
        "expiration": None,
    }

    # Attack surface graph
    integrations = extract_integrations(response.url, soup)
    attack_surface = build_attack_surface(hostname, integrations)

    # Prototype pollution forensics
    prototype_pollution = prototype_pollution_analysis(response.url, soup)

    return {
        "metadata": metadata,
        "overview": overview,
        "security": security,
        "accessibility": accessibility,
        "tech": tech,
        "dns": dns_data,
        "attack_surface": attack_surface,
        "prototype_pollution": prototype_pollution,
    }
