import re
import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlparse, urljoin
from collections import defaultdict
import socket
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
    r"JSON\.parse"
]

GADGET_PATTERNS = [
    r"\|\|\s*defaults\.",
    r"\b(isAdmin|role|permissions|auth|token)\b",
    r"merge\(",
    r"deepMerge",
    r"extend\(",
    r"__proto__",
    r"constructor",
    r"prototype"
]

SINK_PATTERNS = [
    r"innerHTML",
    r"insertAdjacentHTML",
    r"document\.write",
    r"\beval\(",
    r"new Function",
    r"setTimeout\s*\(\s*['\"]",
    r"setInterval\s*\(\s*['\"]"
]


def scan_code(content, location):
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


def prototype_pollution_analysis(base_url, soup):
    findings = []
    script_tags = soup.find_all("script")

    # Scan inline scripts
    for script in script_tags:
        if script.string:
            findings.extend(scan_code(script.string, "inline"))

    # Scan external scripts (limit to 8)
    external_count = 0
    for script in script_tags:
        if script.get("src") and external_count < 8:
            try:
                script_url = urljoin(base_url, script.get("src"))
                resp = requests.get(script_url, timeout=5)
                findings.extend(scan_code(resp.text[:50000], script_url))
                external_count += 1
            except:
                pass

    counts = defaultdict(int)
    for f in findings:
        counts[f["category"]] += 1

    confidence = "Low"
    if counts["Source"] and counts["Gadget"] and counts["Sink"]:
        confidence = "High"
    elif counts["Source"] and (counts["Gadget"] or counts["Sink"]):
        confidence = "Medium"

    return {
        "confidence": confidence,
        "counts": counts,
        "findings": findings,
        "hardening": [
            "Sanitize object keys before deep merges (__proto__, constructor, prototype).",
            "Use Object.create(null) for config objects.",
            "Validate postMessage origin strictly (exact match).",
            "Avoid unsafe sinks like innerHTML and eval."
        ],
        "notes": "Static heuristic scan only. Runtime analysis required to confirm exploitability."
    }


# =========================
# Core Analyzer
# =========================

@app.get("/analyze")
def analyze(url: str):
    if not url.startswith("http"):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=8)
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception as e:
        return {"error": str(e)}

    parsed = urlparse(url)

    # Basic headers
    headers = response.headers
    security_findings = []

    if "Content-Security-Policy" not in headers:
        security_findings.append("Missing CSP")
    if "Strict-Transport-Security" not in headers:
        security_findings.append("Missing HSTS")
    if parsed.scheme != "https":
        security_findings.append("Not using HTTPS")

    # DNS lookup
    dns_data = {}
    try:
        dns_data["A"] = [str(r) for r in dns.resolver.resolve(parsed.hostname, "A")]
    except:
        dns_data["A"] = []

    # Prototype pollution analysis
    pp_results = prototype_pollution_analysis(url, soup)

    return {
        "status": response.status_code,
        "headers": dict(headers),
        "security_findings": security_findings,
        "dns": dns_data,
        "prototype_pollution": pp_results
    }
