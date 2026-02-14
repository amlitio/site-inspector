import builtwith
import whois
import socket
import requests
import dns.resolver
from bs4 import BeautifulSoup
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import os
import time
from urllib.parse import urlparse

# Initialize App
app = FastAPI(title="Deep Inspector MVP")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Backend Logic ---
def calculate_carbon(bytes_transfer):
    gb = bytes_transfer / (1024 * 1024 * 1024)
    co2 = gb * 0.81 * 442
    grade = "F"
    if co2 < 0.095: grade = "A+"
    elif co2 < 0.186: grade = "A"
    elif co2 < 0.341: grade = "B"
    elif co2 < 0.493: grade = "C"
    elif co2 < 0.656: grade = "D"
    elif co2 < 0.850: grade = "E"
    return round(co2, 3), grade

def get_dns_records(domain):
    records = {'MX': [], 'NS': [], 'A': []}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    try:
        mx = resolver.resolve(domain, 'MX')
        records['MX'] = [str(x.exchange) for x in mx]
    except: pass
    try:
        ns = resolver.resolve(domain, 'NS')
        records['NS'] = [str(x.target) for x in ns]
    except: pass
    try:
        a = resolver.resolve(domain, 'A')
        records['A'] = [str(x.address) for x in a]
    except: pass
    return records

def analyze_security(headers):
    security_headers = {
        'Strict-Transport-Security': 'Missing', 'Content-Security-Policy': 'Missing',
        'X-Frame-Options': 'Missing', 'X-Content-Type-Options': 'Missing', 'Referrer-Policy': 'Missing'
    }
    score = 0
    total = len(security_headers)
    vulns = []

    for h in security_headers.keys():
        if any(h.lower() == k.lower() for k in headers.keys()):
            security_headers[h] = "Present"
            score += 1
            
    if security_headers['Strict-Transport-Security'] == 'Missing':
        vulns.append({"name": "Man-in-the-Middle Risk", "desc": "Missing HSTS.", "risk": "High"})
    if security_headers['Content-Security-Policy'] == 'Missing':
        vulns.append({"name": "XSS Vulnerability", "desc": "Missing CSP.", "risk": "Medium"})
    if security_headers['X-Frame-Options'] == 'Missing':
        vulns.append({"name": "Clickjacking Risk", "desc": "Site can be framed.", "risk": "Medium"})

    return security_headers, int((score/total)*100), vulns

def check_bots(base_url):
    bots = {"robots": False, "sitemap": False}
    try:
        if requests.get(f"{base_url}/robots.txt", timeout=2).status_code == 200: bots["robots"] = True
    except: pass
    try:
        if requests.get(f"{base_url}/sitemap.xml", timeout=2).status_code == 200: bots["sitemap"] = True
    except: pass
    return bots

def analyze_logic(url: str):
    if not url.startswith(('http://', 'https://')): target_url = 'https://' + url
    else: target_url = url
    try:
        parsed = urlparse(target_url)
        domain = parsed.netloc
        base_url = f"{parsed.scheme}://{domain}"
        if not domain: return {"error": "Invalid URL"}
    except: return {"error": "Invalid URL format"}
    
    start_time = time.time()
    try:
        response = requests.get(target_url, timeout=5, headers={'User-Agent': 'DeepInspector/1.0'})
        ttfb = round((time.time() - start_time) * 1000, 2)
        page_size_bytes = len(response.content)
        co2, eco_grade = calculate_carbon(page_size_bytes)
        page_size_kb = round(page_size_bytes / 1024, 1)
        headers = response.headers
        sec_headers, sec_score, vulns = analyze_security(headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else "No Title"
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        description = meta_desc['content'] if meta_desc else "No Description"
        links = {'internal': 0, 'external': 0, 'total': 0}
        socials = []
        all_anchors = soup.find_all('a', href=True)
        links['total'] = len(all_anchors)
        for link in all_anchors:
            href = link['href'].lower()
            if any(x in href for x in ['facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com', 'github.com', 'tiktok.com']):
                if href not in socials: socials.append(link['href'])
            if href.startswith('/') or domain in href: links['internal'] += 1
            elif href.startswith('http'): links['external'] += 1
    except Exception as e: return {"error": f"Connection Failed: {str(e)}"}

    tech_stack = {}
    try: tech_stack = builtwith.parse(target_url)
    except: pass

    whois_data = {}
    try:
        w = whois.whois(domain)
        # Handle lists in whois data
        exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        cre = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        
        whois_data = {
            "registrar": str(w.registrar) if w.registrar else "Unknown",
            "org": str(w.org) if w.org else "Redacted",
            "date": str(cre) if cre else "Unknown",
            "expiration": str(exp) if exp else "Unknown",
            "country": str(w.country) if w.country else "Unknown"
        }
    except: whois_data = {"error": "Hidden"}

    return {
        "overview": {
            "url": target_url, "domain": domain, "status": response.status_code, "ttfb": ttfb,
            "size_kb": page_size_kb, "server": headers.get('Server', 'Unknown'), "title": title,
            "description": description[:120] + "..." if len(description) > 120 else description
        },
        "eco": {"co2_grams": co2, "grade": eco_grade},
        "links": links, "bots": check_bots(base_url), "tech": tech_stack,
        "security": {"score": sec_score, "headers": sec_headers, "vulns": vulns},
        "dns": get_dns_records(domain), "whois": whois_data, "socials": list(set(socials))[:5]
    }

class URLRequest(BaseModel):
    url: str

@app.get("/", response_class=HTMLResponse)
def home():
    # Load HTML from separate file
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.post("/analyze")
def analyze_route(req: URLRequest):
    return analyze_logic(req.url)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))


