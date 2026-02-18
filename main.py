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

app = FastAPI(title="Deep Inspector MVP")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

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
    try: records['MX'] = [str(x.exchange) for x in resolver.resolve(domain, 'MX')]
    except: pass
    try: records['NS'] = [str(x.target) for x in resolver.resolve(domain, 'NS')]
    except: pass
    try: records['A'] = [str(x.address) for x in resolver.resolve(domain, 'A')]
    except: pass
    return records

def analyze_security(headers, soup, url_scheme):
    security_headers = {
        'Strict-Transport-Security': 'Missing', 'Content-Security-Policy': 'Missing',
        'X-Frame-Options': 'Missing', 'X-Content-Type-Options': 'Missing', 'Referrer-Policy': 'Missing'
    }
    score = 0
    vulns = []
    
    # 1. Header Check
    for h in security_headers.keys():
        if any(h.lower() == k.lower() for k in headers.keys()):
            security_headers[h] = "Present"
            score += 1
            
    # 2. Vulnerability Rules
    if security_headers['Strict-Transport-Security'] == 'Missing':
        vulns.append({"name": "Man-in-the-Middle Risk", "desc": "Missing HSTS. Users can be tricked to use HTTP.", "risk": "High"})
    
    # Clickjacking Detection
    if security_headers['X-Frame-Options'] == 'Missing' and security_headers['Content-Security-Policy'] == 'Missing':
        vulns.append({"name": "Clickjacking Vulnerable", "desc": "Site can be framed by attackers (Missing X-Frame-Options).", "risk": "High"})
        
    if security_headers['Content-Security-Policy'] == 'Missing':
        vulns.append({"name": "XSS Risk", "desc": "Missing CSP. Script injection is easier.", "risk": "Medium"})

    # 3. Login Form Detection
    login_found = False
    if soup:
        password_inputs = soup.find_all('input', {'type': 'password'})
        if password_inputs:
            login_found = True
            if url_scheme != 'https':
                vulns.append({"name": "Insecure Login Form", "desc": "Login form found on non-HTTPS page!", "risk": "High"})

    return security_headers, int((score/5)*100), vulns, login_found

def check_accessibility(soup):
    score = 100
    images = soup.find_all('img')
    img_count = len(images)
    missing_alt = 0
    for img in images:
        if not img.get('alt'):
            missing_alt += 1
            
    # Deduct points
    if missing_alt > 0: score -= 20
    
    # Lang attribute
    html = soup.find('html')
    lang = html.get('lang') if html else None
    if not lang: score -= 20
    
    # Headings
    headings = len(soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']))
    if headings == 0: score -= 10
    
    # ARIA roles
    aria_count = len(soup.find_all(attrs={"role": True}))
    
    # Skip Link (simple check)
    skip_link = False
    for a in soup.find_all('a'):
        if 'skip' in (a.get_text() or '').lower():
            skip_link = True
            break
            
    return {
        "score": max(0, score),
        "images_count": img_count,
        "images_missing_alt": missing_alt,
        "lang_tag": lang,
        "headings_count": headings,
        "aria_count": aria_count,
        "forms_count": len(soup.find_all('form')),
        "skip_link": skip_link
    }

def analyze_speed(soup):
    return {
        "js_count": len(soup.find_all('script', src=True)),
        "css_count": len(soup.find_all('link', rel='stylesheet')),
        "img_count": len(soup.find_all('img')),
        "request_count": len(soup.find_all(['script', 'link', 'img']))
    }

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
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Security & Clickjacking Analysis
        sec_headers, sec_score, vulns, login_found = analyze_security(response.headers, soup, parsed.scheme)
        
        # Deep Checks
        a11y_data = check_accessibility(soup)
        speed_data = analyze_speed(soup)
        
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
            "size_kb": round(page_size_bytes / 1024, 1), "server": response.headers.get('Server', 'Unknown'), "title": title,
            "description": description[:120] + "..." if len(description) > 120 else description
        },
        "eco": {"co2_grams": co2, "grade": eco_grade},
        "links": links, "bots": check_bots(base_url), "tech": tech_stack,
        "security": {"score": sec_score, "headers": sec_headers, "vulns": vulns, "login_found": login_found, "https": parsed.scheme == 'https'},
        "a11y": a11y_data, "speed": speed_data,
        "dns": get_dns_records(domain), "whois": whois_data, "socials": list(set(socials))[:5]
    }

class URLRequest(BaseModel):
    url: str

@app.get("/", response_class=HTMLResponse)
def home():
    with open("index.html", "r", encoding="utf-8") as f: return f.read()

@app.post("/analyze")
def analyze_route(req: URLRequest):
    return analyze_logic(req.url)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
