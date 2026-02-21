mport builtwith
import whois
import socket
import requests
import dns.resolver
from bs4 import BeautifulSoup
from fastapi import FastAPI
from fastapi.responses import FileResponse
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
    if co2 < 0.095: return round(co2, 3), "A+"
    if co2 < 0.186: return round(co2, 3), "A"
    if co2 < 0.341: return round(co2, 3), "B"
    if co2 < 0.493: return round(co2, 3), "C"
    if co2 < 0.656: return round(co2, 3), "D"
    return round(co2, 3), "E"

def get_dns_records(domain):
    records = {'MX': [], 'NS': [], 'A': []}
    resolver = dns.resolver.Resolver()
    resolver.timeout, resolver.lifetime = 2, 2
    for record_type in ['MX', 'NS', 'A']:
        try:
            answers = resolver.resolve(domain, record_type)
            records[record_type] = [str(x.exchange) if record_type == 'MX' else str(x.target) if record_type == 'NS' else str(x.address) for x in answers]
        except: pass
    return records

def analyze_security(headers, soup, url_scheme):
    sec_headers = {
        'Strict-Transport-Security': 'Missing', 'Content-Security-Policy': 'Missing',
        'X-Frame-Options': 'Missing', 'X-Content-Type-Options': 'Missing', 'Referrer-Policy': 'Missing'
    }
    score, vulns = 0, []
    
    for h in sec_headers.keys():
        if any(h.lower() == k.lower() for k in headers.keys()):
            sec_headers[h] = "Present"
            score += 1
            
    if sec_headers['Strict-Transport-Security'] == 'Missing':
        vulns.append({"name": "Man-in-the-Middle Risk", "desc": "Missing HSTS.", "risk": "High"})
    if sec_headers['X-Frame-Options'] == 'Missing' and sec_headers['Content-Security-Policy'] == 'Missing':
        vulns.append({"name": "Clickjacking Vulnerable", "desc": "Site can be framed by attackers.", "risk": "High"})
    if sec_headers['Content-Security-Policy'] == 'Missing':
        vulns.append({"name": "XSS Risk", "desc": "Missing CSP.", "risk": "Medium"})

    login_found = False
    if soup and soup.find_all('input', {'type': 'password'}):
        login_found = True
        if url_scheme != 'https':
            vulns.append({"name": "Insecure Login", "desc": "Login over HTTP!", "risk": "High"})

    return sec_headers, int((score/5)*100), vulns, login_found

def check_a11y(soup):
    score, missing_alt = 100, sum(1 for img in soup.find_all('img') if not img.get('alt'))
    if missing_alt > 0: score -= 20
    if not (soup.find('html') and soup.find('html').get('lang')): score -= 20
    if len(soup.find_all(['h1', 'h2', 'h3'])) == 0: score -= 10
    
    return {
        "score": max(0, score), "images_missing_alt": missing_alt,
        "lang_tag": soup.find('html').get('lang') if soup.find('html') else None,
        "forms_count": len(soup.find_all('form'))
    }

def analyze_logic(url: str):
    target_url = url if url.startswith(('http://', 'https://')) else 'https://' + url
    try:
        parsed = urlparse(target_url)
        domain = parsed.netloc
        if not domain: return {"error": "Invalid URL"}
    except: return {"error": "Invalid URL"}
    
    start_time = time.time()
    try:
        res = requests.get(target_url, timeout=5, headers={'User-Agent': 'DeepInspector/1.0'})
        ttfb = round((time.time() - start_time) * 1000, 2)
        soup = BeautifulSoup(res.text, 'html.parser')
        co2, eco_grade = calculate_carbon(len(res.content))
        
        sec_headers, sec_score, vulns, login_found = analyze_security(res.headers, soup, parsed.scheme)
        a11y_data = check_a11y(soup)
        
        links = {'internal': sum(1 for a in soup.find_all('a', href=True) if a['href'].startswith('/') or domain in a['href']), 
                 'external': sum(1 for a in soup.find_all('a', href=True) if a['href'].startswith('http') and domain not in a['href'])}
        
    except Exception as e: return {"error": f"Connection Failed: {str(e)}"}

    try: 
        w = whois.whois(domain)
        exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        whois_data = {"registrar": str(w.registrar), "expiration": str(exp)}
    except: whois_data = {"error": "Hidden"}

    return {
        "overview": {"url": target_url, "domain": domain, "ttfb": ttfb, "size_kb": round(len(res.content) / 1024, 1)},
        "eco": {"co2_grams": co2, "grade": eco_grade},
        "links": links, "security": {"score": sec_score, "headers": sec_headers, "vulns": vulns, "login_found": login_found},
        "a11y": a11y_data, "speed": {
            "js_count": len(soup.find_all('script', src=True)),
            "css_count": len(soup.find_all('link', rel='stylesheet')),
            "img_count": len(soup.find_all('img'))
        },
        "dns": get_dns_records(domain), "whois": whois_data
    }

class URLRequest(BaseModel):
    url: str

@app.get("/", response_class=FileResponse)
def home():
    # SERVES THE HTML FILE DIRECTLY - NO HTML IN THIS FILE!
    return FileResponse("index.html")

@app.post("/analyze")
def analyze_route(req: URLRequest):
    return analyze_logic(req.url)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
