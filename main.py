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

# CORS to prevent browser errors
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 1. Backend Analysis Logic ---

def calculate_carbon(bytes_transfer):
    # Estimation: 0.81 kWh/GB * 442g CO2/kWh
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

def analyze_headers(headers):
    security_headers = {
        'Strict-Transport-Security': 'Missing',
        'Content-Security-Policy': 'Missing',
        'X-Frame-Options': 'Missing',
        'X-Content-Type-Options': 'Missing',
        'Referrer-Policy': 'Missing'
    }
    score = 0
    total = len(security_headers)
    for h in security_headers.keys():
        if any(h.lower() == k.lower() for k in headers.keys()):
            security_headers[h] = "Present"
            score += 1
    return security_headers, int((score/total)*100)

def check_bots(base_url):
    bots = {"robots": False, "sitemap": False}
    try:
        r = requests.get(f"{base_url}/robots.txt", timeout=2)
        if r.status_code == 200: bots["robots"] = True
    except: pass
    
    try:
        s = requests.get(f"{base_url}/sitemap.xml", timeout=2)
        if s.status_code == 200: bots["sitemap"] = True
    except: pass
    return bots

def analyze_logic(url: str):
    if not url.startswith(('http://', 'https://')):
        target_url = 'https://' + url
    else:
        target_url = url

    try:
        parsed = urlparse(target_url)
        domain = parsed.netloc
        base_url = f"{parsed.scheme}://{domain}"
        if not domain: return {"error": "Invalid URL"}
    except:
        return {"error": "Invalid URL format"}

    start_time = time.time()
    
    # Main HTTP Request
    try:
        response = requests.get(target_url, timeout=5, headers={'User-Agent': 'DeepInspector/1.0'})
        ttfb = round((time.time() - start_time) * 1000, 2)
        
        # Carbon Calculation
        page_size_bytes = len(response.content)
        co2, eco_grade = calculate_carbon(page_size_bytes)
        page_size_kb = round(page_size_bytes / 1024, 1)

        headers = response.headers
        sec_headers, sec_score = analyze_headers(headers)
        
        # HTML Parsing
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else "No Title"
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        description = meta_desc['content'] if meta_desc else "No Description"
        
        # Link Analysis
        links = {'internal': 0, 'external': 0, 'total': 0}
        socials = []
        all_anchors = soup.find_all('a', href=True)
        links['total'] = len(all_anchors)
        
        for link in all_anchors:
            href = link['href'].lower()
            if any(x in href for x in ['facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com', 'github.com', 'tiktok.com']):
                if href not in socials: socials.append(link['href'])
            
            if href.startswith('/') or domain in href:
                links['internal'] += 1
            elif href.startswith('http'):
                links['external'] += 1

    except Exception as e:
        return {"error": f"Connection Failed: {str(e)}"}

    # Tech Stack
    tech_stack = {}
    try: tech_stack = builtwith.parse(target_url)
    except: pass

    # Whois
    whois_data = {}
    try:
        w = whois.whois(domain)
        whois_data = {
            "registrar": str(w.registrar) if w.registrar else "Unknown",
            "org": str(w.org) if w.org else "Redacted",
            "date": str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date),
            "country": str(w.country) if w.country else "Unknown"
        }
    except: whois_data = {"error": "Hidden"}

    dns_data = get_dns_records(domain)
    bot_access = check_bots(base_url)

    return {
        "overview": {
            "url": target_url,
            "domain": domain,
            "status": response.status_code,
            "ttfb": ttfb,
            "size_kb": page_size_kb,
            "server": headers.get('Server', 'Unknown'),
            "title": title,
            "description": description[:120] + "..." if len(description) > 120 else description
        },
        "eco": {
            "co2_grams": co2,
            "grade": eco_grade
        },
        "links": links,
        "bots": bot_access,
        "tech": tech_stack,
        "security": {
            "score": sec_score,
            "headers": sec_headers
        },
        "dns": dns_data,
        "whois": whois_data,
        "socials": list(set(socials))[:5]
    }

# --- 2. Frontend (HTML/JS) ---

html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deep Inspector | Site Audit Tool</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/alpinejs/3.12.0/cdn.min.js" defer></script>
    <style>
        body { background-color: #0B0E14; color: #cbd5e1; font-family: 'Inter', sans-serif; }
        .glass { background: rgba(30, 41, 59, 0.4); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.05); }
        .glass-panel { background: #151b26; border: 1px solid #1e293b; }
        .tab-btn.active { border-bottom: 2px solid #3b82f6; color: white; background: rgba(59, 130, 246, 0.1); }
        .tab-btn { color: #64748b; }
        .loader { border: 3px solid rgba(255,255,255,0.1); border-top: 3px solid #3b82f6; border-radius: 50%; width: 20px; height: 20px; animation: spin 0.8s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .grade-A, .grade-Ap { color: #22c55e; border-color: #22c55e; }
        .grade-B, .grade-C { color: #eab308; border-color: #eab308; }
        .grade-D, .grade-E, .grade-F { color: #ef4444; border-color: #ef4444; }
    </style>
</head>
<body class="min-h-screen" x-data="app()">

    <nav class="border-b border-gray-800 bg-[#0B0E14] sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div class="flex items-center gap-3">
                    <div class="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
                        <i class="fas fa-bolt text-white text-sm"></i>
                    </div>
                    <span class="font-bold text-xl tracking-tight text-white">Deep Inspector</span>
                </div>
            </div>
        </div>
    </nav>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        
        <div class="max-w-3xl mx-auto text-center mb-12">
            <h1 class="text-4xl font-bold text-white mb-4">Analyze any website instantly.</h1>
            <p class="text-gray-400 mb-8">Get Tech Stack, Carbon Footprint, SEO Links, and Security Headers.</p>
            
            <div class="relative group">
                <div class="absolute -inset-1 bg-gradient-to-r from-blue-600 to-cyan-600 rounded-xl blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
                <div class="relative glass rounded-xl p-2 flex items-center shadow-2xl">
                    <i class="fas fa-search text-gray-500 ml-4"></i>
                    <input type="text" x-model="url" @keydown.enter="analyze()" placeholder="example.com" 
                           class="w-full bg-transparent border-none text-white px-4 py-3 focus:outline-none text-lg placeholder-gray-600">
                    <button @click="analyze()" class="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded-lg font-medium transition-colors flex items-center gap-2" :disabled="loading">
                        <span x-show="!loading">Run Audit</span>
                        <div x-show="loading" class="loader"></div>
                    </button>
                </div>
            </div>
            <p class="text-red-400 text-sm mt-4 font-medium" x-text="error" x-show="error"></p>
        </div>

        <div x-show="results" x-transition.opacity.duration.500ms class="space-y-6">
            
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div class="glass-panel p-5 rounded-xl border-t-2" :class="results?.eco?.grade.includes('A') ? 'grade-Ap' : 'grade-' + results?.eco?.grade">
                    <div class="flex justify-between items-start mb-2">
                        <div class="text-gray-400 text-xs font-bold uppercase">Eco Grade</div>
                        <i class="fas fa-leaf" :class="results?.eco?.grade.includes('A') ? 'grade-Ap' : 'grade-' + results?.eco?.grade"></i>
                    </div>
                    <div class="text-3xl font-bold text-white" x-text="results?.eco?.grade"></div>
                    <div class="text-xs text-gray-500 mt-1"><span x-text="results?.eco?.co2_grams"></span>g CO2 / view</div>
                </div>

                <div class="glass-panel p-5 rounded-xl border-t-2 border-blue-500">
                    <div class="flex justify-between items-start mb-2">
                        <div class="text-gray-400 text-xs font-bold uppercase">Speed</div>
                        <i class="fas fa-tachometer-alt text-blue-500"></i>
                    </div>
                    <div class="text-3xl font-bold text-white"><span x-text="results?.overview?.ttfb"></span><span class="text-lg text-gray-500 ml-1">ms</span></div>
                    <div class="text-xs text-gray-500 mt-1">Page Size: <span x-text="results?.overview?.size_kb"></span> KB</div>
                </div>

                <div class="glass-panel p-5 rounded-xl border-t-2 border-purple-500">
                    <div class="flex justify-between items-start mb-2">
                        <div class="text-gray-400 text-xs font-bold uppercase">Security</div>
                        <i class="fas fa-shield-alt text-purple-500"></i>
                    </div>
                    <div class="text-3xl font-bold text-white"><span x-text="results?.security?.score"></span><span class="text-lg text-gray-500">/100</span></div>
                    <div class="text-xs text-gray-500 mt-1">Headers Check</div>
                </div>

                <div class="glass-panel p-5 rounded-xl border-t-2 border-orange-500">
                    <div class="flex justify-between items-start mb-2">
                        <div class="text-gray-400 text-xs font-bold uppercase">Links</div>
                        <i class="fas fa-link text-orange-500"></i>
                    </div>
                    <div class="text-3xl font-bold text-white" x-text="results?.links?.total"></div>
                    <div class="text-xs text-gray-500 mt-1">
                        Int: <span x-text="results?.links?.internal"></span> | Ext: <span x-text="results?.links?.external"></span>
                    </div>
                </div>
            </div>

            <div class="glass-panel rounded-xl overflow-hidden min-h-[600px]">
                <div class="flex border-b border-gray-800">
                    <button @click="tab = 'tech'" :class="{'active': tab === 'tech'}" class="flex-1 py-4 text-sm font-medium hover:bg-gray-800 transition tab-btn">Stack</button>
                    <button @click="tab = 'seo'" :class="{'active': tab === 'seo'}" class="flex-1 py-4 text-sm font-medium hover:bg-gray-800 transition tab-btn">SEO</button>
                    <button @click="tab = 'security'" :class="{'active': tab === 'security'}" class="flex-1 py-4 text-sm font-medium hover:bg-gray-800 transition tab-btn">Security</button>
                    <button @click="tab = 'dns'" :class="{'active': tab === 'dns'}" class="flex-1 py-4 text-sm font-medium hover:bg-gray-800 transition tab-btn">DNS</button>
                </div>

                <div class="p-6 md:p-8">
                    
                    <div x-show="tab === 'tech'" class="animate-fade-in">
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                            <template x-for="(items, category) in results?.tech">
                                <div class="bg-gray-900/50 rounded-lg p-4 border border-gray-800">
                                    <div class="text-xs font-bold text-gray-500 uppercase tracking-wider mb-3" x-text="category"></div>
                                    <div class="flex flex-wrap gap-2">
                                        <template x-for="item in items">
                                            <span class="bg-blue-500/10 text-blue-400 px-2.5 py-1 rounded text-sm border border-blue-500/20" x-text="item"></span>
                                        </template>
                                    </div>
                                </div>
                            </template>
                        </div>
                        <div x-show="Object.keys(results?.tech || {}).length === 0" class="text-center text-gray-500 py-10">No stack detected.</div>
                    </div>

                    <div x-show="tab === 'seo'" class="animate-fade-in space-y-8">
                        <div class="bg-gray-900/50 p-6 rounded-xl border border-gray-800">
                            <h3 class="text-sm font-bold text-gray-400 uppercase mb-4">Meta Information</h3>
                            <div class="space-y-4">
                                <div><div class="text-xs text-gray-500 mb-1">Title Tag</div><div class="text-lg text-white font-medium" x-text="results?.overview?.title"></div></div>
                                <div><div class="text-xs text-gray-500 mb-1">Meta Description</div><div class="text-gray-400 leading-relaxed" x-text="results?.overview?.description"></div></div>
                            </div>
                        </div>

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div class="bg-gray-900/50 p-6 rounded-xl border border-gray-800 flex justify-between items-center">
                                <div><div class="text-white font-bold">Robots.txt</div><div class="text-xs text-gray-500">Controls crawling</div></div>
                                <span class="px-3 py-1 rounded-full text-xs font-bold" :class="results?.bots?.robots ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'" x-text="results?.bots?.robots ? 'Found' : 'Missing'"></span>
                            </div>
                            <div class="bg-gray-900/50 p-6 rounded-xl border border-gray-800 flex justify-between items-center">
                                <div><div class="text-white font-bold">Sitemap.xml</div><div class="text-xs text-gray-500">Helps indexing</div></div>
                                <span class="px-3 py-1 rounded-full text-xs font-bold" :class="results?.bots?.sitemap ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'" x-text="results?.bots?.sitemap ? 'Found' : 'Missing'"></span>
                            </div>
                        </div>
                        
                         <div x-show="results?.socials?.length > 0">
                            <h3 class="text-sm font-bold text-gray-400 uppercase mb-4">Connected Accounts</h3>
                            <div class="flex flex-wrap gap-3">
                                <template x-for="link in results?.socials">
                                    <a :href="link" target="_blank" class="bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded-lg flex items-center gap-2 text-sm transition text-gray-300">
                                        <i class="fas fa-external-link-alt text-xs"></i>
                                        <span x-text="new URL(link).hostname"></span>
                                    </a>
                                </template>
                            </div>
                        </div>
                    </div>

                    <div x-show="tab === 'security'" class="animate-fade-in">
                        <div class="overflow-hidden rounded-lg border border-gray-800">
                            <table class="w-full text-left">
                                <thead class="bg-gray-900 text-xs text-gray-400 uppercase"><tr><th class="px-6 py-4">Header</th><th class="px-6 py-4 text-right">Status</th></tr></thead>
                                <tbody class="divide-y divide-gray-800 bg-gray-900/30">
                                    <template x-for="(status, header) in results?.security?.headers">
                                        <tr>
                                            <td class="px-6 py-4 font-mono text-sm text-gray-300" x-text="header"></td>
                                            <td class="px-6 py-4 text-right"><span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium" :class="status === 'Present' ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'" x-text="status"></span></td>
                                        </tr>
                                    </template>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div x-show="tab === 'dns'" class="animate-fade-in grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div class="space-y-6">
                            <h3 class="text-sm font-bold text-gray-400 uppercase">DNS Records</h3>
                            <div class="bg-gray-900/50 p-5 rounded-lg border border-gray-800">
                                <div class="mb-4">
                                    <span class="text-xs font-bold text-blue-400 uppercase bg-blue-400/10 px-2 py-1 rounded">MX (Mail)</span>
                                    <ul class="mt-3 space-y-2">
                                        <template x-for="mx in results?.dns?.MX"><li class="font-mono text-sm text-gray-400 truncate" x-text="mx"></li></template>
                                        <li x-show="results?.dns?.MX.length === 0" class="text-gray-600 text-sm italic">No records found</li>
                                    </ul>
                                </div>
                                <div class="border-t border-gray-800 pt-4">
                                    <span class="text-xs font-bold text-purple-400 uppercase bg-purple-400/10 px-2 py-1 rounded">A (Host IP)</span>
                                    <ul class="mt-3 space-y-2"><template x-for="ip in results?.dns?.A"><li class="font-mono text-sm text-gray-400" x-text="ip"></li></template></ul>
                                </div>
                            </div>
                        </div>

                        <div class="space-y-6">
                            <h3 class="text-sm font-bold text-gray-400 uppercase">Ownership</h3>
                            <div class="bg-gray-900/50 p-5 rounded-lg border border-gray-800 space-y-4">
                                <div class="flex justify-between border-b border-gray-800 pb-2"><span class="text-gray-500">Registrar</span><span class="text-white" x-text="results?.whois?.registrar || 'Unknown'"></span></div>
                                <div class="flex justify-between border-b border-gray-800 pb-2"><span class="text-gray-500">Org</span><span class="text-white" x-text="results?.whois?.org || 'Redacted'"></span></div>
                                <div class="flex justify-between"><span class="text-gray-500">Country</span><span class="text-white" x-text="results?.whois?.country || 'Unknown'"></span></div>
                            </div>
                        </div>
                    </div>

                </div>
            </div>
        </div>
    </main>

    <script>
        function app() {
            return {
                url: '',
                loading: false,
                results: null,
                error: null,
                tab: 'tech',
                async analyze() {
                    if (!this.url) return;
                    this.loading = true; this.error = null; this.results = null;
                    try {
                        const res = await fetch('/analyze', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({url: this.url})
                        });
                        const data = await res.json();
                        if (data.error) this.error = data.error;
                        else this.results = data;
                    } catch (e) {
                        this.error = "Could not connect to analysis server.";
                    } finally {
                        this.loading = false;
                    }
                }
            }
        }
    </script>
</body>
</html>
"""

class URLRequest(BaseModel):
    url: str

@app.get("/", response_class=HTMLResponse)
def home():
    return html_content

@app.post("/analyze")
def analyze_route(req: URLRequest):
    return analyze_logic(req.url)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))


