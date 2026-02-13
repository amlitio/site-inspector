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

app = FastAPI(title="Deep Inspector Pro")

# Allow CORS to prevent frontend errors
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Backend Analysis Logic ---

def get_dns_records(domain):
    records = {'MX': [], 'NS': [], 'A': []}
    try:
        # Set a timeout for DNS queries to prevent hanging
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

    except Exception:
        pass # Fail silently on DNS issues
        
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
        # Case insensitive check
        if any(h.lower() == k.lower() for k in headers.keys()):
            security_headers[h] = "Present"
            score += 1
            
    return security_headers, int((score/total)*100)

def analyze_logic(url: str):
    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        target_url = 'https://' + url
    else:
        target_url = url

    try:
        parsed = urlparse(target_url)
        domain = parsed.netloc
        if not domain: return {"error": "Invalid URL"}
    except:
        return {"error": "Invalid URL format"}

    # Initialize results
    start_time = time.time()
    
    # 1. HTTP Request (with timeout to prevent freezing)
    try:
        response = requests.get(target_url, timeout=5, headers={'User-Agent': 'DeepInspector/1.0'})
        ttfb = round((time.time() - start_time) * 1000, 2)
        status_code = response.status_code
        headers = response.headers
        sec_headers, sec_score = analyze_headers(headers)
        
        # HTML Parsing
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else "No Title"
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        description = meta_desc['content'] if meta_desc else "No Description"
        
        # Social Links
        socials = []
        for link in soup.find_all('a', href=True):
            href = link['href'].lower()
            if any(x in href for x in ['facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com', 'github.com']):
                if href not in socials:
                    socials.append(link['href'])
    except Exception as e:
        return {"error": f"Could not connect: {str(e)}"}

    # 2. Tech Stack
    try:
        tech_stack = builtwith.parse(target_url)
    except:
        tech_stack = {}

    # 3. Whois
    try:
        w = whois.whois(domain)
        whois_data = {
            "registrar": str(w.registrar) if w.registrar else "Unknown",
            "org": str(w.org) if w.org else "Redacted",
            "creation_date": str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date),
            "country": str(w.country) if w.country else "Unknown"
        }
    except:
        whois_data = {"error": "Hidden"}

    # 4. DNS
    dns_data = get_dns_records(domain)

    return {
        "overview": {
            "url": target_url,
            "domain": domain,
            "status": status_code,
            "ttfb_ms": ttfb,
            "server": headers.get('Server', 'Unknown'),
            "title": title,
            "description": description[:100] + "..." if len(description) > 100 else description
        },
        "tech": tech_stack,
        "security": {
            "score": sec_score,
            "headers": sec_headers
        },
        "dns": dns_data,
        "whois": whois_data,
        "socials": list(set(socials))[:5]
    }

# --- Frontend ---
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deep Inspector Pro</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/alpinejs/3.12.0/cdn.min.js" defer></script>
    <style>
        body { background-color: #0f1117; color: #e2e8f0; font-family: 'Inter', sans-serif; }
        .glass { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.08); }
        .tab-btn.active { border-bottom: 2px solid #3b82f6; color: white; }
        .tab-btn { color: #94a3b8; }
        .loader { border: 3px solid rgba(255,255,255,0.1); border-top: 3px solid #3b82f6; border-radius: 50%; width: 24px; height: 24px; animation: spin 1s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        /* Scrollbar */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #0f1117; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #475569; }
    </style>
</head>
<body class="min-h-screen" x-data="app()">

    <!-- Navbar -->
    <nav class="border-b border-gray-800 bg-gray-900/50 backdrop-blur-md sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div class="flex items-center">
                    <i class="fas fa-search-location text-blue-500 text-2xl mr-3"></i>
                    <span class="font-bold text-xl tracking-tight">Deep Inspector <span class="text-blue-500 text-sm align-top">PRO</span></span>
                </div>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        
        <!-- Search Hero -->
        <div class="text-center mb-12">
            <h1 class="text-4xl md:text-5xl font-extrabold mb-4 bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-500">
                Analyze Any Website
            </h1>
            <p class="text-gray-400 text-lg mb-8 max-w-2xl mx-auto">
                Full diagnostic report: Tech Stack, Security Headers, DNS Records, and SEO.
            </p>
            
            <div class="max-w-2xl mx-auto relative">
                <div class="glass rounded-xl p-2 flex items-center shadow-2xl transition-all focus-within:ring-2 ring-blue-500/50">
                    <i class="fas fa-globe text-gray-500 ml-4"></i>
                    <input type="text" x-model="url" @keydown.enter="analyze()" placeholder="enter domain (e.g., apple.com)" 
                           class="w-full bg-transparent border-none text-white px-4 py-3 focus:outline-none text-lg placeholder-gray-600">
                    <button @click="analyze()" class="bg-blue-600 hover:bg-blue-500 text-white px-8 py-3 rounded-lg font-semibold transition-colors flex items-center" :disabled="loading">
                        <span x-show="!loading">Analyze</span>
                        <div x-show="loading" class="loader"></div>
                    </button>
                </div>
                <p class="text-red-400 text-sm mt-3 font-semibold" x-text="error" x-show="error"></p>
            </div>
        </div>

        <!-- History Pills -->
        <div class="flex justify-center flex-wrap gap-2 mb-12" x-show="history.length > 0">
            <template x-for="site in history">
                <button @click="url = site; analyze()" class="glass px-4 py-1 rounded-full text-xs text-gray-400 hover:text-white hover:bg-gray-800 transition">
                    <i class="fas fa-history mr-1"></i> <span x-text="site"></span>
                </button>
            </template>
        </div>

        <!-- Results Dashboard -->
        <div x-show="results" x-transition.opacity.duration.500ms class="space-y-6">
            
            <!-- Top Stats Cards -->
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div class="glass p-5 rounded-xl border-l-4 border-blue-500">
                    <div class="text-gray-400 text-xs font-bold uppercase mb-1">Response Time</div>
                    <div class="text-2xl font-mono text-white"><span x-text="results?.overview?.ttfb_ms"></span> <span class="text-sm text-gray-500">ms</span></div>
                </div>
                <div class="glass p-5 rounded-xl border-l-4 border-purple-500">
                    <div class="text-gray-400 text-xs font-bold uppercase mb-1">Security Score</div>
                    <div class="text-2xl font-mono text-white"><span x-text="results?.security?.score"></span><span class="text-sm text-gray-500">%</span></div>
                </div>
                <div class="glass p-5 rounded-xl border-l-4 border-green-500">
                    <div class="text-gray-400 text-xs font-bold uppercase mb-1">Server</div>
                    <div class="text-lg font-mono text-white truncate" x-text="results?.overview?.server"></div>
                </div>
                <div class="glass p-5 rounded-xl border-l-4 border-yellow-500">
                    <div class="text-gray-400 text-xs font-bold uppercase mb-1">Status</div>
                    <div class="text-2xl font-mono text-white" x-text="results?.overview?.status"></div>
                </div>
            </div>

            <!-- Main Tabs Interface -->
            <div class="glass rounded-xl overflow-hidden min-h-[500px]">
                <!-- Tab Headers -->
                <div class="flex border-b border-gray-700 bg-gray-900/30">
                    <button @click="tab = 'tech'" :class="{'active': tab === 'tech', 'text-white': tab === 'tech'}" class="flex-1 py-4 text-sm font-medium hover:bg-gray-800 transition tab-btn">
                        <i class="fas fa-layer-group mb-1 block"></i> Tech
                    </button>
                    <button @click="tab = 'security'" :class="{'active': tab === 'security', 'text-white': tab === 'security'}" class="flex-1 py-4 text-sm font-medium hover:bg-gray-800 transition tab-btn">
                        <i class="fas fa-shield-alt mb-1 block"></i> Security
                    </button>
                    <button @click="tab = 'seo'" :class="{'active': tab === 'seo', 'text-white': tab === 'seo'}" class="flex-1 py-4 text-sm font-medium hover:bg-gray-800 transition tab-btn">
                        <i class="fas fa-search mb-1 block"></i> SEO
                    </button>
                    <button @click="tab = 'dns'" :class="{'active': tab === 'dns', 'text-white': tab === 'dns'}" class="flex-1 py-4 text-sm font-medium hover:bg-gray-800 transition tab-btn">
                        <i class="fas fa-network-wired mb-1 block"></i> DNS
                    </button>
                </div>

                <!-- Tab Content -->
                <div class="p-6 md:p-8">
                    
                    <!-- Tech Stack Tab -->
                    <div x-show="tab === 'tech'">
                        <h3 class="text-xl font-bold mb-6 text-blue-400">Detected Technologies</h3>
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            <template x-for="(items, category) in results?.tech">
                                <div class="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                    <div class="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3" x-text="category"></div>
                                    <div class="flex flex-wrap gap-2">
                                        <template x-for="item in items">
                                            <span class="bg-blue-900/30 text-blue-200 px-2 py-1 rounded text-sm border border-blue-500/20" x-text="item"></span>
                                        </template>
                                    </div>
                                </div>
                            </template>
                        </div>
                        <div x-show="Object.keys(results?.tech || {}).length === 0" class="text-center text-gray-500 py-10">
                            No specific technologies detected or site is hidden.
                        </div>
                    </div>

                    <!-- Security Tab -->
                    <div x-show="tab === 'security'">
                        <div class="flex items-center justify-between mb-6">
                            <h3 class="text-xl font-bold text-purple-400">Security Headers</h3>
                            <div class="text-sm bg-gray-800 px-3 py-1 rounded-full">Score: <span x-text="results?.security?.score"></span>/100</div>
                        </div>
                        <div class="overflow-x-auto">
                            <table class="w-full text-left">
                                <thead class="text-xs text-gray-400 uppercase bg-gray-800/50">
                                    <tr>
                                        <th class="px-4 py-3 rounded-l-lg">Header Name</th>
                                        <th class="px-4 py-3 rounded-r-lg">Status</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-gray-800">
                                    <template x-for="(status, header) in results?.security?.headers">
                                        <tr>
                                            <td class="px-4 py-3 font-mono text-sm text-gray-300" x-text="header"></td>
                                            <td class="px-4 py-3">
                                                <span class="px-2 py-1 rounded text-xs font-bold" 
                                                      :class="status === 'Present' ? 'bg-green-900 text-green-300' : 'bg-red-900/50 text-red-300'"
                                                      x-text="status"></span>
                                            </td>
                                        </tr>
                                    </template>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- SEO Tab -->
                    <div x-show="tab === 'seo'">
                        <div class="space-y-6">
                            <div>
                                <div class="text-xs font-bold text-gray-500 uppercase mb-2">Page Title</div>
                                <div class="bg-gray-800/50 p-4 rounded-lg border-l-4 border-green-500 font-serif text-lg" x-text="results?.overview?.title"></div>
                            </div>
                            <div>
                                <div class="text-xs font-bold text-gray-500 uppercase mb-2">Meta Description</div>
                                <div class="bg-gray-800/50 p-4 rounded-lg text-gray-300 leading-relaxed" x-text="results?.overview?.description"></div>
                            </div>
                            <div>
                                <div class="text-xs font-bold text-gray-500 uppercase mb-2">Social Links Found</div>
                                <div class="flex flex-wrap gap-3">
                                    <template x-for="link in results?.socials">
                                        <a :href="link" target="_blank" class="bg-gray-700 hover:bg-gray-600 px-3 py-2 rounded flex items-center gap-2 text-sm transition">
                                            <i class="fas fa-link text-gray-400"></i>
                                            <span x-text="new URL(link).hostname"></span>
                                        </a>
                                    </template>
                                    <span x-show="results?.socials.length === 0" class="text-gray-500 italic">No social links found on homepage.</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- DNS Tab -->
                    <div x-show="tab === 'dns'">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                            <!-- DNS Records -->
                            <div class="space-y-4">
                                <h4 class="font-bold text-gray-300 border-b border-gray-700 pb-2">DNS Records</h4>
                                
                                <div>
                                    <span class="badge bg-blue-900 text-blue-200 text-xs px-2 py-1 rounded">A Records (IPs)</span>
                                    <ul class="mt-2 space-y-1">
                                        <template x-for="ip in results?.dns?.A">
                                            <li class="font-mono text-sm text-gray-400" x-text="ip"></li>
                                        </template>
                                    </ul>
                                </div>
                                
                                <div>
                                    <span class="badge bg-purple-900 text-purple-200 text-xs px-2 py-1 rounded">MX Records (Mail)</span>
                                    <ul class="mt-2 space-y-1">
                                        <template x-for="mx in results?.dns?.MX">
                                            <li class="font-mono text-sm text-gray-400" x-text="mx"></li>
                                        </template>
                                        <li x-show="results?.dns?.MX.length === 0" class="text-gray-600 text-sm italic">No MX records found</li>
                                    </ul>
                                </div>
                            </div>

                            <!-- Whois -->
                            <div class="space-y-4">
                                <h4 class="font-bold text-gray-300 border-b border-gray-700 pb-2">Domain Ownership</h4>
                                <div class="bg-gray-800/50 rounded-lg p-4 space-y-3">
                                    <div class="flex justify-between">
                                        <span class="text-gray-500">Registrar</span>
                                        <span class="text-white text-right" x-text="results?.whois?.registrar || 'Unknown'"></span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-gray-500">Registered On</span>
                                        <span class="text-white text-right" x-text="results?.whois?.creation_date || 'Unknown'"></span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-gray-500">Organization</span>
                                        <span class="text-white text-right" x-text="results?.whois?.org || 'Redacted'"></span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-gray-500">Country</span>
                                        <span class="text-white text-right" x-text="results?.whois?.country || 'Unknown'"></span>
                                    </div>
                                </div>
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
                history: JSON.parse(localStorage.getItem('scan_history') || '[]'),

                async analyze() {
                    if (!this.url) return;
                    
                    this.loading = true;
                    this.error = null;
                    this.results = null;

                    // Add to history
                    if (!this.history.includes(this.url)) {
                        this.history.unshift(this.url);
                        if (this.history.length > 5) this.history.pop();
                        localStorage.setItem('scan_history', JSON.stringify(this.history));
                    }

                    try {
                        const res = await fetch('/analyze', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({url: this.url})
                        });
                        
                        const data = await res.json();
                        
                        if (data.error) {
                            this.error = data.error;
                        } else {
                            this.results = data;
                        }
                    } catch (e) {
                        this.error = "Server Error: Could not connect to API.";
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

# NOTE: Removed 'async' from here to prevent blocking in FastAPI
@app.post("/analyze")
def analyze_route(req: URLRequest):
    return analyze_logic(req.url)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))


