import builtwith
import whois
import socket
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn
import os

# Initialize App
app = FastAPI(title="Deep Inspector")

# --- Logic ---
def analyze_site_logic(url: str):
    if not url.startswith(('http://', 'https://')):
        target_url = 'http://' + url
    else:
        target_url = url

    domain = target_url.split('//')[-1].split('/')[0]
    
    # 1. Tech Stack
    try:
        tech_stack = builtwith.parse(target_url)
    except:
        tech_stack = {}

    # 2. Whois
    try:
        w = whois.whois(domain)
        whois_info = {
            "registrar": w.registrar,
            "org": w.org,
            "city": w.city,
            "country": w.country
        }
    except:
        whois_info = {"error": "Hidden or Redacted"}

    # 3. IP
    try:
        ip = socket.gethostbyname(domain)
    except:
        ip = "Hidden"

    return {
        "url": target_url,
        "domain": domain,
        "ip": ip,
        "tech": tech_stack,
        "whois": whois_info
    }

# --- Frontend (Single File) ---
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deep Inspector</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #000; color: white; font-family: sans-serif; }
        .glass { background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); }
        .loader { border: 3px solid rgba(255,255,255,0.1); border-top: 3px solid #0070f3; border-radius: 50%; width: 24px; height: 24px; animation: spin 1s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body class="min-h-screen flex flex-col items-center justify-center p-4">
    <div class="w-full max-w-2xl">
        <h1 class="text-5xl font-bold text-center mb-8 bg-clip-text text-transparent bg-gradient-to-r from-white to-gray-500">Deep Inspector</h1>
        
        <div class="glass rounded-xl p-2 flex items-center mb-8">
            <input type="text" id="urlInput" placeholder="example.com" class="w-full bg-transparent border-none text-white px-4 py-3 focus:outline-none text-lg">
            <button onclick="analyze()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg font-bold">Analyze</button>
        </div>

        <div id="loader" class="hidden flex justify-center mb-8"><div class="loader"></div></div>

        <div id="results" class="hidden space-y-6">
            <div class="grid grid-cols-2 gap-4">
                <div class="glass p-5 rounded-xl">
                    <div class="text-gray-400 text-xs font-bold uppercase">Domain</div>
                    <div id="res-domain" class="text-xl font-mono text-cyan-400"></div>
                </div>
                <div class="glass p-5 rounded-xl">
                    <div class="text-gray-400 text-xs font-bold uppercase">IP Address</div>
                    <div id="res-ip" class="text-xl font-mono"></div>
                </div>
            </div>

            <div class="glass rounded-xl p-6 border-t-4 border-blue-600">
                <h2 class="text-xl font-bold mb-4">Technology Stack</h2>
                <div id="tech-grid" class="grid grid-cols-1 md:grid-cols-2 gap-4"></div>
            </div>

            <div class="glass rounded-xl p-6">
                <h2 class="text-xl font-bold mb-4">Domain Info</h2>
                <div id="whois-grid" class="grid grid-cols-1 gap-2 text-sm"></div>
            </div>
        </div>
    </div>

    <script>
        async function analyze() {
            const url = document.getElementById('urlInput').value;
            if(!url) return;
            
            document.getElementById('loader').classList.remove('hidden');
            document.getElementById('results').classList.add('hidden');

            try {
                const res = await fetch('/analyze', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url})
                });
                const data = await res.json();
                
                document.getElementById('res-domain').innerText = data.domain;
                document.getElementById('res-ip').innerText = data.ip;
                
                // Tech
                const techGrid = document.getElementById('tech-grid');
                techGrid.innerHTML = '';
                if(Object.keys(data.tech).length === 0) techGrid.innerHTML = '<span class="text-gray-500">No tech detected</span>';
                for(const [cat, items] of Object.entries(data.tech)) {
                    techGrid.innerHTML += `<div><div class="text-gray-400 text-xs uppercase">${cat}</div><div class="text-sm">${items.join(', ')}</div></div>`;
                }

                // Whois
                const wGrid = document.getElementById('whois-grid');
                wGrid.innerHTML = '';
                for(const [k, v] of Object.entries(data.whois)) {
                    if(v) wGrid.innerHTML += `<div class="flex justify-between border-b border-gray-800 pb-1"><span class="text-gray-400 capitalize">${k}</span><span>${v}</span></div>`;
                }

                document.getElementById('loader').classList.add('hidden');
                document.getElementById('results').classList.remove('hidden');
            } catch(e) {
                alert("Error analyzing site");
                document.getElementById('loader').classList.add('hidden');
            }
        }
    </script>
</body>
</html>
"""

class URLRequest(BaseModel):
    url: str

@app.get("/", response_class=HTMLResponse)
async def home():
    return html_content

@app.post("/analyze")
async def analyze_route(req: URLRequest):
    return analyze_site_logic(req.url)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))


