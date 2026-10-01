import json,os
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse
import psycopg2
from passlib.hash import pbkdf2_sha256

def get_db():
    return psycopg2.connect(os.environ["DATABASE_URL"],sslmode="require")

class handler(BaseHTTPRequestHandler):
    def _send(self,status,data):
        body=json.dumps(data).encode()
        self.send_response(status);self.send_header("Content-Type","application/json");self.send_header("Cache-Control","no-store");self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
    def do_POST(self):
        if urlparse(self.path).path!="/api/verify": return self._send(404,{"ok":False,"message":"Not found"})
        try:
            n=int(self.headers.get("Content-Length","0"))
            data=json.loads(self.rfile.read(n))
            pin=str(data.get("pin",""))
            if len(pin)!=6 or not pin.isdigit(): return self._send(400,{"ok":False,"message":"Invalid PIN"})
            with get_db() as db:
                with db.cursor() as cur:
                    cur.execute("SELECT pin_hash FROM pin_settings WHERE id=1")
                    row=cur.fetchone()
            if not row: return self._send(500,{"ok":False,"message":"PIN is not configured"})
            ok=pbkdf2_sha256.verify(pin,row[0])
            return self._send(200 if ok else 401,{"ok":ok,"message":"Access granted" if ok else "Incorrect PIN"})
        except Exception:
            return self._send(500,{"ok":False,"message":"Server error"})
