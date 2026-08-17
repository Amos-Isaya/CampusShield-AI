#!/usr/bin/env python3
"""CampusShield AI — dependency-free application server."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta
import hashlib, hmac, json, mimetypes, os, re, secrets, sqlite3, time

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "campusshield.db"
HOST, PORT = "127.0.0.1", int(os.getenv("CAMPUSSHIELD_PORT", "8080"))
MAX_BODY = 1_000_000
LOGIN_ATTEMPTS = {}

def now(): return datetime.now(timezone.utc).isoformat()
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310_000).hex()
    return f"{salt}${digest}"

def password_valid(password, stored):
    try:
        salt, expected = stored.split("$", 1)
        return hmac.compare_digest(password_hash(password, salt).split("$", 1)[1], expected)
    except ValueError: return False

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('student','analyst')), created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, reporter_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL, incident_type TEXT NOT NULL, description TEXT NOT NULL, suspicious_content TEXT NOT NULL DEFAULT '', risk_score INTEGER NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new', analysis TEXT NOT NULL, indicators TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), action TEXT NOT NULL, resource TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL);
        """)
        for name,email,password,role in [
            ("Jordan Student","student@campus.edu","Demo123!","student"),
            ("Morgan Analyst","analyst@campus.edu","Admin123!","analyst")]:
            c.execute("INSERT OR IGNORE INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",(name,email,password_hash(password),role,now()))
        if c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0:
            reporter=c.execute("SELECT id FROM users WHERE email='student@campus.edu'").fetchone()[0]
            samples=[
                ("Fake Microsoft password warning","phishing","An email says my campus account will be suspended today.","Verify your password immediately: https://bit.ly/campus-login","investigating"),
                ("Unexpected invoice attachment","malware","I received an invoice from a sender I do not recognize.","Open the attached invoice.zip to receive your refund.","new"),
                ("Unrecognized account sign-in","account","A sign-in notification showed a device I do not own.","","resolved")]
            for title,kind,description,content,status in samples:
                score,severity,analysis,indicators=analyze({"title":title,"incident_type":kind,"description":description,"suspicious_content":content});stamp=now()
                c.execute("INSERT INTO incidents(reporter_id,title,incident_type,description,suspicious_content,risk_score,severity,status,analysis,indicators,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(reporter,title,kind,description,content,score,severity,status,json.dumps(analysis),json.dumps(indicators),stamp,stamp))

def audit(conn, user_id, action, resource, detail=""):
    conn.execute("INSERT INTO audit_logs(user_id,action,resource,detail,created_at) VALUES(?,?,?,?,?)",(user_id,action,resource,detail[:300],now()))

RULES = [
    (r"\b(password|passcode|login|verify your account|credentials?)\b", 18, "Requests account credentials"),
    (r"\b(urgent|immediately|within 24 hours|final warning|act now)\b", 12, "Uses urgency or pressure"),
    (r"\b(gift card|wire transfer|bitcoin|crypto|payment|refund)\b", 18, "References an unusual payment"),
    (r"\b(click here|open attachment|download|scan (the )?qr)\b", 10, "Encourages a risky action"),
    (r"\b(suspended|locked|deactivated|compromised)\b", 12, "Threatens account loss"),
    (r"https?://(?:\d{1,3}\.){3}\d{1,3}", 22, "Uses an IP-address link"),
    (r"https?://[^\s]*(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl)", 15, "Uses a shortened link"),
    (r"\.(?:zip|exe|scr|js|iso|html?)\b", 20, "References a potentially dangerous file")]

def analyze(payload):
    text = " ".join(str(payload.get(k,"")) for k in ("title","description","suspicious_content")).lower()
    score, indicators = 5, []
    for pattern, points, label in RULES:
        if re.search(pattern,text,re.I): score += points; indicators.append(label)
    urls = re.findall(r"https?://[^\s<>\]\)]+", text, re.I)
    if urls:
        score += min(18, len(urls)*6); indicators.append(f"Contains {len(urls)} external link{'s' if len(urls)!=1 else ''}")
    if payload.get("incident_type") in ("malware","account"): score += 12
    score=min(100,score)
    severity="critical" if score>=75 else "high" if score>=50 else "medium" if score>=25 else "low"
    recommendation={"critical":"Disconnect the affected device, do not interact further, and contact campus IT immediately.","high":"Do not click links or reply. Preserve the message and ask campus IT to verify it.","medium":"Verify the sender through a trusted channel before taking action.","low":"No strong threat indicators were detected, but remain cautious and verify unexpected requests."}[severity]
    return score,severity,{"summary":f"The report was classified as {severity} risk with a score of {score}/100.","recommendation":recommendation,"method":"Transparent rule-based triage; an analyst must verify the result."},indicators or ["No common high-risk language detected"]

class App(BaseHTTPRequestHandler):
    server_version="CampusShield/1.0"
    def log_message(self, fmt, *args): print(f"[{self.log_date_time_string()}] {fmt%args}")
    def send_json(self,data,status=200):
        raw=json.dumps(data).encode(); self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(raw))); self.security_headers(); self.end_headers(); self.wfile.write(raw)
    def security_headers(self):
        self.send_header("X-Content-Type-Options","nosniff"); self.send_header("X-Frame-Options","DENY"); self.send_header("Referrer-Policy","no-referrer"); self.send_header("Permissions-Policy","camera=(), microphone=(), geolocation=()"); self.send_header("Content-Security-Policy","default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; script-src 'self'; connect-src 'self'")
    def body(self):
        try:
            size=int(self.headers.get("Content-Length","0"));
            if size>MAX_BODY: return None
            return json.loads(self.rfile.read(size) or b"{}")
        except (ValueError,json.JSONDecodeError): return None
    def user(self):
        auth=self.headers.get("Authorization","")
        if not auth.startswith("Bearer "): return None
        token_hash=hashlib.sha256(auth[7:].encode()).hexdigest()
        with db() as c:
            return c.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?",(token_hash,now())).fetchone()
    def require_user(self,role=None):
        user=self.user()
        if not user: self.send_json({"error":"Authentication required"},401); return None
        if role and user["role"]!=role: self.send_json({"error":"Insufficient permissions"},403); return None
        return user
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/api/health": return self.send_json({"status":"ok","time":now()})
        if path=="/api/me":
            u=self.require_user();
            if u: self.send_json({"user":{"id":u["id"],"name":u["name"],"email":u["email"],"role":u["role"]}})
            return
        if path=="/api/incidents": return self.get_incidents()
        if path=="/api/stats": return self.get_stats()
        if path=="/api/audit": return self.get_audit()
        self.static(path)
    def do_POST(self):
        path=urlparse(self.path).path
        if path=="/api/login": return self.login()
        if path=="/api/logout": return self.logout()
        if path=="/api/incidents": return self.create_incident()
        self.send_json({"error":"Not found"},404)
    def do_PATCH(self):
        match=re.fullmatch(r"/api/incidents/(\d+)",urlparse(self.path).path)
        if match:return self.update_incident(int(match.group(1)))
        self.send_json({"error":"Not found"},404)
    def login(self):
        data=self.body()
        if not data:return self.send_json({"error":"Invalid request"},400)
        ip=self.client_address[0]; recent=[t for t in LOGIN_ATTEMPTS.get(ip,[]) if time.time()-t<300]
        if len(recent)>=8:return self.send_json({"error":"Too many attempts. Try again later."},429)
        email=str(data.get("email","")).lower().strip(); password=str(data.get("password",""))
        with db() as c:
            u=c.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
            if not u or not password_valid(password,u["password_hash"]):
                recent.append(time.time());LOGIN_ATTEMPTS[ip]=recent;return self.send_json({"error":"Invalid email or password"},401)
            token=secrets.token_urlsafe(32); expiry=(datetime.now(timezone.utc)+timedelta(hours=12)).isoformat()
            c.execute("DELETE FROM sessions WHERE expires_at<=?",(now(),));c.execute("INSERT INTO sessions VALUES(?,?,?)",(hashlib.sha256(token.encode()).hexdigest(),u["id"],expiry));audit(c,u["id"],"login","session","Successful sign in")
        self.send_json({"token":token,"user":{"id":u["id"],"name":u["name"],"email":u["email"],"role":u["role"]}})
    def logout(self):
        u=self.require_user();
        if not u:return
        token_hash=hashlib.sha256(self.headers["Authorization"][7:].encode()).hexdigest()
        with db() as c:c.execute("DELETE FROM sessions WHERE token_hash=?",(token_hash,));audit(c,u["id"],"logout","session")
        self.send_json({"ok":True})
    def get_incidents(self):
        u=self.require_user();
        if not u:return
        with db() as c:
            if u["role"]=="analyst": rows=c.execute("SELECT i.*,u.name reporter_name,u.email reporter_email FROM incidents i JOIN users u ON u.id=i.reporter_id ORDER BY i.created_at DESC").fetchall()
            else: rows=c.execute("SELECT i.*,u.name reporter_name,u.email reporter_email FROM incidents i JOIN users u ON u.id=i.reporter_id WHERE reporter_id=? ORDER BY i.created_at DESC",(u["id"],)).fetchall()
        self.send_json({"incidents":[dict(r)|{"analysis":json.loads(r["analysis"]),"indicators":json.loads(r["indicators"])} for r in rows]})
    def create_incident(self):
        u=self.require_user();data=self.body()
        if not u:return
        if not data:return self.send_json({"error":"Invalid request"},400)
        fields={k:str(data.get(k,"")).strip() for k in ("title","incident_type","description","suspicious_content")}
        if not fields["title"] or not fields["description"] or fields["incident_type"] not in ("phishing","malware","account","harassment","other"):return self.send_json({"error":"Complete all required fields"},422)
        if len(fields["title"])>120 or len(fields["description"])>4000 or len(fields["suspicious_content"])>8000:return self.send_json({"error":"Report is too long"},422)
        score,severity,analysis,indicators=analyze(fields);stamp=now()
        with db() as c:
            cur=c.execute("INSERT INTO incidents(reporter_id,title,incident_type,description,suspicious_content,risk_score,severity,status,analysis,indicators,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(u["id"],fields["title"],fields["incident_type"],fields["description"],fields["suspicious_content"],score,severity,"new",json.dumps(analysis),json.dumps(indicators),stamp,stamp));audit(c,u["id"],"create","incident",f"Created incident #{cur.lastrowid}")
        self.send_json({"id":cur.lastrowid,"risk_score":score,"severity":severity,"analysis":analysis,"indicators":indicators},201)
    def update_incident(self,incident_id):
        u=self.require_user("analyst");data=self.body()
        if not u:return
        status=str((data or {}).get("status",""))
        if status not in ("new","investigating","contained","resolved"):return self.send_json({"error":"Invalid status"},422)
        with db() as c:
            if not c.execute("SELECT 1 FROM incidents WHERE id=?",(incident_id,)).fetchone():return self.send_json({"error":"Incident not found"},404)
            c.execute("UPDATE incidents SET status=?,updated_at=? WHERE id=?",(status,now(),incident_id));audit(c,u["id"],"update","incident",f"Set incident #{incident_id} to {status}")
        self.send_json({"ok":True})
    def get_stats(self):
        u=self.require_user("analyst");
        if not u:return
        with db() as c:
            totals=dict(c.execute("SELECT COUNT(*) total, SUM(status='new') new_count, SUM(severity IN ('high','critical')) high_count, SUM(status='resolved') resolved FROM incidents").fetchone());types=[dict(r) for r in c.execute("SELECT incident_type label,COUNT(*) value FROM incidents GROUP BY incident_type ORDER BY value DESC")];severities=[dict(r) for r in c.execute("SELECT severity label,COUNT(*) value FROM incidents GROUP BY severity")]
        self.send_json({"totals":totals,"types":types,"severities":severities})
    def get_audit(self):
        u=self.require_user("analyst");
        if not u:return
        with db() as c:rows=c.execute("SELECT a.*,u.name user_name FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 50").fetchall()
        self.send_json({"logs":[dict(r) for r in rows]})
    def static(self,path):
        if path=="/":path="/index.html"
        target=(ROOT/"public"/path.lstrip("/")).resolve();base=(ROOT/"public").resolve()
        if base not in target.parents and target!=base:return self.send_json({"error":"Not found"},404)
        if not target.is_file():target=base/"index.html"
        raw=target.read_bytes();self.send_response(200);self.send_header("Content-Type",mimetypes.guess_type(target)[0] or "application/octet-stream");self.send_header("Content-Length",str(len(raw)));self.security_headers();self.end_headers();self.wfile.write(raw)

if __name__=="__main__":
    init_db();print(f"CampusShield AI running at http://{HOST}:{PORT}");ThreadingHTTPServer((HOST,PORT),App).serve_forever()
