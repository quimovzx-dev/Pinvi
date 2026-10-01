import os
import psycopg2
from passlib.hash import pbkdf2_sha256

PIN=os.environ.get("PINVI_INITIAL_PIN")
if not PIN or len(PIN)!=6 or not PIN.isdigit(): raise SystemExit("Set PINVI_INITIAL_PIN to a 6-digit PIN")
db=psycopg2.connect(os.environ["DATABASE_URL"],sslmode="require")
with db:
    with db.cursor() as c:
        c.execute("CREATE TABLE IF NOT EXISTS pin_settings (id INTEGER PRIMARY KEY CHECK(id=1), pin_hash TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())")
        c.execute("INSERT INTO pin_settings(id,pin_hash) VALUES(1,%s) ON CONFLICT(id) DO UPDATE SET pin_hash=EXCLUDED.pin_hash,updated_at=now()", (pbkdf2_sha256.hash(PIN),))
print("Pinvi PIN configured.")
