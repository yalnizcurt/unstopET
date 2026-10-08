"""Bounded, temporary demo history. No raw binary uploads or credentials are retained."""
from datetime import datetime, timezone
import json
import sqlite3
import threading
import secrets
import time

class Store:
    def __init__(self, path=':memory:'):
        self.db=sqlite3.connect(path,check_same_thread=False); self.lock=threading.RLock()
        self.db.execute('CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, kind TEXT, principal TEXT, created REAL, data TEXT)')
        self.db.execute('CREATE INDEX IF NOT EXISTS record_kind ON records(kind,principal,created)')
    def put(self,kind,data,principal='demo-owner',record_id=None):
        identity=record_id or secrets.token_hex(16); now=time.time()
        record=dict(data, id=identity,created_at=data.get('created_at',datetime.now(timezone.utc).isoformat()),schema_version=1)
        with self.lock:
            self.db.execute('INSERT OR REPLACE INTO records VALUES (?,?,?,?,?)',(identity,kind,principal,now,json.dumps(record)))
            self.db.execute('DELETE FROM records WHERE created < ?',(now-86400,))
            self.db.execute('DELETE FROM records WHERE id IN (SELECT id FROM records ORDER BY created DESC LIMIT -1 OFFSET 300)')
            self.db.commit()
        return record
    def list(self,kind,principal='demo-owner'):
        with self.lock: rows=self.db.execute('SELECT data FROM records WHERE kind=? AND principal=? ORDER BY created DESC LIMIT 100',(kind,principal)).fetchall()
        return [json.loads(row[0]) for row in rows]
    def get(self,identity,kind,principal='demo-owner'):
        with self.lock: row=self.db.execute('SELECT data FROM records WHERE id=? AND kind=? AND principal=?',(identity,kind,principal)).fetchone()
        return json.loads(row[0]) if row else None
