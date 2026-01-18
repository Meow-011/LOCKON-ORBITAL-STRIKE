import sqlite3
import json
from datetime import datetime
import os

DB_FILE = "lockon_history.db"

def init_db():
    """Initialize the SQLite database schema."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Table: Scans
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        timestamp TEXT,
        profile TEXT,
        total_findings INTEGER,
        critical_count INTEGER,
        high_count INTEGER,
        medium_count INTEGER,
        low_count INTEGER
    )''')
    
    # Table: Findings
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        type TEXT,
        severity TEXT,
        category TEXT,
        detail TEXT,
        evidence TEXT,
        remediation TEXT,
        exploit_type TEXT,
        exploit_data TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )''')
    
    # [FIX] Migration for existing DB
    try:
        c.execute("ALTER TABLE findings ADD COLUMN exploit_type TEXT")
        c.execute("ALTER TABLE findings ADD COLUMN exploit_data TEXT")
    except sqlite3.OperationalError:
        pass # Columns already exist
    
    conn.commit()
    conn.close()

def save_scan_result(target, profile, findings):
    """Saves a completed scan and its findings to the database."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Calculate Stats
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.get('severity', 'Info')
        if sev in stats: stats[sev] += 1
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Insert Scan
    c.execute('''INSERT INTO scans 
        (target, timestamp, profile, total_findings, critical_count, high_count, medium_count, low_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
        (target, timestamp, profile, len(findings), 
         stats['Critical'], stats['High'], stats['Medium'], stats['Low']))
    
    scan_id = c.lastrowid
    
    # Insert Findings
    for f in findings:
        ex_data = json.dumps(f.get('exploit_data')) if f.get('exploit_data') else None
        
        c.execute('''INSERT INTO findings 
            (scan_id, type, severity, category, detail, evidence, remediation, exploit_type, exploit_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (scan_id, f.get('type'), f.get('severity'), f.get('category'), 
             f.get('detail'), str(f.get('evidence')), f.get('remediation'),
             f.get('exploit_type'), ex_data))
             
    conn.commit()
    conn.close()
    return scan_id

def get_scan_history():
    """Returns list of all scans."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY id DESC")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

def get_scan_findings(scan_id):
    """Returns findings for a specific scan."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows