"""
Team Collaboration Module
Finding assignment, comments, status tracking, and team management.
Stored in SQLite for local/small team use.
"""
import sqlite3
import os
import json
from datetime import datetime


DB_PATH = os.path.join("data", "collaboration.db")


def _ensure_db():
    """Initialize the collaboration database."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS finding_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_hash TEXT NOT NULL,
            assigned_to TEXT,
            status TEXT DEFAULT 'open',
            priority TEXT DEFAULT 'normal',
            due_date TEXT,
            created_at TEXT DEFAULT (datetime('now', 'localtime')),
            updated_at TEXT DEFAULT (datetime('now', 'localtime'))
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS finding_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_hash TEXT NOT NULL,
            author TEXT DEFAULT 'Analyst',
            content TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now', 'localtime'))
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS team_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'analyst',
            email TEXT,
            created_at TEXT DEFAULT (datetime('now', 'localtime'))
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS finding_status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_hash TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'open',
            verified INTEGER DEFAULT 0,
            false_positive INTEGER DEFAULT 0,
            notes TEXT DEFAULT '',
            updated_at TEXT DEFAULT (datetime('now', 'localtime'))
        )
    """)
    
    conn.commit()
    conn.close()


_ensure_db()


class CollaborationManager:
    """Manages team collaboration features for findings."""
    
    STATUSES = ["open", "in_progress", "verified", "false_positive", "fixed", "accepted_risk", "wont_fix"]
    PRIORITIES = ["critical", "high", "normal", "low"]
    
    @staticmethod
    def _finding_hash(finding):
        """Generate a hash for a finding based on type + detail."""
        ftype = finding.get('type', '')
        detail = finding.get('detail', finding.get('url', ''))
        return f"{ftype}|||{detail}"[:200]
    
    # --- Assignment ---
    
    @staticmethod
    def assign_finding(finding, assigned_to, priority="normal", due_date=None):
        """Assign a finding to a team member."""
        fhash = CollaborationManager._finding_hash(finding)
        conn = sqlite3.connect(DB_PATH)
        
        # Upsert
        existing = conn.execute(
            "SELECT id FROM finding_assignments WHERE finding_hash = ?", (fhash,)
        ).fetchone()
        
        if existing:
            conn.execute(
                "UPDATE finding_assignments SET assigned_to = ?, priority = ?, due_date = ?, updated_at = ? WHERE finding_hash = ?",
                (assigned_to, priority, due_date, datetime.now().isoformat(), fhash)
            )
        else:
            conn.execute(
                "INSERT INTO finding_assignments (finding_hash, assigned_to, priority, due_date) VALUES (?, ?, ?, ?)",
                (fhash, assigned_to, priority, due_date)
            )
        
        conn.commit()
        conn.close()
    
    @staticmethod
    def get_assignment(finding):
        """Get the assignment info for a finding."""
        fhash = CollaborationManager._finding_hash(finding)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM finding_assignments WHERE finding_hash = ?", (fhash,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    
    @staticmethod
    def get_all_assignments():
        """Get all finding assignments."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM finding_assignments ORDER BY updated_at DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]
    
    # --- Comments ---
    
    @staticmethod
    def add_comment(finding, author, content):
        """Add a comment to a finding."""
        fhash = CollaborationManager._finding_hash(finding)
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO finding_comments (finding_hash, author, content) VALUES (?, ?, ?)",
            (fhash, author, content)
        )
        conn.commit()
        conn.close()
    
    @staticmethod
    def get_comments(finding):
        """Get all comments for a finding."""
        fhash = CollaborationManager._finding_hash(finding)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM finding_comments WHERE finding_hash = ? ORDER BY created_at ASC", (fhash,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    
    # --- Status ---
    
    @staticmethod
    def set_status(finding, status, verified=False, false_positive=False, notes=""):
        """Set the triage status of a finding."""
        fhash = CollaborationManager._finding_hash(finding)
        conn = sqlite3.connect(DB_PATH)
        
        conn.execute("""
            INSERT INTO finding_status (finding_hash, status, verified, false_positive, notes)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(finding_hash) DO UPDATE SET
                status = excluded.status,
                verified = excluded.verified,
                false_positive = excluded.false_positive,
                notes = excluded.notes,
                updated_at = datetime('now', 'localtime')
        """, (fhash, status, 1 if verified else 0, 1 if false_positive else 0, notes))
        
        conn.commit()
        conn.close()
    
    @staticmethod
    def get_status(finding):
        """Get the triage status of a finding."""
        fhash = CollaborationManager._finding_hash(finding)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM finding_status WHERE finding_hash = ?", (fhash,)
        ).fetchone()
        conn.close()
        return dict(row) if row else {"status": "open", "verified": False, "false_positive": False, "notes": ""}
    
    # --- Team Members ---
    
    @staticmethod
    def add_member(name, role="analyst", email=""):
        """Add a team member."""
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute(
                "INSERT INTO team_members (name, role, email) VALUES (?, ?, ?)",
                (name, role, email)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # Already exists
        conn.close()
    
    @staticmethod
    def get_members():
        """Get all team members."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM team_members ORDER BY name").fetchall()
        conn.close()
        return [dict(r) for r in rows]
    
    @staticmethod
    def remove_member(name):
        """Remove a team member."""
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM team_members WHERE name = ?", (name,))
        conn.commit()
        conn.close()
    
    # --- Dashboard Stats ---
    
    @staticmethod
    def get_dashboard_stats():
        """Get collaboration dashboard statistics."""
        conn = sqlite3.connect(DB_PATH)
        
        total = conn.execute("SELECT COUNT(*) FROM finding_status").fetchone()[0]
        open_count = conn.execute("SELECT COUNT(*) FROM finding_status WHERE status = 'open'").fetchone()[0]
        in_progress = conn.execute("SELECT COUNT(*) FROM finding_status WHERE status = 'in_progress'").fetchone()[0]
        verified = conn.execute("SELECT COUNT(*) FROM finding_status WHERE verified = 1").fetchone()[0]
        false_pos = conn.execute("SELECT COUNT(*) FROM finding_status WHERE false_positive = 1").fetchone()[0]
        fixed = conn.execute("SELECT COUNT(*) FROM finding_status WHERE status = 'fixed'").fetchone()[0]
        total_comments = conn.execute("SELECT COUNT(*) FROM finding_comments").fetchone()[0]
        total_assignments = conn.execute("SELECT COUNT(*) FROM finding_assignments").fetchone()[0]
        
        conn.close()
        
        return {
            "total_tracked": total,
            "open": open_count,
            "in_progress": in_progress,
            "verified": verified,
            "false_positives": false_pos,
            "fixed": fixed,
            "total_comments": total_comments,
            "total_assignments": total_assignments,
        }
