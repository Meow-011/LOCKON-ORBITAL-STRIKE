"""
Scan Scheduler
Schedule scans to run at specified intervals with SQLite persistence.
"""
import sqlite3
import threading
import time
import os
from datetime import datetime, timedelta


DB_PATH = os.path.join("data", "scheduler.db")


def _ensure_db():
    """Initialize the scheduler database."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            profile TEXT DEFAULT 'Full Scan',
            interval TEXT DEFAULT 'daily',
            next_run TEXT NOT NULL,
            last_run TEXT,
            enabled INTEGER DEFAULT 1,
            modules_config TEXT DEFAULT '{}',
            created_at TEXT DEFAULT (datetime('now', 'localtime'))
        )
    """)
    conn.commit()
    conn.close()


_ensure_db()


class ScanScheduler:
    """Manages scheduled scans with background monitoring."""
    
    INTERVALS = {
        "once": None,
        "hourly": timedelta(hours=1),
        "daily": timedelta(days=1),
        "weekly": timedelta(weeks=1),
        "monthly": timedelta(days=30),
    }
    
    def __init__(self, scan_trigger_callback=None, log_callback=None):
        """
        Args:
            scan_trigger_callback: Function(target, profile, modules_config) → triggers a scan
            log_callback: Function(msg) → logs a message
        """
        self.scan_trigger = scan_trigger_callback
        self.log = log_callback or (lambda msg: None)
        self._running = False
        self._thread = None
    
    def add_schedule(self, target, profile="Full Scan", interval="daily", modules_config="{}"):
        """Add a new scheduled scan."""
        if interval not in self.INTERVALS:
            raise ValueError(f"Invalid interval: {interval}. Must be one of: {list(self.INTERVALS.keys())}")
        
        # Calculate next run time
        now = datetime.now()
        if interval == "once":
            next_run = now + timedelta(minutes=1)
        elif interval == "hourly":
            next_run = now + timedelta(hours=1)
        elif interval == "daily":
            next_run = now + timedelta(days=1)
        elif interval == "weekly":
            next_run = now + timedelta(weeks=1)
        elif interval == "monthly":
            next_run = now + timedelta(days=30)
        else:
            next_run = now + timedelta(days=1)
        
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO schedules (target, profile, interval, next_run, modules_config) VALUES (?, ?, ?, ?, ?)",
            (target, profile, interval, next_run.isoformat(), modules_config)
        )
        conn.commit()
        conn.close()
        
        self.log(f"📅 Scheduled: {target} → {interval} (next: {next_run.strftime('%Y-%m-%d %H:%M')})")
        return True
    
    def get_schedules(self):
        """Get all scheduled scans."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM schedules ORDER BY next_run ASC").fetchall()
        conn.close()
        return [dict(r) for r in rows]
    
    def delete_schedule(self, schedule_id):
        """Delete a scheduled scan."""
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
        conn.commit()
        conn.close()
    
    def toggle_schedule(self, schedule_id, enabled=True):
        """Enable or disable a scheduled scan."""
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE schedules SET enabled = ? WHERE id = ?", (1 if enabled else 0, schedule_id))
        conn.commit()
        conn.close()
    
    def _check_and_run(self):
        """Check for due schedules and trigger scans."""
        now = datetime.now()
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        
        due = conn.execute(
            "SELECT * FROM schedules WHERE enabled = 1 AND next_run <= ?",
            (now.isoformat(),)
        ).fetchall()
        
        for schedule in due:
            target = schedule['target']
            profile = schedule['profile']
            interval = schedule['interval']
            schedule_id = schedule['id']
            
            self.log(f"⏰ Scheduled scan triggered: {target} ({interval})")
            
            # Trigger the scan
            if self.scan_trigger:
                try:
                    self.scan_trigger(target, profile, schedule['modules_config'])
                except Exception as e:
                    self.log(f"❌ Scheduled scan failed: {e}")
            
            # Update next run time
            if interval == "once":
                conn.execute("UPDATE schedules SET enabled = 0, last_run = ? WHERE id = ?",
                           (now.isoformat(), schedule_id))
            else:
                delta = self.INTERVALS.get(interval, timedelta(days=1))
                next_run = now + delta
                conn.execute(
                    "UPDATE schedules SET next_run = ?, last_run = ? WHERE id = ?",
                    (next_run.isoformat(), now.isoformat(), schedule_id)
                )
        
        conn.commit()
        conn.close()
    
    def start(self):
        """Start the scheduler background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        self.log("📅 Scheduler started (checking every 60s)")
    
    def stop(self):
        """Stop the scheduler."""
        self._running = False
    
    def _monitor_loop(self):
        """Background loop that checks for due scans every 60 seconds."""
        while self._running:
            try:
                self._check_and_run()
            except Exception as e:
                if self.log:
                    self.log(f"Scheduler error: {e}")
            time.sleep(60)
