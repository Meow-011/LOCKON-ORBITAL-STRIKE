"""
Scan Queue Manager
Manages multi-target scan campaigns with configurable concurrency.
"""
import threading
import asyncio
import uuid
import time
from collections import OrderedDict
from enum import Enum


class ScanState(Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class ScanJob:
    """Represents a single scan target in the queue."""
    __slots__ = [
        "id", "target", "profile", "cookies", "priority",
        "state", "progress", "findings_count", "error",
        "created_at", "started_at", "finished_at",
        "auth_config", "stealth", "max_rps", "modules_config",
        "_scanner_ref",
    ]

    def __init__(self, target, profile="Full Scan", priority=0, **kwargs):
        self.id = str(uuid.uuid4())[:8]
        self.target = target
        self.profile = profile
        self.cookies = kwargs.get("cookies", "")
        self.priority = priority  # Higher = sooner
        self.state = ScanState.QUEUED
        self.progress = 0.0
        self.findings_count = 0
        self.error = None
        self.created_at = time.time()
        self.started_at = None
        self.finished_at = None
        self.auth_config = kwargs.get("auth_config")
        self.stealth = kwargs.get("stealth", False)
        self.max_rps = kwargs.get("max_rps", 20)
        self.modules_config = kwargs.get("modules_config")
        self._scanner_ref = None

    def elapsed(self):
        if not self.started_at:
            return 0
        end = self.finished_at or time.time()
        return int(end - self.started_at)

    def to_dict(self):
        return {
            "id": self.id,
            "target": self.target,
            "profile": self.profile,
            "state": self.state.value,
            "progress": self.progress,
            "findings_count": self.findings_count,
            "elapsed": self.elapsed(),
            "priority": self.priority,
            "error": self.error,
        }


class ScanQueue:
    """
    Manages a queue of scan jobs with configurable concurrency.
    
    Usage:
        queue = ScanQueue(max_concurrent=2, log_callback=log)
        queue.add("https://example.com", profile="Full Scan")
        queue.add("https://other.com")
        queue.start()
    """

    def __init__(self, max_concurrent=2, log_callback=None,
                 finding_callback=None, scan_factory=None):
        self.max_concurrent = max(1, min(5, max_concurrent))
        self.log = log_callback or (lambda m: None)
        self.finding_callback = finding_callback
        self.scan_factory = scan_factory  # func(target, profile, ...) → ScannerThread

        self._jobs = OrderedDict()  # id → ScanJob
        self._lock = threading.Lock()
        self._running = False
        self._thread = None

        # Callbacks
        self.on_job_start = None    # func(job)
        self.on_job_complete = None # func(job)
        self.on_job_finding = None  # func(job, finding)
        self.on_queue_empty = None  # func()

    # --- Queue Operations ---

    def add(self, target, profile="Full Scan", priority=0, **kwargs):
        """Add a target to the scan queue. Returns the job ID."""
        job = ScanJob(target, profile, priority, **kwargs)
        with self._lock:
            self._jobs[job.id] = job
        self.log(f"📋 Queued: {target} (ID: {job.id}, priority: {priority})")
        return job.id

    def add_batch(self, targets, profile="Full Scan", **kwargs):
        """Add multiple targets at once. Returns list of job IDs."""
        ids = []
        for t in targets:
            t = t.strip()
            if t:
                ids.append(self.add(t, profile, **kwargs))
        self.log(f"📋 Batch queued: {len(ids)} targets")
        return ids

    def remove(self, job_id):
        """Remove a queued job (only if not running)."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job.state == ScanState.QUEUED:
                del self._jobs[job_id]
                self.log(f"🗑️ Removed: {job.target}")
                return True
        return False

    def cancel(self, job_id):
        """Cancel a running or queued job."""
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False
            if job.state == ScanState.RUNNING and job._scanner_ref:
                job._scanner_ref.stop()
            job.state = ScanState.CANCELLED
            job.finished_at = time.time()
            self.log(f"❌ Cancelled: {job.target}")
            return True

    def prioritize(self, job_id, new_priority):
        """Change priority of a queued job."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job.state == ScanState.QUEUED:
                job.priority = new_priority
                return True
        return False

    def clear_completed(self):
        """Remove all completed/failed/cancelled jobs from the queue."""
        with self._lock:
            to_remove = [
                jid for jid, j in self._jobs.items()
                if j.state in (ScanState.COMPLETED, ScanState.FAILED, ScanState.CANCELLED)
            ]
            for jid in to_remove:
                del self._jobs[jid]
        return len(to_remove)

    # --- Queue Control ---

    def start(self):
        """Start processing the queue in background."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._process_loop, daemon=True)
        self._thread.start()
        self.log(f"🚀 Scan queue started (max {self.max_concurrent} concurrent)")

    def stop(self):
        """Stop the queue processor (running scans continue to completion)."""
        self._running = False
        self.log("⏹️ Scan queue stopped")

    # --- Query ---

    def get_jobs(self):
        """Get all jobs as dicts."""
        with self._lock:
            return [j.to_dict() for j in self._jobs.values()]

    def get_job(self, job_id):
        """Get a single job."""
        job = self._jobs.get(job_id)
        return job.to_dict() if job else None

    def get_stats(self):
        """Get queue statistics."""
        with self._lock:
            states = {}
            for j in self._jobs.values():
                states[j.state.value] = states.get(j.state.value, 0) + 1
            return {
                "total": len(self._jobs),
                "running": states.get("running", 0),
                "queued": states.get("queued", 0),
                "completed": states.get("completed", 0),
                "failed": states.get("failed", 0),
            }

    # --- Internal ---

    def _process_loop(self):
        """Main loop: pick jobs from queue and run them."""
        while self._running:
            with self._lock:
                running_count = sum(
                    1 for j in self._jobs.values() if j.state == ScanState.RUNNING
                )
                if running_count >= self.max_concurrent:
                    pass  # At capacity
                else:
                    # Pick next queued job (highest priority first)
                    queued = [
                        j for j in self._jobs.values() if j.state == ScanState.QUEUED
                    ]
                    queued.sort(key=lambda j: -j.priority)
                    
                    slots = self.max_concurrent - running_count
                    for job in queued[:slots]:
                        self._start_job(job)

            time.sleep(1)  # Check every second

        # Check if queue is empty
        with self._lock:
            remaining = sum(
                1 for j in self._jobs.values()
                if j.state in (ScanState.QUEUED, ScanState.RUNNING)
            )
        if remaining == 0 and self.on_queue_empty:
            self.on_queue_empty()

    def _start_job(self, job):
        """Start a scan job."""
        job.state = ScanState.RUNNING
        job.started_at = time.time()
        self.log(f"▶️ Starting: {job.target}")

        if self.on_job_start:
            try:
                self.on_job_start(job)
            except Exception:
                pass

        def run_scan():
            try:
                if not self.scan_factory:
                    from core.scanner import ScannerThread
                    scanner = ScannerThread(
                        job.target, job.profile,
                        log_callback=lambda msg: self.log(f"[{job.id}] {msg}"),
                        finding_callback=lambda f: self._on_finding(job, f),
                        finish_callback=lambda: self._on_complete(job),
                        cookies=job.cookies,
                        stealth_mode=job.stealth,
                        modules_config=job.modules_config,
                        max_rps=job.max_rps,
                        auth_config=job.auth_config,
                    )
                else:
                    scanner = self.scan_factory(job)

                job._scanner_ref = scanner
                scanner.start()
                scanner.join()
            except Exception as e:
                job.state = ScanState.FAILED
                job.error = str(e)
                job.finished_at = time.time()
                self.log(f"❌ Failed: {job.target} — {e}")

        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()

    def _on_finding(self, job, finding):
        """Handle a finding from a scan job."""
        job.findings_count += 1
        if self.finding_callback:
            finding["_queue_job_id"] = job.id
            finding["_queue_target"] = job.target
            self.finding_callback(finding)
        if self.on_job_finding:
            try:
                self.on_job_finding(job, finding)
            except Exception:
                pass

    def _on_complete(self, job):
        """Handle scan completion."""
        job.state = ScanState.COMPLETED
        job.progress = 1.0
        job.finished_at = time.time()
        elapsed = job.elapsed()
        self.log(f"✅ Completed: {job.target} — {job.findings_count} findings in {elapsed}s")
        if self.on_job_complete:
            try:
                self.on_job_complete(job)
            except Exception:
                pass
