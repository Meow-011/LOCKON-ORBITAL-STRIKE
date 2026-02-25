import time
import statistics
import aiohttp
import asyncio

class ChronosTimeParams:
    """
    Project CHRONOS: Temporal Anomaly Detection.
    Uses statistical analysis (Z-Score) to distinguish true time-based delays from network jitter.
    """
    def __init__(self):
        self.baseline_mean = 0.0
        self.baseline_stdev = 0.0
        self.calibrated = False
        self.min_samples = 10
        self.z_threshold = 4.0 # 4 Sigma (99.997% confidence)

    async def measure_baseline(self, url, headers=None, session=None, samples=10):
        """
        Establishes the baseline response time for the target using async aiohttp.
        """
        response_times = []
        print(f"[*] Chronos: Calibrating baseline for {url} ({samples} samples)...")
        
        # Use provided session or create a temporary one
        own_session = False
        if session is None:
            session = aiohttp.ClientSession()
            own_session = True
        
        try:
            for _ in range(samples):
                try:
                    start = time.time()
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                        await resp.read()
                    end = time.time()
                    response_times.append(end - start)
                    await asyncio.sleep(0.1) # Breather
                except Exception:
                    pass
        finally:
            if own_session:
                await session.close()
                    
        if len(response_times) < 3:
            # Fallback if calibration fails
            self.baseline_mean = 0.5
            self.baseline_stdev = 0.2
            self.calibrated = False
            return
            
        self.baseline_mean = statistics.mean(response_times)
        if len(response_times) > 1:
            self.baseline_stdev = statistics.stdev(response_times)
        else:
            self.baseline_stdev = 0.1
            
        # Avoid zero division
        if self.baseline_stdev == 0:
            self.baseline_stdev = 0.01
            
        self.calibrated = True
        print(f"[*] Chronos: Baseline Mean={self.baseline_mean:.4f}s, Stdev={self.baseline_stdev:.4f}s")

    def is_statistically_significant(self, duration):
        """
        Calculates Z-Score to determine if the duration is an anomaly.
        """
        if not self.calibrated:
            # Fallback to static check if not calibrated
            return duration > 5.0
            
        # Z = (X - Mean) / Stdev
        z_score = (duration - self.baseline_mean) / self.baseline_stdev
        
        # Check against threshold (e.g., 4 Sigma)
        # Also ensure strict minimum delay (e.g., at least 2s) to avoid micro-optimizations being flagged
        return z_score > self.z_threshold and duration > (self.baseline_mean + 2.0)
