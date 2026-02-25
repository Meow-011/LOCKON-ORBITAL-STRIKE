"""
HTTP Proxy/Interceptor Engine
Lightweight async HTTP proxy with intercept and passthrough modes.
Does NOT require mitmproxy — uses only stdlib + aiohttp.
"""
import asyncio
import threading
import time
import json
import uuid
from datetime import datetime
from urllib.parse import urlparse
from collections import deque

try:
    import aiohttp
except ImportError:
    aiohttp = None


class ProxyRequest:
    """Represents an intercepted HTTP request."""
    
    def __init__(self, method, url, headers, body=b""):
        self.id = str(uuid.uuid4())[:8]
        self.method = method
        self.url = url
        self.headers = dict(headers) if headers else {}
        self.body = body
        self.timestamp = datetime.now().isoformat()
        
        parsed = urlparse(url)
        self.host = parsed.hostname or ""
        self.path = parsed.path or "/"
        self.scheme = parsed.scheme or "http"
        
        # Response (filled after forwarding)
        self.response_status = None
        self.response_headers = {}
        self.response_body = b""
        self.response_time_ms = 0
        
        # State
        self.intercepted = False
        self.forwarded = False
        self.dropped = False
        self.modified = False
    
    def to_dict(self):
        return {
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "headers": self.headers,
            "body": self.body.decode("utf-8", errors="replace") if self.body else "",
            "timestamp": self.timestamp,
            "response_status": self.response_status,
            "response_headers": self.response_headers,
            "response_body": self.response_body.decode("utf-8", errors="replace") if self.response_body else "",
            "response_time_ms": self.response_time_ms,
            "intercepted": self.intercepted,
            "forwarded": self.forwarded,
            "dropped": self.dropped,
            "modified": self.modified,
        }


class ProxyEngine:
    """Async HTTP proxy engine with intercept capabilities."""
    
    def __init__(self, port=8080, log_callback=None, request_callback=None):
        self.port = port
        self.log = log_callback or (lambda msg: None)
        self.request_callback = request_callback  # Called for each request
        
        self.intercept_mode = False  # True = pause requests for editing
        self.running = False
        self._server = None
        self._loop = None
        self._thread = None
        
        # History
        self.history = deque(maxlen=500)
        
        # Intercept queue: pending requests waiting for user action
        self._intercept_queue = {}  # id → asyncio.Event
        self._intercept_data = {}   # id → ProxyRequest (possibly modified)
    
    def start(self):
        """Start the proxy server in a background thread."""
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._run_server, daemon=True)
        self._thread.start()
        self.log(f"🔌 Proxy server starting on localhost:{self.port}")
    
    def stop(self):
        """Stop the proxy server."""
        self.running = False
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        self.log("🔌 Proxy server stopped")
    
    def set_intercept(self, enabled):
        """Enable or disable intercept mode."""
        self.intercept_mode = enabled
        mode = "INTERCEPT" if enabled else "PASSTHROUGH"
        self.log(f"🔌 Proxy mode: {mode}")
    
    def forward_request(self, request_id):
        """Forward a held request (in intercept mode)."""
        if request_id in self._intercept_queue:
            self._intercept_queue[request_id].set()
    
    def drop_request(self, request_id):
        """Drop a held request."""
        if request_id in self._intercept_data:
            self._intercept_data[request_id].dropped = True
        if request_id in self._intercept_queue:
            self._intercept_queue[request_id].set()
    
    def modify_request(self, request_id, method=None, url=None, headers=None, body=None):
        """Modify a held request before forwarding."""
        if request_id in self._intercept_data:
            req = self._intercept_data[request_id]
            if method: req.method = method
            if url: req.url = url
            if headers: req.headers = headers
            if body is not None: req.body = body.encode() if isinstance(body, str) else body
            req.modified = True
    
    def get_history(self, limit=100):
        """Get recent proxy history."""
        items = list(self.history)[-limit:]
        return [r.to_dict() for r in items]
    
    def clear_history(self):
        """Clear proxy history."""
        self.history.clear()
    
    def repeat_request(self, request_id):
        """Find a request by ID and re-send it."""
        for req in self.history:
            if req.id == request_id:
                # Create a copy and send it
                new_req = ProxyRequest(req.method, req.url, req.headers.copy(), req.body)
                threading.Thread(target=self._repeat_in_thread, args=(new_req,), daemon=True).start()
                return new_req.id
        return None
    
    def _repeat_in_thread(self, req):
        """Send a repeated request in a new event loop."""
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(self._do_forward(req))
            self.history.append(req)
            if self.request_callback:
                self.request_callback(req)
        except Exception as e:
            self.log(f"Repeat error: {e}")
        finally:
            loop.close()
    
    def _run_server(self):
        """Run the proxy server event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        
        try:
            self._loop.run_until_complete(self._start_proxy())
            self._loop.run_forever()
        except Exception as e:
            self.log(f"Proxy error: {e}")
        finally:
            self._loop.close()
    
    async def _start_proxy(self):
        """Start the async proxy server."""
        server = await asyncio.start_server(
            self._handle_connection, "127.0.0.1", self.port
        )
        self._server = server
        self.log(f"✅ Proxy listening on 127.0.0.1:{self.port}")
    
    async def _handle_connection(self, reader, writer):
        """Handle an incoming proxy connection."""
        try:
            # Read the request line
            request_line = await asyncio.wait_for(reader.readline(), timeout=10)
            if not request_line:
                writer.close()
                return
            
            request_line = request_line.decode("utf-8", errors="replace").strip()
            parts = request_line.split(" ", 2)
            if len(parts) < 3:
                writer.close()
                return
            
            method, url, proto = parts
            
            # Handle CONNECT (HTTPS tunneling)
            if method == "CONNECT":
                await self._handle_connect(reader, writer, url)
                return
            
            # Read headers
            headers = {}
            content_length = 0
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                line = line.decode("utf-8", errors="replace").strip()
                if not line:
                    break
                if ":" in line:
                    key, val = line.split(":", 1)
                    headers[key.strip()] = val.strip()
                    if key.strip().lower() == "content-length":
                        content_length = int(val.strip())
            
            # Read body
            body = b""
            if content_length > 0:
                body = await asyncio.wait_for(reader.read(content_length), timeout=10)
            
            # Create request object
            proxy_req = ProxyRequest(method, url, headers, body)
            
            # Intercept mode: hold the request
            if self.intercept_mode:
                proxy_req.intercepted = True
                event = asyncio.Event()
                self._intercept_queue[proxy_req.id] = event
                self._intercept_data[proxy_req.id] = proxy_req
                
                if self.request_callback:
                    self.request_callback(proxy_req)
                
                # Wait for user action (forward/drop)
                await asyncio.wait_for(event.wait(), timeout=300)  # 5 min timeout
                
                # Clean up
                self._intercept_queue.pop(proxy_req.id, None)
                proxy_req = self._intercept_data.pop(proxy_req.id, proxy_req)
                
                if proxy_req.dropped:
                    writer.write(b"HTTP/1.1 444 Dropped\r\n\r\n")
                    await writer.drain()
                    writer.close()
                    return
            
            # Forward the request
            await self._do_forward(proxy_req)
            
            # Add to history
            self.history.append(proxy_req)
            proxy_req.forwarded = True
            
            if self.request_callback and not proxy_req.intercepted:
                self.request_callback(proxy_req)
            
            # Send response back to client
            status_line = f"HTTP/1.1 {proxy_req.response_status or 502} OK\r\n"
            writer.write(status_line.encode())
            for k, v in proxy_req.response_headers.items():
                if k.lower() not in ('transfer-encoding', 'content-encoding'):
                    writer.write(f"{k}: {v}\r\n".encode())
            writer.write(f"Content-Length: {len(proxy_req.response_body)}\r\n".encode())
            writer.write(b"\r\n")
            writer.write(proxy_req.response_body)
            await writer.drain()
            
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            self.log(f"Proxy handler error: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                pass
    
    async def _handle_connect(self, reader, writer, target):
        """Handle HTTPS CONNECT tunnel (passthrough only)."""
        host, port = target.split(":") if ":" in target else (target, "443")
        
        # Read remaining headers
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            if not line or line.strip() == b"":
                break
        
        try:
            remote_reader, remote_writer = await asyncio.open_connection(host, int(port))
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            
            # Bidirectional pipe
            await asyncio.gather(
                self._pipe(reader, remote_writer),
                self._pipe(remote_reader, writer),
                return_exceptions=True
            )
        except Exception:
            pass
        finally:
            try: writer.close()
            except: pass
    
    async def _pipe(self, reader, writer):
        """Pipe data between two streams."""
        try:
            while True:
                data = await asyncio.wait_for(reader.read(8192), timeout=30)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
    
    async def _do_forward(self, req):
        """Forward a request to the target and capture the response."""
        if aiohttp is None:
            req.response_status = 502
            req.response_body = b"aiohttp not installed"
            return
        
        start = time.time()
        try:
            # Remove proxy-specific headers
            fwd_headers = {k: v for k, v in req.headers.items() 
                         if k.lower() not in ('proxy-connection', 'proxy-authorization', 'host')}
            
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(
                    req.method, req.url, 
                    headers=fwd_headers, 
                    data=req.body if req.body else None,
                    ssl=False
                ) as resp:
                    req.response_status = resp.status
                    req.response_headers = dict(resp.headers)
                    req.response_body = await resp.read()
                    req.response_time_ms = int((time.time() - start) * 1000)
        except Exception as e:
            req.response_status = 502
            req.response_body = f"Proxy error: {e}".encode()
            req.response_time_ms = int((time.time() - start) * 1000)
