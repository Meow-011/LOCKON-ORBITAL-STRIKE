"""
REST API Server (Headless Mode)
FastAPI-based API for programmatic access to LOCKON scans.
Supports API key auth and real-time WebSocket progress.
"""
import os
import json
import asyncio
import uuid
import threading

# Lazy imports — only loaded when server starts
fastapi = None
uvicorn = None


def _lazy_import():
    global fastapi, uvicorn
    try:
        import fastapi as _fastapi
        import uvicorn as _uvicorn
        fastapi = _fastapi
        uvicorn = _uvicorn
        return True
    except ImportError:
        return False


# Active scans tracking
_active_scans = {}
_scan_results = {}
_api_keys = set()

# Default API key
DEFAULT_API_KEY = os.environ.get("LOCKON_API_KEY", "lockon-orbital-strike-api-key")
_api_keys.add(DEFAULT_API_KEY)


def create_api_app():
    """Create and configure the FastAPI application."""
    if not _lazy_import():
        raise RuntimeError("FastAPI/uvicorn not installed. Run: pip install fastapi uvicorn")
    
    from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
    from fastapi.security import APIKeyHeader
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    from typing import Optional, List
    
    app = FastAPI(
        title="LOCKON ORBITAL STRIKE API",
        description="RESTful API for automated vulnerability scanning",
        version="1.0.0"
    )
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Auth
    api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
    
    async def verify_api_key(api_key: str = Depends(api_key_header)):
        if api_key not in _api_keys:
            raise HTTPException(status_code=403, detail="Invalid API key")
        return api_key
    
    # Models
    class ScanRequest(BaseModel):
        target: str
        profile: Optional[str] = "Full Scan"
        cookies: Optional[str] = ""
        stealth: Optional[bool] = False
        max_rps: Optional[int] = 20
    
    class ScanStatus(BaseModel):
        scan_id: str
        target: str
        status: str  # "running", "completed", "failed"
        progress: float
        findings_count: int
    
    # WebSocket connections for real-time updates
    ws_connections = []
    
    @app.get("/api/health")
    async def health():
        return {"status": "ok", "service": "LOCKON ORBITAL STRIKE"}
    
    @app.post("/api/scan/start", dependencies=[Depends(verify_api_key)])
    async def start_scan(req: ScanRequest):
        scan_id = str(uuid.uuid4())[:8]
        
        _active_scans[scan_id] = {
            "target": req.target,
            "profile": req.profile,
            "status": "queued",
            "progress": 0.0,
            "findings": [],
        }
        
        # Launch scan in background thread
        def run_scan():
            try:
                from core.scanner import ScannerThread
                
                def log_cb(msg):
                    _active_scans[scan_id]["status"] = "running"
                    # Broadcast to WebSocket clients
                    for ws in ws_connections:
                        try:
                            asyncio.run(ws.send_json({"type": "log", "scan_id": scan_id, "message": msg}))
                        except: pass
                
                def finding_cb(finding):
                    _active_scans[scan_id]["findings"].append(finding)
                    for ws in ws_connections:
                        try:
                            asyncio.run(ws.send_json({"type": "finding", "scan_id": scan_id, "finding": finding}))
                        except: pass
                
                def done_cb():
                    _active_scans[scan_id]["status"] = "completed"
                    _active_scans[scan_id]["progress"] = 1.0
                    _scan_results[scan_id] = _active_scans[scan_id]["findings"]
                
                scanner = ScannerThread(
                    req.target, req.profile, log_cb, finding_cb, done_cb,
                    req.cookies, stealth_mode=req.stealth, max_rps=req.max_rps
                )
                scanner.start()
                scanner.join()
            except Exception as e:
                _active_scans[scan_id]["status"] = "failed"
                _active_scans[scan_id]["error"] = str(e)
        
        threading.Thread(target=run_scan, daemon=True).start()
        
        return {"scan_id": scan_id, "status": "queued", "target": req.target}
    
    @app.get("/api/scan/{scan_id}/status", dependencies=[Depends(verify_api_key)])
    async def get_scan_status(scan_id: str):
        if scan_id not in _active_scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        scan = _active_scans[scan_id]
        return {
            "scan_id": scan_id,
            "target": scan["target"],
            "status": scan["status"],
            "progress": scan["progress"],
            "findings_count": len(scan["findings"]),
        }
    
    @app.get("/api/scan/{scan_id}/findings", dependencies=[Depends(verify_api_key)])
    async def get_scan_findings(scan_id: str):
        if scan_id not in _active_scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {"scan_id": scan_id, "findings": _active_scans[scan_id]["findings"]}
    
    @app.post("/api/scan/{scan_id}/stop", dependencies=[Depends(verify_api_key)])
    async def stop_scan(scan_id: str):
        if scan_id not in _active_scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        _active_scans[scan_id]["status"] = "stopped"
        return {"scan_id": scan_id, "status": "stopped"}
    
    @app.get("/api/scans", dependencies=[Depends(verify_api_key)])
    async def list_scans():
        return [
            {
                "scan_id": sid,
                "target": s["target"],
                "status": s["status"],
                "findings_count": len(s["findings"]),
            }
            for sid, s in _active_scans.items()
        ]
    
    @app.get("/api/report/{scan_id}/html", dependencies=[Depends(verify_api_key)])
    async def export_html_report(scan_id: str):
        if scan_id not in _active_scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        from core.reporter import generate_html_report
        scan = _active_scans[scan_id]
        path = generate_html_report(scan["target"], scan["findings"])
        return {"scan_id": scan_id, "report_path": path}
    
    @app.get("/api/report/{scan_id}/pdf", dependencies=[Depends(verify_api_key)])
    async def export_pdf_report(scan_id: str):
        if scan_id not in _active_scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        from core.pdf_reporter import generate_pdf_report
        scan = _active_scans[scan_id]
        path = generate_pdf_report(scan["target"], scan["findings"])
        return {"scan_id": scan_id, "report_path": path}
    
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await websocket.accept()
        ws_connections.append(websocket)
        try:
            while True:
                data = await websocket.receive_text()
                # Handle incoming commands via WebSocket
                try:
                    cmd = json.loads(data)
                    if cmd.get("type") == "ping":
                        await websocket.send_json({"type": "pong"})
                except: pass
        except WebSocketDisconnect:
            ws_connections.remove(websocket)
    
    return app


def start_api_server(host="0.0.0.0", port=9090, log_callback=None):
    """Start the API server in a background thread."""
    log = log_callback or print
    
    if not _lazy_import():
        log("❌ FastAPI/uvicorn not installed. Run: pip install fastapi uvicorn")
        return None
    
    app = create_api_app()
    
    def run():
        log(f"🌐 API server starting on {host}:{port}")
        log(f"   Default API key: {DEFAULT_API_KEY}")
        log(f"   Docs: http://{host}:{port}/docs")
        uvicorn.run(app, host=host, port=port, log_level="warning")
    
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread
