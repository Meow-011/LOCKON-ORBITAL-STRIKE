"""
INTERCEPT Tab — HTTP Proxy GUI
Request/Response viewer with intercept, forward, drop, repeat, and editing.
"""
import flet as ft
import threading
from gui.theme import *


class ProxyTab:
    def __init__(self, page: ft.Page, log_callback=None):
        self.page = page
        self.log = log_callback or (lambda msg: None)
        self.proxy = None  # Initialized on start
        
        # State
        self.selected_request = None
        self._request_rows = {}
        
        # --- Controls ---
        self.port_input = ft.TextField(
            value="8080", width=80, height=35,
            text_style=ft.TextStyle(font_family="Consolas", size=11, color=COLOR_TEXT_MAIN),
            border_color=COLOR_BORDER_SUBTLE, focused_border_color=COLOR_ACCENT_PRIMARY,
            bgcolor=COLOR_BG_INPUT, border_radius=4, content_padding=8, text_align=ft.TextAlign.CENTER
        )
        
        self.intercept_switch = ft.Switch(
            label="INTERCEPT", value=False,
            active_color="#ff5252", track_color={ft.ControlState.SELECTED: "#331111", ft.ControlState.DEFAULT: "#222"},
            label_style=ft.TextStyle(font_family="Consolas", size=11, color=COLOR_TEXT_MAIN, weight="bold"),
            on_change=self._toggle_intercept
        )
        
        self.btn_start = ft.ElevatedButton(
            "START", icon=ft.Icons.PLAY_ARROW,
            style=ft.ButtonStyle(bgcolor=COLOR_ACCENT_PRIMARY, color="black", shape=ft.RoundedRectangleBorder(radius=4)),
            height=35, on_click=self._start_proxy
        )
        self.btn_stop = ft.ElevatedButton(
            "STOP", icon=ft.Icons.STOP, visible=False,
            style=ft.ButtonStyle(bgcolor=COLOR_SEV_CRITICAL, color="white", shape=ft.RoundedRectangleBorder(radius=4)),
            height=35, on_click=self._stop_proxy
        )
        
        self.status_text = ft.Text("● OFFLINE", size=10, color=COLOR_TEXT_DIM, font_family="Consolas", weight="bold")
        self.request_count = ft.Text("0 requests", size=10, color=COLOR_TEXT_DIM, font_family="Consolas")
        
        # --- Request History Table ---
        self.history_table = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True, spacing=2)
        
        # --- Intercepted Request Actions ---
        self.btn_forward = ft.ElevatedButton(
            "FORWARD", icon=ft.Icons.FAST_FORWARD,
            style=ft.ButtonStyle(bgcolor="#4caf50", color="white", shape=ft.RoundedRectangleBorder(radius=4)),
            height=30, on_click=self._forward_request, visible=False
        )
        self.btn_drop = ft.ElevatedButton(
            "DROP", icon=ft.Icons.DELETE,
            style=ft.ButtonStyle(bgcolor=COLOR_SEV_CRITICAL, color="white", shape=ft.RoundedRectangleBorder(radius=4)),
            height=30, on_click=self._drop_request, visible=False
        )
        self.btn_repeat = ft.OutlinedButton(
            "REPEAT", icon=ft.Icons.REPLAY,
            style=ft.ButtonStyle(color=COLOR_TEXT_DIM, side=ft.BorderSide(1, COLOR_BORDER_SUBTLE), shape=ft.RoundedRectangleBorder(radius=4)),
            height=30, on_click=self._repeat_request
        )
        
        # --- Request/Response Detail Panels ---
        self.req_method = ft.Text("", size=12, weight="bold", color=COLOR_ACCENT_PRIMARY, font_family="Consolas")
        self.req_url = ft.Text("", size=11, color=COLOR_TEXT_MAIN, font_family="Consolas", selectable=True, max_lines=3)
        self.req_headers_field = ft.TextField(
            multiline=True, min_lines=4, max_lines=10,
            text_style=ft.TextStyle(font_family="Consolas", size=10, color=COLOR_TEXT_DIM),
            border_color=COLOR_BORDER_SUBTLE, bgcolor=COLOR_BG_INPUT, border_radius=4,
            read_only=False, label="Request Headers", label_style=ft.TextStyle(size=10, color=COLOR_TEXT_DIM)
        )
        self.req_body_field = ft.TextField(
            multiline=True, min_lines=3, max_lines=8,
            text_style=ft.TextStyle(font_family="Consolas", size=10, color=COLOR_TEXT_DIM),
            border_color=COLOR_BORDER_SUBTLE, bgcolor=COLOR_BG_INPUT, border_radius=4,
            read_only=False, label="Request Body", label_style=ft.TextStyle(size=10, color=COLOR_TEXT_DIM)
        )
        
        self.resp_status = ft.Text("", size=12, weight="bold", font_family="Consolas")
        self.resp_time = ft.Text("", size=10, color=COLOR_TEXT_DIM, font_family="Consolas")
        self.resp_headers_field = ft.TextField(
            multiline=True, min_lines=4, max_lines=10,
            text_style=ft.TextStyle(font_family="Consolas", size=10, color=COLOR_TEXT_DIM),
            border_color=COLOR_BORDER_SUBTLE, bgcolor=COLOR_BG_INPUT, border_radius=4,
            read_only=True, label="Response Headers", label_style=ft.TextStyle(size=10, color=COLOR_TEXT_DIM)
        )
        self.resp_body_field = ft.TextField(
            multiline=True, min_lines=5, max_lines=15,
            text_style=ft.TextStyle(font_family="Consolas", size=10, color="#00e676"),
            border_color=COLOR_BORDER_SUBTLE, bgcolor="#0a0a0a", border_radius=4,
            read_only=True, label="Response Body", label_style=ft.TextStyle(size=10, color=COLOR_TEXT_DIM)
        )
        
        # Empty state
        self.detail_empty = ft.Container(
            padding=30,
            content=ft.Column([
                ft.Icon(ft.Icons.HTTP, size=36, color=COLOR_TEXT_DIM),
                ft.Text("Select a request to inspect", size=12, color=COLOR_TEXT_DIM),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=5),
            alignment=ft.alignment.center, expand=True
        )
        
        self.detail_panel = ft.Column([self.detail_empty], scroll=ft.ScrollMode.AUTO, expand=True)
    
    def get_content(self):
        return ft.Container(
            padding=15, bgcolor=COLOR_SURFACE, border_radius=8,
            content=ft.Column([
                # Header bar
                ft.Row([
                    ft.Icon(ft.Icons.SWAP_VERT, color=COLOR_ACCENT_PRIMARY),
                    ft.Text("INTERCEPT", size=14, weight="bold", color="white", font_family="Consolas"),
                    ft.Container(expand=True),
                    self.status_text,
                    ft.Text("Port:", size=10, color=COLOR_TEXT_DIM),
                    self.port_input,
                    self.btn_start,
                    self.btn_stop,
                    ft.Container(width=10),
                    self.intercept_switch,
                ], vertical_alignment=ft.CrossAxisAlignment.CENTER),
                ft.Divider(color=COLOR_BORDER_SUBTLE),
                
                # Main split view
                ft.Row([
                    # Left: Request History
                    ft.Container(
                        width=380,
                        content=ft.Column([
                            ft.Row([
                                self.request_count,
                                ft.Container(expand=True),
                                ft.IconButton(ft.Icons.DELETE_SWEEP, icon_size=16, icon_color=COLOR_TEXT_DIM, 
                                            tooltip="Clear history", on_click=self._clear_history),
                            ]),
                            ft.Divider(color=COLOR_BORDER_SUBTLE, height=1),
                            self.history_table,
                        ], expand=True),
                        bgcolor=COLOR_BG_PANEL, border_radius=6, padding=10,
                        border=ft.border.all(1, COLOR_BORDER_SUBTLE),
                    ),
                    
                    # Right: Request/Response Detail
                    ft.Container(
                        expand=True,
                        content=ft.Column([
                            # Action bar
                            ft.Row([
                                self.req_method,
                                self.req_url,
                                ft.Container(expand=True),
                                self.btn_forward,
                                self.btn_drop,
                                self.btn_repeat,
                            ], vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=5),
                            ft.Divider(color=COLOR_BORDER_SUBTLE, height=1),
                            # Detail
                            self.detail_panel,
                        ], expand=True),
                        bgcolor=COLOR_BG_PANEL, border_radius=6, padding=10,
                        border=ft.border.all(1, COLOR_BORDER_SUBTLE),
                    ),
                ], expand=True, spacing=10),
            ], expand=True)
        )
    
    def _on_request(self, proxy_req):
        """Callback from proxy engine when a request completes or is intercepted."""
        try:
            status = proxy_req.response_status or "..."
            status_color = "#4caf50" if 200 <= (status if isinstance(status, int) else 0) < 300 else \
                           "#ff9800" if 300 <= (status if isinstance(status, int) else 0) < 400 else \
                           "#f44336" if (status if isinstance(status, int) else 0) >= 400 else COLOR_TEXT_DIM
            
            intercept_icon = ft.Icon(ft.Icons.PAUSE_CIRCLE, size=12, color="#ff5252") if proxy_req.intercepted and not proxy_req.forwarded else None
            
            row = ft.Container(
                content=ft.Row([
                    ft.Container(
                        content=ft.Text(proxy_req.method, size=9, weight="bold", color="white", font_family="Consolas"),
                        bgcolor=COLOR_ACCENT_PRIMARY if proxy_req.method == "GET" else "#ff9800",
                        padding=ft.padding.symmetric(horizontal=5, vertical=2), border_radius=3, width=45
                    ),
                    ft.Text(str(status), size=10, color=status_color, weight="bold", font_family="Consolas", width=30),
                    ft.Text(proxy_req.host + proxy_req.path[:40], size=10, color=COLOR_TEXT_MAIN, font_family="Consolas", expand=True, max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Text(f"{proxy_req.response_time_ms}ms" if proxy_req.response_time_ms else "", size=9, color=COLOR_TEXT_DIM, font_family="Consolas"),
                    intercept_icon or ft.Container(width=0),
                ], spacing=5, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                padding=ft.padding.symmetric(horizontal=6, vertical=4),
                border_radius=3, ink=True,
                on_click=lambda e, r=proxy_req: self._select_request(r),
                bgcolor="#1a1a22" if not proxy_req.intercepted else "#1a0a0a",
            )
            
            self._request_rows[proxy_req.id] = row
            self.history_table.controls.insert(0, row)
            
            # Update count
            count = len(self.history_table.controls)
            self.request_count.value = f"{count} requests"
            
            try: self.page.update()
            except Exception: pass
            
        except Exception:
            pass
    
    def _select_request(self, proxy_req):
        """Show request/response details in the right panel."""
        self.selected_request = proxy_req
        
        self.req_method.value = proxy_req.method
        self.req_url.value = proxy_req.url
        
        # Headers
        headers_str = "\n".join(f"{k}: {v}" for k, v in proxy_req.headers.items())
        self.req_headers_field.value = headers_str
        self.req_body_field.value = proxy_req.body.decode("utf-8", errors="replace") if proxy_req.body else ""
        
        # Response
        if proxy_req.response_status:
            status = proxy_req.response_status
            color = "#4caf50" if 200 <= status < 300 else "#ff9800" if 300 <= status < 400 else "#f44336"
            self.resp_status.value = f"HTTP {status}"
            self.resp_status.color = color
            self.resp_time.value = f"{proxy_req.response_time_ms}ms"
            
            resp_headers_str = "\n".join(f"{k}: {v}" for k, v in proxy_req.response_headers.items())
            self.resp_headers_field.value = resp_headers_str
            
            body = proxy_req.response_body.decode("utf-8", errors="replace") if proxy_req.response_body else ""
            self.resp_body_field.value = body[:10000]  # Limit display
        else:
            self.resp_status.value = "Pending..."
            self.resp_status.color = COLOR_TEXT_DIM
            self.resp_time.value = ""
            self.resp_headers_field.value = ""
            self.resp_body_field.value = ""
        
        # Show/hide intercept buttons
        is_held = proxy_req.intercepted and not proxy_req.forwarded and not proxy_req.dropped
        self.btn_forward.visible = is_held
        self.btn_drop.visible = is_held
        
        # Update detail panel
        self.detail_panel.controls = [
            ft.Container(height=5),
            ft.Text("REQUEST", size=10, weight="bold", color=COLOR_ACCENT_PRIMARY, font_family="Consolas"),
            self.req_headers_field,
            self.req_body_field,
            ft.Container(height=10),
            ft.Row([
                ft.Text("RESPONSE", size=10, weight="bold", color="#4caf50", font_family="Consolas"),
                ft.Container(expand=True),
                self.resp_status,
                self.resp_time,
            ]),
            self.resp_headers_field,
            self.resp_body_field,
        ]
        
        try: self.page.update()
        except Exception: pass
    
    def _start_proxy(self, e=None):
        """Start the proxy server."""
        try:
            from core.proxy_engine import ProxyEngine
            port = int(self.port_input.value or 8080)
            self.proxy = ProxyEngine(port=port, log_callback=self.log, request_callback=self._on_request)
            self.proxy.start()
            
            self.status_text.value = f"● LISTENING :{port}"
            self.status_text.color = "#4caf50"
            self.btn_start.visible = False
            self.btn_stop.visible = True
            self.page.update()
        except Exception as ex:
            self.log(f"Proxy start error: {ex}")
    
    def _stop_proxy(self, e=None):
        """Stop the proxy server."""
        if self.proxy:
            self.proxy.stop()
            self.proxy = None
        
        self.status_text.value = "● OFFLINE"
        self.status_text.color = COLOR_TEXT_DIM
        self.btn_start.visible = True
        self.btn_stop.visible = False
        self.intercept_switch.value = False
        try: self.page.update()
        except: pass
    
    def _toggle_intercept(self, e=None):
        """Toggle intercept mode."""
        if self.proxy:
            self.proxy.set_intercept(self.intercept_switch.value)
    
    def _forward_request(self, e=None):
        """Forward the selected intercepted request."""
        if self.proxy and self.selected_request:
            # Apply any modifications from the text fields
            if self.req_body_field.value != (self.selected_request.body.decode("utf-8", errors="replace") if self.selected_request.body else ""):
                self.proxy.modify_request(self.selected_request.id, body=self.req_body_field.value)
            self.proxy.forward_request(self.selected_request.id)
            self.btn_forward.visible = False
            self.btn_drop.visible = False
            try: self.page.update()
            except: pass
    
    def _drop_request(self, e=None):
        """Drop the selected intercepted request."""
        if self.proxy and self.selected_request:
            self.proxy.drop_request(self.selected_request.id)
            self.btn_forward.visible = False
            self.btn_drop.visible = False
            try: self.page.update()
            except: pass
    
    def _repeat_request(self, e=None):
        """Repeat the selected request."""
        if self.proxy and self.selected_request:
            self.proxy.repeat_request(self.selected_request.id)
            self.log(f"↺ Repeating: {self.selected_request.method} {self.selected_request.url}")
    
    def _clear_history(self, e=None):
        """Clear proxy history."""
        if self.proxy:
            self.proxy.clear_history()
        self.history_table.controls.clear()
        self._request_rows.clear()
        self.request_count.value = "0 requests"
        self.detail_panel.controls = [self.detail_empty]
        try: self.page.update()
        except: pass
