import flet as ft
import re
from gui.theme import *
from gui.components.ui_helpers import create_input_label

class MissionTab:
    def __init__(self, start_callback):
        self.start_callback = start_callback
        
        # Use centralized theme colors
        self.COLOR_SURFACE = COLOR_SURFACE
        self.COLOR_INPUT = COLOR_INPUT_FIELD
        self.COLOR_BORDER_SUBTLE = COLOR_BORDER_SUBTLE
        self.COLOR_ACCENT_PRIMARY = COLOR_ACCENT_PRIMARY
        
        # Inputs
        self.url_input = ft.TextField(
            hint_text="https://target.com (one per line for batch scan)", 
            text_style=ft.TextStyle(font_family="Consolas", color="white"), 
            border_color=self.COLOR_BORDER_SUBTLE, 
            focused_border_color=self.COLOR_ACCENT_PRIMARY, 
            bgcolor=self.COLOR_INPUT, 
            min_lines=2,
            max_lines=5,
            multiline=True,
            content_padding=15, 
            border_radius=4,
            prefix_icon=ft.Icons.LINK, 
            prefix_style=ft.TextStyle(color=self.COLOR_ACCENT_PRIMARY),
            expand=True,
            cursor_color=self.COLOR_ACCENT_PRIMARY,
            on_change=self._on_url_change,
            autofocus=True
        )
        
        # URL Validation feedback
        self.url_error_text = ft.Text("", size=11, color=COLOR_SEV_CRITICAL, font_family="Consolas", visible=False)
        
        self.scan_profile = ft.Dropdown(
            options=[
                ft.dropdown.Option("Full Scan"),
                ft.dropdown.Option("Top 10 (OWASP)"),
                ft.dropdown.Option("SQLi Only"),
                ft.dropdown.Option("XSS Only"),
                ft.dropdown.Option("Custom"),
            ],
            value="Full Scan", 
            bgcolor=self.COLOR_INPUT, 
            border_color=self.COLOR_BORDER_SUBTLE, 
            focused_border_color=self.COLOR_ACCENT_PRIMARY, 
            text_style=ft.TextStyle(font_family="Consolas", color=COLOR_TEXT_MAIN), 
            content_padding=10, 
            border_radius=4, 
            expand=True,
            on_change=self._on_profile_change,
            tooltip="Full Scan: All 10 modules | OWASP: Top vulnerabilities | SQLi/XSS: Targeted scan | Custom: Pick modules"
        )
        
        self.scan_cookies = ft.TextField(
            multiline=True, 
            min_lines=3, 
            bgcolor=self.COLOR_INPUT, 
            border_color=self.COLOR_BORDER_SUBTLE, 
            focused_border_color=self.COLOR_ACCENT_PRIMARY, 
            hint_text="Cookie: ...", 
            text_style=ft.TextStyle(font_family="Consolas", size=12, color=COLOR_TEXT_DIM), 
            content_padding=10, 
            border_radius=4,
            cursor_color=self.COLOR_ACCENT_PRIMARY
        )
        
        # [THEME] Checkbox Style
        chk_style = {
            "check_color": "black", 
            "active_color": self.COLOR_ACCENT_PRIMARY, 
            "fill_color": {ft.ControlState.DEFAULT: "#333", ft.ControlState.SELECTED: self.COLOR_ACCENT_PRIMARY}
        }
        
        self.chk_sqli = ft.Checkbox(label="SQL Injection (SQLi)", value=True, on_change=self._on_module_change, **chk_style)
        self.chk_xss = ft.Checkbox(label="Cross-Site Scripting (XSS)", value=True, on_change=self._on_module_change, **chk_style)
        self.chk_nosql = ft.Checkbox(label="NoSQL Injection", value=True, on_change=self._on_module_change, **chk_style)
        self.chk_rce = ft.Checkbox(label="RCE / Cmd Injection", value=True, on_change=self._on_module_change, **chk_style)
        self.chk_cve = ft.Checkbox(label="CVE Sniper (Known Exploits)", value=True, on_change=self._on_module_change, **chk_style)
        self.chk_leak = ft.Checkbox(label="Git/Backup Leaks", value=True, on_change=self._on_module_change, **chk_style)
        self.chk_cloud = ft.Checkbox(label="Cloud Misconfig (AWS/Docker)", value=True, on_change=self._on_module_change, **chk_style)
        self.chk_auth = ft.Checkbox(label="Auth Bypass / IDOR", value=True, on_change=self._on_module_change, **chk_style)
        self.chk_api = ft.Checkbox(label="API Warfare (Swagger/GraphQL)", value=True, on_change=self._on_module_change, **chk_style) 
        self.chk_recon = ft.Checkbox(label="Deep Recon (Subfinder & JS Entropy)", value=True, on_change=self._on_module_change, **chk_style)

        self.module_count_text = ft.Text("(10/10 Selected)", size=11, color=COLOR_ACCENT_PRIMARY, font_family="Consolas")

        self.tactical_modules = ft.ExpansionTile(
            title=ft.Row([ft.Icon(ft.Icons.GRID_VIEW, color=self.COLOR_ACCENT_PRIMARY), ft.Text("TACTICAL MODULES", size=12, weight="bold", color="white", font_family="Consolas"), self.module_count_text]),
            icon_color=self.COLOR_ACCENT_PRIMARY,
            initially_expanded=False,
            controls=[
                ft.Container(
                    padding=10,
                    content=ft.Column([
                        ft.Row([self.chk_sqli, self.chk_xss]),
                        ft.Row([self.chk_nosql, self.chk_rce]),
                        ft.Row([self.chk_cve, self.chk_leak]),
                        ft.Row([self.chk_cloud, self.chk_auth]),
                        ft.Row([self.chk_api, self.chk_recon]),
                    ])
                )
            ],
            shape=ft.RoundedRectangleBorder(radius=4),
            collapsed_shape=ft.RoundedRectangleBorder(radius=4),
            bgcolor=self.COLOR_INPUT
        )
        
        # [NEW] Stealth Mode Toggle
        self.stealth_toggle = ft.Switch(
            label="ACTIVE STEALTH MODE (WAF EVASION)",
            label_style=ft.TextStyle(font_family="Consolas", color=COLOR_TEXT_MAIN, weight="bold"),
            active_color=self.COLOR_ACCENT_PRIMARY,
            track_color={ft.ControlState.SELECTED: "#224444", ft.ControlState.DEFAULT: "#222"},
            value=False
        )
        
        self.proxy_input = ft.TextField(
            hint_text="http://127.0.0.1:8080 (leave empty to disable)",
            text_style=ft.TextStyle(font_family="Consolas", size=12, color=COLOR_TEXT_DIM),
            border_color=self.COLOR_BORDER_SUBTLE,
            focused_border_color=self.COLOR_ACCENT_PRIMARY,
            bgcolor=self.COLOR_INPUT,
            height=40,
            content_padding=10,
            border_radius=4,
            cursor_color=self.COLOR_ACCENT_PRIMARY
        )

        # [Auth] Bearer Token
        self.bearer_token_input = ft.TextField(
            hint_text="eyJhbGciOiJIUzI1NiIs... (paste token without 'Bearer ' prefix)",
            text_style=ft.TextStyle(font_family="Consolas", size=12, color=COLOR_TEXT_DIM),
            border_color=self.COLOR_BORDER_SUBTLE,
            focused_border_color=self.COLOR_ACCENT_PRIMARY,
            bgcolor=self.COLOR_INPUT,
            height=40,
            content_padding=10,
            border_radius=4,
            cursor_color=self.COLOR_ACCENT_PRIMARY,
            password=True,
            can_reveal_password=True,
        )
        
        # [Auth] Form Login Config
        self.login_url_input = ft.TextField(
            hint_text="https://target.com/login",
            text_style=ft.TextStyle(font_family="Consolas", size=12, color=COLOR_TEXT_DIM),
            border_color=self.COLOR_BORDER_SUBTLE,
            focused_border_color=self.COLOR_ACCENT_PRIMARY,
            bgcolor=self.COLOR_INPUT,
            height=40, content_padding=10, border_radius=4,
            cursor_color=self.COLOR_ACCENT_PRIMARY
        )
        self.login_user_field = ft.TextField(
            hint_text="username", value="username",
            text_style=ft.TextStyle(font_family="Consolas", size=12, color=COLOR_TEXT_DIM),
            border_color=self.COLOR_BORDER_SUBTLE, bgcolor=self.COLOR_INPUT,
            height=35, content_padding=8, border_radius=4, width=150,
            cursor_color=self.COLOR_ACCENT_PRIMARY
        )
        self.login_pass_field = ft.TextField(
            hint_text="password", value="password",
            text_style=ft.TextStyle(font_family="Consolas", size=12, color=COLOR_TEXT_DIM),
            border_color=self.COLOR_BORDER_SUBTLE, bgcolor=self.COLOR_INPUT,
            height=35, content_padding=8, border_radius=4, width=150,
            cursor_color=self.COLOR_ACCENT_PRIMARY
        )
        self.login_username = ft.TextField(
            hint_text="admin",
            text_style=ft.TextStyle(font_family="Consolas", size=12, color=COLOR_TEXT_DIM),
            border_color=self.COLOR_BORDER_SUBTLE, bgcolor=self.COLOR_INPUT,
            height=35, content_padding=8, border_radius=4, expand=True,
            cursor_color=self.COLOR_ACCENT_PRIMARY
        )
        self.login_password = ft.TextField(
            hint_text="password123",
            text_style=ft.TextStyle(font_family="Consolas", size=12, color=COLOR_TEXT_DIM),
            border_color=self.COLOR_BORDER_SUBTLE, bgcolor=self.COLOR_INPUT,
            height=35, content_padding=8, border_radius=4, expand=True,
            password=True, can_reveal_password=True,
            cursor_color=self.COLOR_ACCENT_PRIMARY
        )
        self.session_validation_url = ft.TextField(
            hint_text="https://target.com/api/me (URL that returns 401 when logged out)",
            text_style=ft.TextStyle(font_family="Consolas", size=12, color=COLOR_TEXT_DIM),
            border_color=self.COLOR_BORDER_SUBTLE, bgcolor=self.COLOR_INPUT,
            height=40, content_padding=10, border_radius=4,
            focused_border_color=self.COLOR_ACCENT_PRIMARY,
            cursor_color=self.COLOR_ACCENT_PRIMARY
        )

        # Rate Limiting
        self.rps_label = ft.Text("RPS LIMIT: 20", size=11, color=COLOR_TEXT_DIM, font_family="Consolas", weight="bold")
        self.rps_slider = ft.Slider(
            min=1, max=100, divisions=99, value=20,
            active_color=self.COLOR_ACCENT_PRIMARY,
            inactive_color="#222",
            on_change=self._on_rps_change
        )

        # Scope Control
        self.scope_include = ft.TextField(
            hint_text="*.example.com, /api/* (comma-separated)",
            text_style=ft.TextStyle(font_family="Consolas", size=12, color=COLOR_TEXT_DIM),
            border_color=self.COLOR_BORDER_SUBTLE, focused_border_color=self.COLOR_ACCENT_PRIMARY,
            bgcolor=self.COLOR_INPUT, height=40, content_padding=10, border_radius=4,
            cursor_color=self.COLOR_ACCENT_PRIMARY
        )
        self.scope_exclude = ft.TextField(
            hint_text="/logout, /admin/delete* (comma-separated)",
            text_style=ft.TextStyle(font_family="Consolas", size=12, color=COLOR_TEXT_DIM),
            border_color=self.COLOR_BORDER_SUBTLE, focused_border_color=self.COLOR_ACCENT_PRIMARY,
            bgcolor=self.COLOR_INPUT, height=40, content_padding=10, border_radius=4,
            cursor_color=self.COLOR_ACCENT_PRIMARY
        )

        self.advanced_options = ft.ExpansionTile(
            title=ft.Text("ADVANCED OPTIONS", size=12, weight="bold", color=COLOR_TEXT_DIM, font_family="Consolas"), 
            icon_color=COLOR_TEXT_DIM, 
            controls=[
                ft.Container(height=5),
                # Stealth toggle
                ft.Row([
                    ft.Icon(ft.Icons.VISIBILITY_OFF, color=COLOR_TEXT_DIM, size=18),
                    self.stealth_toggle
                ], spacing=5),
                ft.Container(height=10),
                ft.Divider(color=self.COLOR_BORDER_SUBTLE),
                ft.Container(height=5),
                create_input_label("SESSION COOKIES", ft.Icons.KEY), 
                self.scan_cookies, 
                ft.Container(height=10),
                create_input_label("BEARER TOKEN", ft.Icons.TOKEN),
                self.bearer_token_input,
                ft.Container(height=10),
                ft.Divider(color=self.COLOR_BORDER_SUBTLE),
                ft.Container(height=5),
                # Form Login Config
                create_input_label("FORM LOGIN — URL", ft.Icons.LOGIN),
                self.login_url_input,
                ft.Container(height=5),
                ft.Text("FORM FIELD NAMES:", size=10, color=COLOR_TEXT_DIM, font_family="Consolas"),
                ft.Row([
                    ft.Text("Username field:", size=10, color=COLOR_TEXT_DIM), self.login_user_field,
                    ft.Text("Password field:", size=10, color=COLOR_TEXT_DIM), self.login_pass_field,
                ], spacing=5),
                ft.Container(height=5),
                ft.Text("CREDENTIALS:", size=10, color=COLOR_TEXT_DIM, font_family="Consolas"),
                ft.Row([self.login_username, self.login_password], spacing=8),
                ft.Container(height=5),
                create_input_label("SESSION VALIDATION URL", ft.Icons.VERIFIED_USER),
                self.session_validation_url,
                ft.Container(height=10),
                ft.Divider(color=self.COLOR_BORDER_SUBTLE),
                ft.Container(height=5),
                create_input_label("UPSTREAM PROXY", ft.Icons.VPN_KEY),
                self.proxy_input,
                ft.Container(height=15),
                ft.Divider(color=self.COLOR_BORDER_SUBTLE),
                ft.Container(height=5),
                # Rate Limiting
                ft.Row([ft.Icon(ft.Icons.SPEED, size=14, color=COLOR_TEXT_DIM), self.rps_label]),
                self.rps_slider,
                ft.Container(height=10),
                ft.Divider(color=self.COLOR_BORDER_SUBTLE),
                ft.Container(height=5),
                # Scope Control
                create_input_label("SCOPE — INCLUDE PATTERNS", ft.Icons.CHECK_CIRCLE_OUTLINE),
                self.scope_include,
                ft.Container(height=5),
                create_input_label("SCOPE — EXCLUDE PATTERNS", ft.Icons.BLOCK),
                self.scope_exclude,
                ft.Container(height=10)
            ], 
            shape=ft.RoundedRectangleBorder(radius=4), 
            collapsed_shape=ft.RoundedRectangleBorder(radius=4), 
            bgcolor=ft.Colors.TRANSPARENT
        )
        
        self.btn_start = ft.ElevatedButton(
            content=ft.Row([
                ft.Icon(ft.Icons.ROCKET_LAUNCH, color="black"), 
                ft.Text("INITIALIZE ATTACK VECTOR", weight="bold", font_family="Consolas", color="black")
            ], alignment=ft.MainAxisAlignment.CENTER), 
            style=ft.ButtonStyle(
                bgcolor={ft.ControlState.DEFAULT: self.COLOR_ACCENT_PRIMARY, ft.ControlState.DISABLED: "#333"}, 
                color="black", 
                shape=ft.RoundedRectangleBorder(radius=4), 
                padding=20,
                elevation=5
            ), 
            height=50, 
            width=float("inf"),
            on_click=self.start_callback,
            tooltip="Start vulnerability scan (Ctrl+Enter)"
        )
        

        
    def get_content(self):
        return ft.Container(
            padding=20, 
            content=ft.Column([
                create_input_label("TARGET ENDPOINT", ft.Icons.WEB), 
                self.url_input,
                self.url_error_text,
                ft.Container(height=8),
                create_input_label("ATTACK PROFILE", ft.Icons.TUNE), 
                self.scan_profile, 
                ft.Container(height=6),
                self.tactical_modules,
                ft.Container(height=6),
                self.advanced_options, 
                ft.Container(height=12), 
                self.btn_start,
            ],
            scroll=ft.ScrollMode.AUTO 
            )
        )

    def update_scan_state(self, is_running):
        """Toggle UI state between scanning and idle."""
        all_modules = [self.chk_sqli, self.chk_xss, self.chk_nosql, self.chk_rce, self.chk_cve, self.chk_leak, self.chk_cloud, self.chk_auth, self.chk_api, self.chk_recon]
        if is_running:
            self.btn_start.content.controls[1].value = "⬛ ABORT OPERATION"
            self.btn_start.content.controls[0].name = ft.Icons.STOP_CIRCLE
            self.btn_start.style.bgcolor = {ft.ControlState.DEFAULT: "#CF6679"}
            self.btn_start.content.controls[1].color = "white"
            self.btn_start.content.controls[0].color = "white"
            self.stealth_toggle.disabled = True
            self.url_input.disabled = True
            self.scan_profile.disabled = True
            self.scan_cookies.disabled = True
            self.proxy_input.disabled = True
            for m in all_modules: m.disabled = True
        else:
            self.btn_start.content.controls[1].value = "INITIALIZE ATTACK VECTOR"
            self.btn_start.content.controls[0].name = ft.Icons.ROCKET_LAUNCH
            self.btn_start.style.bgcolor = {ft.ControlState.DEFAULT: self.COLOR_ACCENT_PRIMARY}
            self.btn_start.content.controls[1].color = "black"
            self.btn_start.content.controls[0].color = "black"
            self.stealth_toggle.disabled = False
            self.url_input.disabled = False
            self.scan_profile.disabled = False
            self.scan_cookies.disabled = False
            self.proxy_input.disabled = False
            self.rps_slider.disabled = False
            self.scope_include.disabled = False
            self.scope_exclude.disabled = False
            for m in all_modules: m.disabled = False
        try:
            self.btn_start.update()
            self.stealth_toggle.update()
            self.url_input.update()
            self.scan_profile.update()
        except Exception: pass

    def _on_profile_change(self, e):
        val = self.scan_profile.value
        # Reset all
        controls = [self.chk_sqli, self.chk_xss, self.chk_nosql, self.chk_rce, self.chk_cve, self.chk_leak, self.chk_cloud, self.chk_auth, self.chk_api, self.chk_recon]
        for c in controls: c.value = False
        
        if val == "Full Scan":
            for c in controls: c.value = True
        elif val == "Top 10 (OWASP)":
            self.chk_sqli.value = True
            self.chk_xss.value = True
            self.chk_auth.value = True
            self.chk_cve.value = True
            self.chk_rce.value = True
            self.chk_api.value = True # Include API in Top 10
        elif val == "SQLi Only":
            self.chk_sqli.value = True
            self.chk_nosql.value = True
        elif val == "XSS Only":
            self.chk_xss.value = True
        
        # Update UI
        self._update_module_count()
        self.tactical_modules.update()
        if not self.tactical_modules.initially_expanded and val != "Custom":
             self.tactical_modules.initially_expanded = True
             self.tactical_modules.update()

    def _on_module_change(self, e=None):
        """Update the module count display."""
        self._update_module_count()

    def _update_module_count(self):
        """Count selected modules and update label."""
        controls = [self.chk_sqli, self.chk_xss, self.chk_nosql, self.chk_rce, self.chk_cve, self.chk_leak, self.chk_cloud, self.chk_auth, self.chk_api, self.chk_recon]
        count = sum(1 for c in controls if c.value)
        self.module_count_text.value = f"({count}/10 Selected)"
        if count > 0:
            self.module_count_text.color = self.COLOR_ACCENT_PRIMARY
        else:
            self.module_count_text.color = COLOR_TEXT_DIM
        try: self.module_count_text.update()
        except Exception: pass

    def _on_rps_change(self, e):
        """Update RPS label when slider changes."""
        val = int(self.rps_slider.value)
        self.rps_label.value = f"RPS LIMIT: {val}"
        try: self.rps_label.update()
        except Exception: pass

    def _on_url_change(self, e):
        """Validate URLs as user types."""
        raw = self.url_input.value or ""
        lines = [l.strip() for l in raw.strip().split('\n') if l.strip()]
        
        if not lines:
            self.url_error_text.visible = False
            self.btn_start.disabled = True
            try:
                self.url_error_text.update()
                self.btn_start.update()
            except Exception: pass
            return
        
        invalid = []
        url_pattern = re.compile(r'^https?://.+', re.IGNORECASE)
        for line in lines:
            if not url_pattern.match(line):
                invalid.append(line)
        
        if invalid:
            short = invalid[0] if len(invalid[0]) < 50 else invalid[0][:47] + "..."
            self.url_error_text.value = f"⚠ Invalid URL: '{short}' — must start with http:// or https://"
            self.url_error_text.visible = True
            self.url_input.border_color = COLOR_SEV_CRITICAL
            self.btn_start.disabled = True
        else:
            self.url_error_text.visible = False
            self.url_input.border_color = self.COLOR_BORDER_SUBTLE
            self.btn_start.disabled = False
        
        try:
            self.url_error_text.update()
            self.url_input.update()
            self.btn_start.update()
        except Exception: pass
