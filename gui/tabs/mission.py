import flet as ft
from gui.theme import *
from gui.components.ui_helpers import create_input_label

class MissionTab:
    def __init__(self, start_callback):
        self.start_callback = start_callback
        
        # [THEME] Tactical Slate Palette
        self.COLOR_SURFACE = "#1E1E1E"
        self.COLOR_INPUT = "#252525"
        self.COLOR_BORDER_SUBTLE = "#333333"
        self.COLOR_ACCENT_PRIMARY = ft.Colors.CYAN_400
        
        # Inputs
        self.url_input = ft.TextField(
            hint_text="https://target.com", 
            text_style=ft.TextStyle(font_family="Consolas", color="white"), 
            border_color=self.COLOR_BORDER_SUBTLE, 
            focused_border_color=self.COLOR_ACCENT_PRIMARY, 
            bgcolor=self.COLOR_INPUT, 
            height=45, 
            content_padding=15, 
            border_radius=4,
            prefix_icon=ft.Icons.LINK, 
            prefix_style=ft.TextStyle(color=self.COLOR_ACCENT_PRIMARY),
            expand=True,
            cursor_color=self.COLOR_ACCENT_PRIMARY
        )
        
        self.scan_profile = ft.Dropdown(
            options=[
                ft.dropdown.Option("Top 10 (OWASP)"), 
                ft.dropdown.Option("Full Scan"), 
                ft.dropdown.Option("SQLi Only"), 
                ft.dropdown.Option("XSS Only"),
                ft.dropdown.Option("Custom")
            ], 
            value="Custom", 
            bgcolor=self.COLOR_INPUT, 
            border_color=self.COLOR_BORDER_SUBTLE, 
            focused_border_color=self.COLOR_ACCENT_PRIMARY, 
            text_style=ft.TextStyle(color="white", font_family="Consolas"), 
            # content_padding=10, 
            border_radius=4, 
            expand=True,
            on_change=self._on_profile_change,
            # height=45
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
        
        self.chk_sqli = ft.Checkbox(label="SQL Injection (SQLi)", value=False, **chk_style)
        self.chk_xss = ft.Checkbox(label="Cross-Site Scripting (XSS)", value=False, **chk_style)
        self.chk_nosql = ft.Checkbox(label="NoSQL Injection", value=False, **chk_style)
        self.chk_rce = ft.Checkbox(label="RCE / Cmd Injection", value=False, **chk_style)
        self.chk_cve = ft.Checkbox(label="CVE Sniper (Known Exploits)", value=False, **chk_style)
        self.chk_leak = ft.Checkbox(label="Git/Backup Leaks", value=False, **chk_style)
        self.chk_cloud = ft.Checkbox(label="Cloud Misconfig (AWS/Docker)", value=False, **chk_style)
        self.chk_auth = ft.Checkbox(label="Auth Bypass / IDOR", value=False, **chk_style)
        self.chk_api = ft.Checkbox(label="API Warfare (Swagger/GraphQL)", value=False, **chk_style) 
        self.chk_recon = ft.Checkbox(label="Deep Recon (Subfinder & JS Entropy)", value=False, **chk_style)

        self.tactical_modules = ft.ExpansionTile(
            title=ft.Row([ft.Icon(ft.Icons.GRID_VIEW, color=self.COLOR_ACCENT_PRIMARY), ft.Text("TACTICAL MODULES", size=12, weight="bold", color="white", font_family="Consolas")]),
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
        
        self.advanced_options = ft.ExpansionTile(
            title=ft.Text("AUTHENTICATION & HEADERS", size=12, weight="bold", color=COLOR_TEXT_DIM, font_family="Consolas"), 
            icon_color=COLOR_TEXT_DIM, 
            controls=[
                ft.Container(height=5), 
                create_input_label("SESSION COOKIES", ft.Icons.KEY), 
                self.scan_cookies, 
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
            on_click=self.start_callback
        )
        
    def get_content(self):
        mission_card = ft.Container(
            padding=25, 
            bgcolor=self.COLOR_SURFACE, 
            border_radius=8, 
            border=ft.border.all(1, self.COLOR_BORDER_SUBTLE),
            shadow=ft.BoxShadow(blur_radius=15, spread_radius=1, color=ft.Colors.with_opacity(0.2, "black")), 
            content=ft.Column([
                ft.Row([ft.Icon(ft.Icons.ADS_CLICK, color=self.COLOR_ACCENT_PRIMARY), ft.Text("TARGET ACQUISITION", size=14, weight="bold", color="white", font_family="Consolas")]), 
                ft.Divider(color=self.COLOR_BORDER_SUBTLE), 
                ft.Container(height=10),
                create_input_label("TARGET ENDPOINT", ft.Icons.WEB), 
                self.url_input, 
                ft.Container(height=15),
                create_input_label("ATTACK PROFILE", ft.Icons.TUNE), 
                self.scan_profile, 
                ft.Container(height=10),
                
                # [NEW] Tactical Modules
                self.tactical_modules,
                ft.Container(height=10),

                # [NEW] Stealth Toggle
                ft.Container(
                    padding=10,
                    bgcolor=self.COLOR_INPUT,
                    border_radius=4,
                    border=ft.border.all(1, self.COLOR_BORDER_SUBTLE),
                    content=ft.Row([
                        ft.Icon(ft.Icons.VISIBILITY_OFF, color=COLOR_TEXT_DIM),
                        self.stealth_toggle
                    ])
                ),
                
                ft.Divider(color=self.COLOR_BORDER_SUBTLE), 
                self.advanced_options, 
                ft.Container(height=15), 
                self.btn_start, 
                ft.Container(height=15),
                ft.Divider(color=self.COLOR_BORDER_SUBTLE),
            ])
        )
        return ft.Container(
            padding=30, 
            content=ft.Column(
                [
                    mission_card, 
                    ft.Container(expand=True), 
                    ft.Container(height=20),
                    ft.Text("LOCKON SECURITY SUITE v3.5 (TITAN)", size=10, color=COLOR_TEXT_DIM, text_align=ft.TextAlign.CENTER, font_family="Consolas")
                ],
                scroll=ft.ScrollMode.AUTO 
            )
        )

    def update_scan_state(self, is_running):
        if is_running:
            self.btn_start.content.controls[1].value = "ABORT OPERATION"
            self.btn_start.content.controls[0].name = ft.Icons.STOP_CIRCLE
            self.btn_start.style.bgcolor = {ft.ControlState.DEFAULT: "#CF6679"} # Muted Red
            self.btn_start.content.controls[1].color = "white"
            self.btn_start.content.controls[0].color = "white"
            self.stealth_toggle.disabled = True # Lock during scan
        else:
            self.btn_start.content.controls[1].value = "INITIALIZE ATTACK VECTOR"
            self.btn_start.content.controls[0].name = ft.Icons.ROCKET_LAUNCH
            self.btn_start.style.bgcolor = {ft.ControlState.DEFAULT: self.COLOR_ACCENT_PRIMARY}
            self.btn_start.content.controls[1].color = "black"
            self.btn_start.content.controls[0].color = "black"
            self.stealth_toggle.disabled = False
        self.btn_start.update()
        self.stealth_toggle.update()

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
        self.tactical_modules.update()
        if not self.tactical_modules.initially_expanded and val != "Custom":
             self.tactical_modules.initially_expanded = True
             self.tactical_modules.update()
