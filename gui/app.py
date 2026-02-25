import flet as ft
import threading
import asyncio
import time
import os
import sys
from datetime import datetime

from core.scanner import ScannerThread
from core.database import init_db
from core.c2_manager import c2_manager
from core import config as app_config
from modules.active import cve_sniper, upload_rce 

from gui.theme import *
from gui.utils import sanitize_log_message
from gui.tabs.mission import MissionTab
from gui.tabs.findings import FindingsTab
from gui.tabs.system import SystemTab
from gui.tabs.graph import GraphTab
from gui.tabs.phantom import PhantomTab
from gui.tabs.history import HistoryTab
from gui.tabs.proxy import ProxyTab
from gui.tabs.payload_editor import PayloadEditorTab

def main(page: ft.Page):
    apply_theme(page)
    init_db()

    # --- STATE ---
    scan_in_progress = False
    current_scanner = None
    alert_active = False
    
    # --- DASHBOARD COMPONENTS ---
    cyber_bar = ft.ProgressBar(width=None, color="#00ff41", bgcolor="#1a1a1a", value=0)
    lbl_progress_pct = ft.Text("0%", size=10, color="white", font_family="Consolas", weight="bold")
    lbl_phase = ft.Text("SYSTEM READY", font_family="Consolas", color="#33FF33", size=12, weight="bold")
    lbl_time = ft.Text("T+: 00:00", font_family="Consolas", color=COLOR_TEXT_DIM, size=11)
    
    dashboard_header = ft.Container(
        padding=10,
        bgcolor="#0a0a0a",
        border=ft.border.only(bottom=ft.BorderSide(1, COLOR_BORDER)),
        content=ft.Column([
            ft.Row([lbl_phase, ft.Container(expand=True), lbl_time], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Container(height=5),
            ft.Row([
                ft.Container(content=cyber_bar, expand=True),
                ft.Container(width=5),
                lbl_progress_pct,
            ], vertical_alignment=ft.CrossAxisAlignment.CENTER),
        ])
    )

    # --- UI COMPONENTS ---
    terminal_list = ft.ListView(expand=True, spacing=2, padding=15, auto_scroll=True)
    all_logs = []  # Store all log entries for filtering
    current_log_filter = ["ALL"]  # Mutable filter state

    # --- Log Filter Buttons ---
    FILTER_ACTIVE_COLOR = COLOR_ACCENT_PRIMARY  # Blue, not red
    
    def set_log_filter(filter_type):
        current_log_filter[0] = filter_type
        terminal_list.controls.clear()
        for entry in all_logs:
            if filter_type == "ALL" or entry["level"] == filter_type:
                terminal_list.controls.append(entry["widget"])
        # Update button styles
        for btn in log_filter_row.controls:
            if hasattr(btn, 'data'):
                btn.style = ft.ButtonStyle(
                    bgcolor=FILTER_ACTIVE_COLOR if btn.data == filter_type else "transparent",
                    color="white" if btn.data == filter_type else COLOR_TEXT_DIM,
                    shape=ft.RoundedRectangleBorder(radius=3),
                    padding=ft.padding.symmetric(horizontal=8, vertical=2),
                    side=ft.BorderSide(1, COLOR_BORDER) if btn.data != filter_type else None,
                )
        page.update()

    def make_filter_btn(label, filter_key, is_active=False):
        return ft.TextButton(
            text=label, data=filter_key,
            style=ft.ButtonStyle(
                bgcolor=FILTER_ACTIVE_COLOR if is_active else "transparent",
                color="white" if is_active else COLOR_TEXT_DIM,
                shape=ft.RoundedRectangleBorder(radius=3),
                padding=ft.padding.symmetric(horizontal=8, vertical=2),
                side=None if is_active else ft.BorderSide(1, COLOR_BORDER),
            ),
            height=24,
            on_click=lambda e: set_log_filter(e.control.data)
        )
    
    log_search = ft.TextField(
        hint_text="Search logs...", 
        height=26,
        text_size=11,
        text_style=ft.TextStyle(font_family="Consolas", color="white"),
        border_color=COLOR_BORDER, 
        focused_border_color=COLOR_ACCENT_PRIMARY,
        bgcolor=COLOR_BG_INPUT, 
        content_padding=ft.padding.symmetric(horizontal=8, vertical=2),
        border_radius=3,
        prefix_icon=ft.Icons.SEARCH,
        expand=True,
        on_change=lambda e: search_logs(e.control.value)
    )
    
    def search_logs(query):
        q = query.lower().strip()
        terminal_list.controls.clear()
        for entry in all_logs:
            if current_log_filter[0] != "ALL" and entry["level"] != current_log_filter[0]:
                continue
            if q and q not in entry["text"].lower():
                continue
            terminal_list.controls.append(entry["widget"])
        page.update()
    
    def clear_logs(e):
        def do_clear(e_inner):
            page.close(confirm_clear_dlg)
            terminal_list.controls.clear()
            all_logs.clear()
            btn_clear_logs.opacity = 0.3
            page.update()
        confirm_clear_dlg = ft.AlertDialog(
            title=ft.Text("Clear Logs?", font_family="Consolas", weight="bold"),
            content=ft.Text("All execution logs will be permanently removed.", color=COLOR_TEXT_DIM),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e_inner: page.close(confirm_clear_dlg)),
                ft.ElevatedButton("Clear", bgcolor=COLOR_SEV_CRITICAL, color="white", on_click=do_clear),
            ],
            bgcolor=COLOR_BG_PANEL,
        )
        page.open(confirm_clear_dlg)
    
    log_filter_row = ft.Row([
        make_filter_btn("ALL", "ALL", True),
        make_filter_btn("WRN", "WRN"),
        make_filter_btn("ERR", "ERR"),
        make_filter_btn("OK", "OK"),
    ], spacing=4)

    btn_clear_logs = ft.IconButton(ft.Icons.DELETE_SWEEP, icon_size=14, icon_color=COLOR_TEXT_DIM, tooltip="Clear Logs (Ctrl+L)", on_click=clear_logs, opacity=0.3)
    
    # Toggle right panel state
    panel_visible = [True]
    saved_panel_width = [None]
    
    def toggle_right_panel(e):
        panel_visible[0] = not panel_visible[0]
        if panel_visible[0]:
            right_panel.visible = True
            main_splitter.visible = True
            btn_toggle_panel.icon = ft.Icons.CHEVRON_RIGHT
            btn_toggle_panel.tooltip = "Hide Log Panel"
        else:
            right_panel.visible = False
            main_splitter.visible = False
            btn_toggle_panel.icon = ft.Icons.CHEVRON_LEFT
            btn_toggle_panel.tooltip = "Show Log Panel"
        page.update()
    
    btn_toggle_panel = ft.IconButton(ft.Icons.CHEVRON_RIGHT, icon_size=14, icon_color=COLOR_TEXT_DIM, tooltip="Hide Log Panel", on_click=toggle_right_panel)

    terminal_header = ft.Container(
        padding=ft.padding.symmetric(horizontal=10, vertical=4),
        bgcolor=COLOR_BG_PANEL,
        border=ft.border.only(bottom=ft.BorderSide(1, COLOR_BORDER), top=ft.BorderSide(1, COLOR_BORDER)),
        content=ft.Column([
            ft.Row([
                ft.Icon(ft.Icons.TERMINAL, size=14, color=COLOR_SEV_INFO),
                ft.Text("EXECUTION LOGS", size=11, weight="bold", color=COLOR_TEXT_MAIN, font_family="Consolas"),
                ft.Container(expand=True),
                btn_clear_logs,
                btn_toggle_panel,
            ], vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=5),
            ft.Row([
                log_filter_row,
                ft.Container(width=5),
                log_search,
            ], vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=4),
        ], spacing=4)
    )
    
    right_panel = ft.Container(
        expand=1, bgcolor=COLOR_TERM_BG, border=ft.border.only(left=ft.BorderSide(1, COLOR_BORDER)),
        content=ft.Column([terminal_header, terminal_list, dashboard_header], spacing=0)
    )

    # Logging Logic
    def log(message):
        clean_msg, color_hex = sanitize_log_message(message)
        timestamp = datetime.now().strftime("%H:%M:%S")
        # Classify log level for filtering
        level = "ALL"
        msg_lower = clean_msg.lower()
        if any(x in msg_lower for x in ["[wrn]", "warning", "vulnerable"]): level = "WRN"
        elif any(x in msg_lower for x in ["[err]", "error", "fail", "abort"]): level = "ERR"
        elif any(x in msg_lower for x in ["[ok]", "complete", "success", "generated"]): level = "OK"
        
        row = ft.Container(content=ft.Row([ft.Text(f"[{timestamp}]", font_family="Consolas", size=11, color=COLOR_TEXT_DIM), ft.Text(clean_msg, font_family="Consolas", size=11, color=color_hex, selectable=True)], spacing=10, vertical_alignment=ft.CrossAxisAlignment.START), padding=ft.padding.only(bottom=2))
        all_logs.append({"widget": row, "level": level, "text": clean_msg})
        if current_log_filter[0] == "ALL" or current_log_filter[0] == level:
            terminal_list.controls.append(row)
        
        # Update clear button opacity when logs exist
        btn_clear_logs.opacity = 1.0 if len(all_logs) > 0 else 0.3
        page.update()

    # --- EXPLOIT LOGIC ---
    async def execute_exploit_logic(exploit_type, data):
        if exploit_type == "upload_shell":
            return await upload_rce.launch_exploit(data)
        elif exploit_type.startswith("cve_"):
            return await cve_sniper.launch_exploit(exploit_type, data)
        return False

    def on_exploit_click(e, finding):
        def run_exploit_thread():
            exploit_type = finding.get('exploit_type')
            data = finding.get('exploit_data')
            if not exploit_type or not data: return

            exploit_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(exploit_loop)
            try:
                log(f"[DEBUG] Executing Exploit: {exploit_type}")
                success = exploit_loop.run_until_complete(execute_exploit_logic(exploit_type, data))
                
                if page.snack_bar:
                   page.snack_bar.open = False
                   page.update()
                   time.sleep(0.2)
                
                msg = "✅ Connection Established! Device Pwned." if success else "❌ Exploit Failed (Timeout or Firewall Blocked)"
                col = "#33FF33" if success else "#FF3333"
                txt_col = "black" if success else "white"
                
                page.snack_bar = ft.SnackBar(ft.Text(msg, color=txt_col, weight="bold"), bgcolor=col)
                page.snack_bar.open = True
                page.update()
                
            except Exception as ex:
                log(f"Exploit Error: {ex}")
                page.snack_bar = ft.SnackBar(ft.Text(f"❌ Error: {ex}", color="white"), bgcolor="#FF3333")
                page.snack_bar.open = True
                page.update()
            finally:
                exploit_loop.close()

        tabs.selected_index = 2 # Go to Phantom Tab (Unified C2)
        page.update()
        threading.Thread(target=run_exploit_thread, daemon=True).start()
        
        page.snack_bar = ft.SnackBar(ft.Text("🚀 Launching Exploit... Connection incoming..."), bgcolor=COLOR_SEV_CRITICAL)
        page.snack_bar.open = True
        page.update()
        
    def show_exploit_popup(finding):
        nonlocal alert_active
        if alert_active: return
        alert_active = True
        try:
            def on_confirm(e):
                nonlocal alert_active
                alert_active = False
                page.close_dialog()
                on_exploit_click(e, finding)
            def on_cancel(e):
                nonlocal alert_active
                alert_active = False
                page.close_dialog()

            dlg = ft.AlertDialog(
                title=ft.Text("⚡ CRITICAL VULNERABILITY DETECTED", weight="bold", color=COLOR_SEV_CRITICAL, font_family="Consolas"),
                content=ft.Container(
                   width=400,
                   content=ft.Column([
                       ft.Text(f"Target is vulnerable to:", size=12, color=COLOR_TEXT_DIM),
                       ft.Text(f"{finding.get('type')}", size=16, weight="bold", color="white"),
                       ft.Divider(color=COLOR_BORDER),
                       ft.Text("Do you want to launch the C2 Exploit and establish a Reverse Shell now?", size=14)
                   ], tight=True)
                ),
                actions=[
                    ft.TextButton("IGNORE", on_click=on_cancel),
                    ft.ElevatedButton("🚀 EXECUTE RCE", bgcolor=COLOR_SEV_CRITICAL, color="white", on_click=on_confirm),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
                bgcolor=COLOR_BG_PANEL,
                modal=True 
            )
            page.dialog = dlg
            dlg.open = True
            page.update()
        except Exception:
            alert_active = False

    # --- TABS INITIALIZATION ---

    # 1. Findings Tab (Needed early for callback)
    # 1. Findings Tab (Needed early for callback)
    findings_tab = FindingsTab(page, log, on_exploit_click)
    
    def add_finding_wrapper(finding):
        findings_tab.add_finding(finding)
        # [GRAPH VISUALIZER]
        try:
            node_id = f"NODE_{int(time.time()*1000)}"
            color = "white"
            icon = ft.Icons.BUG_REPORT
            if finding.get('severity') == "Critical": 
                color = "#ff0000"; icon = ft.Icons.DANGEROUS
            elif finding.get('severity') == "High": 
                color = "#ff9100"; icon = ft.Icons.WARNING
            elif finding.get('severity') == "Medium": 
                color = "#ffea00"; icon = ft.Icons.INFO
            
            title = finding.get('type', 'Unknown')
            
            # [KILL CHAIN MAPPING] Intelligent Parent Selection
            def get_kill_chain_stage(f_type, f_sev):
                ft_lower = f_type.lower()
                
                # Phase 4: Actions on Objective (Critical Data/Control Loss)
                if any(x in ft_lower for x in ['exfil', 'oast', 'pii', 'shell', 'takeover', 'extracted', 'dump']):
                    return "ACTION"
                    
                # Phase 3: Exploitation (Code/Command Execution, Injection)
                if any(x in ft_lower for x in ['sql', 'rce', 'upload', 'command', 'xxe', 'deserialization', 'injection', 'bypass']):
                    return "EXPLOIT"
                
                # Phase 2: Weaponization (Client-Side, Auth, Logic flaws)
                if any(x in ft_lower for x in ['xss', 'idor', 'weak', 'missing', 'logic', 'race', 'csrf', 'hijack']):
                    return "WEAPON"
                    
                # Phase 1: Reconnaissance (Info Leak, headers, etc)
                # Default fallthrough for Low/Info items or unknown
                return "RECON"

            parent_stage = get_kill_chain_stage(title, finding.get('severity'))
            
            graph_tab.add_node(
                node_id=node_id,
                label=title,
                icon=icon,
                color=color,
                parent_id=parent_stage 
            )
        except Exception as e:
            pass # UI should not crash scanning

        if finding.get('exploit_type'):
             try: show_exploit_popup(finding)
             except Exception: pass

    # 2. Mission Tab
    def on_scan_finish():
        nonlocal scan_in_progress
        scan_in_progress = False
        mission_tab.update_scan_state(False)
        log("Mission execution completed.")
        # [NEW] Notification
        try:
            page.snack_bar = ft.SnackBar(
                ft.Row([
                    ft.Icon(ft.Icons.CHECK_CIRCLE, color="white", size=20),
                    ft.Text("Scan Complete! Check Findings tab for results.", color="white", weight="bold")
                ]),
                bgcolor="#2e7d32",
                duration=5000
            )
            page.snack_bar.open = True
        except Exception:
            pass
        # System bell sound
        try:
            if app_config.get("notification.sound", True):
                if sys.platform == 'win32':
                    import winsound
                    winsound.Beep(800, 200)
                    winsound.Beep(1000, 200)
                else:
                    print('\a')
        except Exception:
            pass
        page.update()
    
    def start_scan_click(e):
        nonlocal scan_in_progress, current_scanner, alert_active
        raw_input = mission_tab.url_input.value
        stealth_mode = mission_tab.stealth_toggle.value
        
        if scan_in_progress:
            if current_scanner:
                def do_abort(e_inner):
                    page.close(abort_dlg)
                    log("\U0001f6d1 ABORT COMMAND RECEIVED.")
                    current_scanner.stop()
                    mission_tab.btn_start.content.controls[1].value = "STOPPING..."
                    page.update()
                abort_dlg = ft.AlertDialog(
                    title=ft.Text("Abort Scan?", font_family="Consolas", weight="bold"),
                    content=ft.Text("The current scan will be terminated immediately.", color=COLOR_TEXT_DIM),
                    actions=[
                        ft.TextButton("Continue Scan", on_click=lambda e_inner: page.close(abort_dlg)),
                        ft.ElevatedButton("Abort", bgcolor=COLOR_SEV_CRITICAL, color="white", on_click=do_abort),
                    ],
                    bgcolor=COLOR_BG_PANEL,
                )
                page.open(abort_dlg)
            return

        if not raw_input: return
        
        # [NEW] Multi-target: split by newlines
        targets = [t.strip() for t in raw_input.strip().split('\n') if t.strip()]
        if not targets: return
        
        scan_in_progress = True
        
        # Reset UI
        findings_tab.clear()
        terminal_list.controls.clear()
        alert_active = False
        c2_manager.output_buffer = "--- C2 READY: WAITING FOR CONNECTION ---\n"
        
        mission_tab.update_scan_state(True)
        if stealth_mode: log(f"\U0001f977 STEALTH MODE ACTIVE: Jitter & WAF Evasion Enabled.")
        
        # [MOD] Collect Tactical Modules
        modules_config = {
            "sqli": mission_tab.chk_sqli.value,
            "xss": mission_tab.chk_xss.value,
            "nosql": mission_tab.chk_nosql.value,
            "rce": mission_tab.chk_rce.value,
            "cve": mission_tab.chk_cve.value,
            "leak": mission_tab.chk_leak.value,
            "cloud": mission_tab.chk_cloud.value,
            "auth": mission_tab.chk_auth.value,
            "api": mission_tab.chk_api.value, 
            "recon": mission_tab.chk_recon.value
        }
        
        # [NEW] Proxy from mission tab
        proxy_url = getattr(mission_tab, 'proxy_input', None)
        proxy = proxy_url.value if proxy_url and proxy_url.value else None

        def run_sequential_targets():
            nonlocal current_scanner
            for idx, target in enumerate(targets):
                if not scan_in_progress: break
                if len(targets) > 1:
                    log(f"\U0001f3af [{idx+1}/{len(targets)}] Scanning target: {target}")
                else:
                    log(f"Initializing Lockon Protocol on {target}")
                
                # [NEW] Set target_url on findings tab
                findings_tab.target_url = target
                
                done_event = threading.Event()
                def target_finished():
                    done_event.set()
                
                current_scanner = ScannerThread(
                    target, 
                    mission_tab.scan_profile.value, 
                    log, 
                    add_finding_wrapper, 
                    target_finished, 
                    mission_tab.scan_cookies.value,
                    stealth_mode=stealth_mode,
                    modules_config=modules_config,
                    proxy_url=proxy,
                    max_rps=int(mission_tab.rps_slider.value),
                    scope_config={
                        'includes': mission_tab.scope_include.value or '',
                        'excludes': mission_tab.scope_exclude.value or ''
                    },
                    auth_config={
                        'bearer_token': mission_tab.bearer_token_input.value or '',
                        'login_url': mission_tab.login_url_input.value or '',
                        'user_field': mission_tab.login_user_field.value or 'username',
                        'pass_field': mission_tab.login_pass_field.value or 'password',
                        'username': mission_tab.login_username.value or '',
                        'password': mission_tab.login_password.value or '',
                        'validation_url': mission_tab.session_validation_url.value or ''
                    }
                )
                current_scanner.start()
                done_event.wait()  # Block until this target finishes
            
            on_scan_finish()
        
        threading.Thread(target=run_sequential_targets, daemon=True).start()
        page.update()

    mission_tab = MissionTab(start_scan_click)
    

    # 3. History Tab
    history_tab = HistoryTab(page)
    
    # 4. C2 Operations & Graph
    graph_tab = GraphTab(page)
    phantom_tab = PhantomTab(page)
    
    # 5. System Tab
    bin_path = os.path.join(os.getcwd(), "bin")
    system_tab = SystemTab(page, bin_path, log)

    # 6. Proxy/Intercept Tab
    proxy_tab = ProxyTab(page, log_callback=log)

    # 7. Payload Editor Tab
    payload_tab = PayloadEditorTab(page)

    # --- TAB CHANGE HANDLER ---
    def on_tab_change(e):
        if e.control.selected_index == 1:
            try: graph_tab.auto_refresh()
            except Exception: pass
        elif e.control.selected_index == 7:  # HISTORY tab (shifted by 2 new tabs)
            try: history_tab.load_history()
            except Exception: pass

    # --- Notification Badge for Findings ---
    findings_badge = ft.Container(
        content=ft.Text("0", size=9, color="white", weight="bold", text_align=ft.TextAlign.CENTER),
        width=20, height=16,
        border_radius=8,
        bgcolor=COLOR_ACCENT_PRIMARY,
        alignment=ft.alignment.center,
        visible=False
    )
    findings_tab_label = ft.Tab(
        tab_content=ft.Column([
            ft.Stack([
                ft.Container(
                    content=ft.Icon(ft.Icons.SECURITY_UPDATE_WARNING, size=24),
                    width=30, height=30,
                    alignment=ft.alignment.center,
                ),
                ft.Container(
                    content=findings_badge,
                    alignment=ft.alignment.top_right,
                ),
            ], width=30, height=30),
            ft.Text("FINDINGS", size=12),
        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=2),
        content=findings_tab.get_content()
    )
    
    # Store badge ref for updates
    _finding_count = [0]
    original_add_finding = findings_tab.add_finding
    def wrapped_add_finding(finding):
        original_add_finding(finding)
        _finding_count[0] += 1
        findings_badge.content.value = str(_finding_count[0])
        findings_badge.visible = True
        try: findings_badge.update()
        except Exception: pass
    findings_tab.add_finding = wrapped_add_finding
    
    # Override clear to reset badge
    original_clear = findings_tab.clear
    def wrapped_clear():
        original_clear()
        _finding_count[0] = 0
        findings_badge.visible = False
        try: findings_badge.update()
        except Exception: pass
    findings_tab.clear = wrapped_clear

    # --- LAYOUT --
    tabs = ft.Tabs(
        selected_index=0, animation_duration=300, on_change=on_tab_change,
        tabs=[
            ft.Tab(text="MISSION", icon=ft.Icons.RADAR, content=mission_tab.get_content()),
            ft.Tab(text="KILL CHAIN", icon=ft.Icons.POLYLINE, content=graph_tab.get_content()),
            ft.Tab(text="PHANTOM", icon=ft.Icons.BUG_REPORT, content=phantom_tab.content),
            findings_tab_label,
            ft.Tab(text="SYSTEM", icon=ft.Icons.MEMORY, content=system_tab.get_content()),
            ft.Tab(text="INTERCEPT", icon=ft.Icons.SWAP_VERT, content=proxy_tab.get_content()),
            ft.Tab(text="PAYLOAD", icon=ft.Icons.CODE, content=payload_tab.get_content()),
            ft.Tab(text="HISTORY", icon=ft.Icons.HISTORY, content=history_tab.get_content()),
        ],
        expand=True,
        divider_color=COLOR_BORDER,
        indicator_color=COLOR_ACCENT_PRIMARY,
        indicator_border_radius=0,
        indicator_border_side=ft.BorderSide(3, COLOR_ACCENT_PRIMARY),
        indicator_padding=ft.padding.only(bottom=0),
        label_color="white",
        unselected_label_color=COLOR_TEXT_DIM,
        overlay_color=ft.Colors.TRANSPARENT,
        label_padding=ft.padding.symmetric(horizontal=12, vertical=8),
    )
    
    # --- STATUS BAR ---
    status_conn = ft.Text("● IDLE", size=10, color=COLOR_SEV_LOW, font_family="Consolas", weight="bold")
    status_target = ft.Text("No target", size=10, color=COLOR_TEXT_DIM, font_family="Consolas")
    status_elapsed = ft.Text("00:00", size=10, color=COLOR_TEXT_DIM, font_family="Consolas")
    status_findings_count = ft.Text("0 findings", size=10, color=COLOR_TEXT_DIM, font_family="Consolas")
    
    status_bar = ft.Container(
        height=26,
        bgcolor="#0a0a0a",
        border=ft.border.only(top=ft.BorderSide(1, COLOR_BORDER)),
        padding=ft.padding.symmetric(horizontal=15, vertical=3),
        content=ft.Row([
            status_conn,
            ft.VerticalDivider(width=1, color=COLOR_BORDER),
            ft.Icon(ft.Icons.LINK, size=12, color=COLOR_TEXT_DIM),
            status_target,
            ft.VerticalDivider(width=1, color=COLOR_BORDER),
            ft.Icon(ft.Icons.TIMER, size=12, color=COLOR_TEXT_DIM),
            status_elapsed,
            ft.Container(expand=True),
            status_findings_count,
            ft.VerticalDivider(width=1, color=COLOR_BORDER),
            ft.Text("v1.0.0", size=9, color=COLOR_TEXT_DIM, font_family="Consolas"),
        ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER)
    )
    
    # --- KEYBOARD SHORTCUTS ---
    def on_keyboard(e: ft.KeyboardEvent):
        nonlocal scan_in_progress
        if e.ctrl:
            if e.key == "Enter":  # Ctrl+Enter: Start scan
                if not scan_in_progress:
                    start_scan_click(None)
            elif e.key == "L":  # Ctrl+L: Clear logs
                terminal_list.controls.clear()
                all_logs.clear()
                page.update()
            elif e.key == "E":  # Ctrl+E: Export
                findings_tab.export_html()
            elif e.key in "123456":  # Ctrl+1-6: Switch tabs
                tabs.selected_index = int(e.key) - 1
                on_tab_change(type('obj', (object,), {'control': tabs})())
                page.update()
        elif e.key == "Escape":  # Esc: Abort
            if scan_in_progress and current_scanner:
                start_scan_click(None)  # Triggers abort dialog
    
    page.on_keyboard_event = on_keyboard
    
    # --- LAYOUT LOGIC (Resizable) ---
    left_width = [None]  # Will be set on first layout
    left_panel = ft.Container(expand=2, bgcolor=COLOR_BG_APP, content=tabs)

    def on_splitter_drag(e: ft.DragUpdateEvent):
        # Initialize from actual width on first drag
        if left_width[0] is None:
            try:
                left_width[0] = page.window.width * 0.65  # approx expand=2 ratio
            except Exception:
                left_width[0] = 640
        left_width[0] = max(300, min(page.window.width - 280, left_width[0] + e.delta_x))
        left_panel.width = left_width[0]
        left_panel.expand = None  # Switch from expand to fixed width
        page.update()

    main_splitter = ft.GestureDetector(
        content=ft.Container(
            width=5, 
            bgcolor=COLOR_BORDER,
            content=ft.Icon(ft.Icons.DRAG_HANDLE, size=16, color=COLOR_TEXT_DIM, rotate=1.57),
            alignment=ft.alignment.center
        ),
        mouse_cursor=ft.MouseCursor.RESIZE_COLUMN,
        on_pan_update=on_splitter_drag,
    )

    page.add(ft.Column([
        ft.Row([
            left_panel, 
            main_splitter, 
            right_panel
        ], expand=True, spacing=0),
        status_bar
    ], expand=True, spacing=0))
    
    # --- STATS LOOP ---
    def update_stats_ui(stats):
        cyber_bar.value = stats['progress']
        pct = int(stats['progress'] * 100)
        lbl_progress_pct.value = f"{pct}%"
        if stats['progress'] > 0.8: cyber_bar.color = "#00ff41" 
        elif stats['progress'] > 0.4: cyber_bar.color = "#ffbd2e" 
        else: cyber_bar.color = "#00b4d8" 
        
        lbl_phase.value = f"STATUS: {stats['phase'].upper()}"
        
        mins, secs = divmod(stats['duration'], 60)
        time_str = f"T+: {int(mins):02}:{int(secs):02}"
        lbl_time.value = time_str
        
        # Update status bar
        status_conn.value = "● SCANNING" if scan_in_progress else "● IDLE"
        status_conn.color = COLOR_SEV_CRITICAL if scan_in_progress else COLOR_SEV_LOW
        status_target.value = getattr(findings_tab, 'target_url', 'No target')
        status_elapsed.value = f"{int(mins):02}:{int(secs):02}"
        status_findings_count.value = f"{len(findings_tab.findings_data)} findings"
        
        try:
            lbl_phase.update()
            lbl_time.update()
            lbl_progress_pct.update()
            cyber_bar.update()
            status_bar.update()
        except Exception:
            pass

    def stats_loop():
        while True:
            try:
                if scan_in_progress and current_scanner:
                    stats = current_scanner.get_stats()
                    update_stats_ui(stats)
                time.sleep(1)
            except Exception:
                time.sleep(1)
    
    threading.Thread(target=stats_loop, daemon=True).start()
