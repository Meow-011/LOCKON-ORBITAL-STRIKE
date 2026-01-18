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
from modules.active import cve_sniper, upload_rce 

from gui.theme import *
from gui.utils import sanitize_log_message
from gui.tabs.mission import MissionTab
from gui.tabs.findings import FindingsTab
from gui.tabs.system import SystemTab
from gui.tabs.graph import GraphTab # [NEW] Orbital Graph
from gui.tabs.phantom import PhantomTab # [NEW] Protocol Phantom

def main(page: ft.Page):
    apply_theme(page)
    init_db()

    # --- STATE ---
    scan_in_progress = False
    current_scanner = None
    alert_active = False
    
    # --- DASHBOARD COMPONENTS (Moved from MissionTab) ---
    # ... (Keep existing dashboard components) ...
    cyber_bar = ft.ProgressBar(width=None, color="#00ff41", bgcolor="#1a1a1a", value=0)
    lbl_phase = ft.Text("SYSTEM READY", font_family="Hacker", color="#33FF33", size=12, weight="bold")
    lbl_reqs = ft.Text("REQ: 0 | TRAFFIC: 0 pps", font_family="Hacker", color=COLOR_TEXT_DIM, size=11)
    lbl_time = ft.Text("T+: 00:00", font_family="Hacker", color=COLOR_TEXT_DIM, size=11)
    
    chart_data = [ft.LineChartDataPoint(0, 0)]
    traffic_chart = ft.LineChart(
        data_series=[
            ft.LineChartData(
                data_points=chart_data,
                stroke_width=2,
                color=COLOR_SEV_CRITICAL,
                curved=True,
                stroke_cap_round=True,
                below_line_bgcolor="#33FF7B72",
            )
        ],
        border=ft.border.all(1, "#333"),
        left_axis=ft.ChartAxis(labels_size=0),
        bottom_axis=ft.ChartAxis(labels_size=0),
        tooltip_bgcolor=COLOR_BG_PANEL,
        min_y=0,
        max_y=100, 
        expand=True,
        height=80
    )

    # --- UI COMPONENTS ---
    terminal_list = ft.ListView(expand=True, spacing=2, padding=15, auto_scroll=True)
    
    dashboard_header = ft.Container(
        padding=10,
        bgcolor="#0a0a0a",
        border=ft.border.only(bottom=ft.BorderSide(1, COLOR_BORDER)),
        content=ft.Column([
            ft.Row([lbl_phase, ft.Container(expand=True), lbl_time], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Container(height=5),
            cyber_bar,
            ft.Container(height=5),
            lbl_reqs,
        ])
    )

    terminal_header = ft.Container(
        padding=ft.padding.symmetric(horizontal=15, vertical=5),
        bgcolor=COLOR_BG_PANEL,
        border=ft.border.only(bottom=ft.BorderSide(1, COLOR_BORDER), top=ft.BorderSide(1, COLOR_BORDER)),
        content=ft.Row([
            ft.Icon(ft.Icons.TERMINAL, size=14, color=COLOR_SEV_INFO),
            ft.Text("EXECUTION LOGS", size=11, weight="bold", color=COLOR_TEXT_MAIN, font_family="Hacker"),
            ft.Container(expand=True),
            ft.Text("root@lockon:~#", size=11, color=COLOR_TEXT_DIM, font_family="Hacker")
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)
    )
    
    right_panel = ft.Container(
        expand=1, bgcolor=COLOR_TERM_BG, border=ft.border.only(left=ft.BorderSide(1, COLOR_BORDER)),
        content=ft.Column([terminal_header, terminal_list, dashboard_header], spacing=0)
    )

    # Logging Logic
    def log(message):
        clean_msg, color_hex = sanitize_log_message(message)
        timestamp = datetime.now().strftime("%H:%M:%S")
        row = ft.Container(content=ft.Row([ft.Text(f"[{timestamp}]", font_family="Hacker", size=11, color=COLOR_TEXT_DIM), ft.Text(clean_msg, font_family="Hacker", size=11, color=color_hex, selectable=True)], spacing=10, vertical_alignment=ft.CrossAxisAlignment.START), padding=ft.padding.only(bottom=2))
        terminal_list.controls.append(row)
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
                title=ft.Text("⚡ CRITICAL VULNERABILITY DETECTED", weight="bold", color=COLOR_SEV_CRITICAL, font_family="Hacker"),
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
        except: 
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
             except: pass

    # 2. Mission Tab
    def on_scan_finish():
        nonlocal scan_in_progress
        scan_in_progress = False
        mission_tab.update_scan_state(False)
        log("Mission execution completed.")
        page.update()
    
    def start_scan_click(e):
        nonlocal scan_in_progress, current_scanner, alert_active
        target = mission_tab.url_input.value
        stealth_mode = mission_tab.stealth_toggle.value # [NEW]
        
        if scan_in_progress:
            if current_scanner:
                log("🛑 ABORT COMMAND RECEIVED.")
                current_scanner.stop()
                mission_tab.btn_start.content.controls[1].value = "STOPPING..."
                page.update()
            return

        if not target: return
        scan_in_progress = True
        
        # Reset UI
        findings_tab.clear()
        terminal_list.controls.clear()
        alert_active = False
        c2_manager.output_buffer = "--- C2 READY: WAITING FOR CONNECTION ---\n"
        
        mission_tab.update_scan_state(True)
        if stealth_mode: log(f"🥷 STEALTH MODE ACTIVE: Jitter & WAF Evasion Enabled.")
        log(f"Initializing Lockon Protocol on {target}")
        
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
            "recon": mission_tab.chk_recon.value # [NEW]
        }
        
        current_scanner = ScannerThread(
            target, 
            mission_tab.scan_profile.value, 
            log, 
            add_finding_wrapper, 
            on_scan_finish, 
            mission_tab.scan_cookies.value,
            stealth_mode=stealth_mode,
            modules_config=modules_config # [NEW]
        )
        current_scanner.start()
        page.update()

    mission_tab = MissionTab(start_scan_click)
    
    # 3. History Tab
    # 4. C2 Operations & Graph
    graph_tab = GraphTab(page) # [NEW]
    phantom_tab = PhantomTab(page) # [NEW] Protocol Phantom
    
    # 5. System Tab
    bin_path = os.path.join(os.getcwd(), "bin")
    system_tab = SystemTab(page, bin_path, log)

    # --- TAB CHANGE HANDLER --- (PHASE 50)
    def on_tab_change(e):
        # Index 1 = Kill Chain / Attack Graph
        if e.control.selected_index == 1:
            try: graph_tab.auto_refresh()
            except: pass

    # --- LAYOUT --
    tabs = ft.Tabs(selected_index=0, animation_duration=300, on_change=on_tab_change, tabs=[
        ft.Tab(text="MISSION", icon=ft.Icons.RADAR, content=mission_tab.get_content()),
        ft.Tab(text="KILL CHAIN", icon=ft.Icons.POLYLINE, content=graph_tab.get_content()), # [NEW]
        ft.Tab(text="PHANTOM", icon=ft.Icons.BUG_REPORT, content=phantom_tab.content), # [NEW] Protocol Phantom
        ft.Tab(text="FINDINGS", icon=ft.Icons.SECURITY_UPDATE_WARNING, content=findings_tab.get_content()),
        ft.Tab(text="SYSTEM", icon=ft.Icons.MEMORY, content=system_tab.get_content()),
    ], expand=True, divider_color=COLOR_BORDER, indicator_color=COLOR_ACCENT, label_color="white", unselected_label_color=COLOR_TEXT_DIM, overlay_color=ft.Colors.TRANSPARENT)
    
    # --- LAYOUT LOGIC ---
    def on_main_split_pan(e: ft.DragUpdateEvent):
        new_width = left_panel.width + e.delta_x
        if 400 <= new_width <= 1200:
            left_panel.width = new_width
            left_panel.update()

    left_panel = ft.Container(width=900, bgcolor=COLOR_BG_APP, content=tabs) # Fixed width initially

    main_splitter = ft.GestureDetector(
        content=ft.Container(
            width=5, 
            bgcolor=COLOR_BORDER,
            content=ft.Icon(ft.Icons.DRAG_HANDLE, size=16, color=COLOR_TEXT_DIM, rotate=1.57), # Rotated for vertical look
            alignment=ft.alignment.center
        ),
        on_pan_update=on_main_split_pan,
        mouse_cursor=ft.MouseCursor.RESIZE_COLUMN
    )

    page.add(ft.Row([
        left_panel, 
        main_splitter, 
        right_panel
    ], expand=True, spacing=0))
    
    # --- STATS LOOP ---
    def update_stats_ui(stats):
        cyber_bar.value = stats['progress']
        if stats['progress'] > 0.8: cyber_bar.color = "#00ff41" 
        elif stats['progress'] > 0.4: cyber_bar.color = "#ffbd2e" 
        else: cyber_bar.color = "#00b4d8" 
        
        lbl_phase.value = f"STATUS: {stats['phase'].upper()}"
        lbl_reqs.value = f"REQ: {stats['requests']} | TRAFFIC: {stats['pps']} pps"
        
        mins, secs = divmod(stats['duration'], 60)
        lbl_time.value = f"T+: {int(mins):02}:{int(secs):02}"
        
        lbl_phase.update()
        lbl_reqs.update()
        lbl_time.update()
        cyber_bar.update()

    def stats_loop():
        while True:
            try:
                if scan_in_progress and current_scanner:
                    stats = current_scanner.get_stats()
                    update_stats_ui(stats)
                time.sleep(1)
            except: 
                time.sleep(1)
    
    threading.Thread(target=stats_loop, daemon=True).start()
