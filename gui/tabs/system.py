import flet as ft
import threading
import setup_tools
import platform
import shutil
import time
import os
from gui.theme import *

try:
    import psutil
except ImportError:
    psutil = None

class SystemTab:
    def __init__(self, page: ft.Page, bin_path, log_callback):
        self.page = page
        self.bin_path = bin_path
        self.log_callback = log_callback
        self.monitoring = True
        
        # Use centralized theme colors
        self.COLOR_SURFACE = COLOR_SURFACE
        self.COLOR_INPUT = COLOR_INPUT_FIELD
        self.COLOR_BORDER_SUBTLE = COLOR_BORDER_SUBTLE
        self.COLOR_ACCENT_PRIMARY = COLOR_ACCENT_PRIMARY
        self.COLOR_ACCENT_WARN = COLOR_ACCENT_WARN
        self.COLOR_ACCENT_CRITICAL = COLOR_ACCENT_DANGER
        
        # --- UI Components ---
        self.cpu_bar = ft.ProgressBar(value=0, color=self.COLOR_ACCENT_PRIMARY, bgcolor="#222", height=8, border_radius=4)
        self.ram_bar = ft.ProgressBar(value=0, color=self.COLOR_ACCENT_WARN, bgcolor="#222", height=8, border_radius=4)
        self.disk_bar = ft.ProgressBar(value=0, color=self.COLOR_ACCENT_CRITICAL, bgcolor="#222", height=8, border_radius=4)
        
        self.lbl_cpu = ft.Text("CPU: 0%", font_family="Consolas", color="white")
        self.lbl_ram = ft.Text("RAM: 0%", font_family="Consolas", color="white")
        self.lbl_disk = ft.Text("DISK: 0%", font_family="Consolas", color="white")
        self.lbl_sys_info = ft.Text("DETECTING...", font_family="Consolas", color=COLOR_TEXT_DIM, size=11)
        
        # Start Monitor
        threading.Thread(target=self.monitor_loop, daemon=True).start()
        
    def install_tools_click(self, e):
        self.log_callback("Verifying dependencies...")
        threading.Thread(target=lambda: setup_tools.check_dependencies(callback=self.log_callback), daemon=True).start()

    def get_sys_info(self):
        uname = platform.uname()
        return f"OS: {uname.system} {uname.release} | NODE: {uname.node} | ARCH: {uname.machine}"

    def monitor_loop(self):
        while self.monitoring:
            try:
                # CPU
                cpu = 0
                if psutil: cpu = psutil.cpu_percent(interval=None)
                
                # RAM
                ram_p = 0
                if psutil: ram_p = psutil.virtual_memory().percent
                
                # DISK
                total, used, free = shutil.disk_usage("/")
                disk_p = (used / total) * 100
                
                # Update UI
                self.cpu_bar.value = cpu / 100
                self.lbl_cpu.value = f"CPU: {cpu}%"
                
                self.ram_bar.value = ram_p / 100
                self.lbl_ram.value = f"RAM: {ram_p}%"
                
                self.disk_bar.value = disk_p / 100
                self.lbl_disk.value = f"DISK: {int(disk_p)}% ({used // (2**30)}GB / {total // (2**30)}GB)"
                
                self.lbl_sys_info.value = self.get_sys_info()
                
                self.cpu_bar.update()
                self.ram_bar.update()
                self.disk_bar.update()
                self.lbl_cpu.update()
                self.lbl_ram.update()
                self.lbl_disk.update()
                self.lbl_sys_info.update()
                
                time.sleep(2)
            except Exception:
                time.sleep(2)

    def get_content(self):
        btn_tools = ft.OutlinedButton(
            "VERIFY DEPENDENCIES", 
            icon=ft.Icons.BUILD_CIRCLE, 
            style=ft.ButtonStyle(
                color=self.COLOR_ACCENT_PRIMARY,
                side={ft.ControlState.DEFAULT: ft.BorderSide(1, self.COLOR_ACCENT_PRIMARY)},
                shape=ft.RoundedRectangleBorder(radius=4)
            ), 
            height=45, 
            on_click=self.install_tools_click
        )
        
        monitor_panel = ft.Container(
            padding=25,
            bgcolor=self.COLOR_SURFACE,
            border=ft.border.all(1, self.COLOR_BORDER_SUBTLE),
            border_radius=8,
            shadow=ft.BoxShadow(blur_radius=15, spread_radius=1, color=ft.Colors.with_opacity(0.2, "black")), 
            content=ft.Column([
                ft.Row([ft.Icon(ft.Icons.MONITOR_HEART, color=self.COLOR_ACCENT_PRIMARY), ft.Text("REAL-TIME SYSTEM MONITOR", size=14, weight="bold", color="white", font_family="Consolas")]), 
                ft.Divider(color=self.COLOR_BORDER_SUBTLE),
                ft.Container(height=10),
                
                ft.Row([ft.Icon(ft.Icons.COMPUTER, size=16, color=COLOR_TEXT_DIM), ft.Text("PROCESSOR LOAD", size=12, color=COLOR_TEXT_DIM, font_family="Consolas")]),
                self.lbl_cpu,
                self.cpu_bar,
                ft.Container(height=15),
                
                ft.Row([ft.Icon(ft.Icons.MEMORY, size=16, color=COLOR_TEXT_DIM), ft.Text("MEMORY USAGE", size=12, color=COLOR_TEXT_DIM, font_family="Consolas")]),
                self.lbl_ram,
                self.ram_bar,
                ft.Container(height=15),
                
                ft.Row([ft.Icon(ft.Icons.STORAGE, size=16, color=COLOR_TEXT_DIM), ft.Text("STORAGE CAPACITY", size=12, color=COLOR_TEXT_DIM, font_family="Consolas")]),
                self.lbl_disk,
                self.disk_bar,
                
                ft.Container(height=15),
                ft.Divider(color=self.COLOR_BORDER_SUBTLE),
                self.lbl_sys_info
            ])
        )

        config_panel = ft.Container(
            padding=25, 
            bgcolor=self.COLOR_INPUT, 
            border_radius=6, 
            border=ft.border.all(1, self.COLOR_BORDER_SUBTLE), 
            content=ft.Column([
                ft.Row([ft.Icon(ft.Icons.SETTINGS_SUGGEST, color=COLOR_TEXT_DIM), ft.Text("SYSTEM CONFIGURATION", size=12, weight="bold", color="white", font_family="Consolas")]), 
                ft.Container(height=10), 
                ft.Text("Dependency verification ensures all external tools are installed.", size=12, color=COLOR_TEXT_DIM, font_family="Consolas"),
                ft.Container(height=15), 
                btn_tools, 
                ft.Container(height=15), 
                ft.Divider(color=self.COLOR_BORDER_SUBTLE),
                ft.Text(f"BINARY PATH: {self.bin_path}", size=11, color=COLOR_TEXT_DIM, font_family="Consolas")
            ])
        )

        return ft.Container(
            padding=30, 
            content=ft.Column([
                monitor_panel,
                ft.Container(height=20),
                config_panel,
                ft.Container(expand=True),
                ft.Text("SYSTEM VISUALIZATION MODULE", size=10, color=COLOR_TEXT_DIM, text_align=ft.TextAlign.CENTER, font_family="Consolas")
            ], scroll=ft.ScrollMode.AUTO)
        )
