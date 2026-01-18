import flet as ft
from core.database import get_scan_history
from gui.theme import *

class HistoryTab:
    def __init__(self, page: ft.Page):
        self.page = page
        self.history_list = ft.ListView(expand=True, spacing=10, padding=10)
        
    def get_content(self):
        return ft.Container(
            padding=10,
            content=ft.Column([
                ft.Row([
                    ft.Text("SCAN HISTORY", size=16, weight="bold", font_family="Hacker", color="white"),
                    ft.IconButton(ft.Icons.REFRESH, icon_color=COLOR_ACCENT, on_click=self.load_history_click, tooltip="Refresh History")
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Divider(color=COLOR_BORDER),
                self.history_list
            ])
        )

    def load_history_click(self, e):
        self.history_list.controls.clear()
        scans = get_scan_history()
        if not scans:
             self.history_list.controls.append(ft.Container(content=ft.Text("No scan history found.", color=COLOR_TEXT_DIM), alignment=ft.alignment.center))
        
        for s in scans:
            timestamp = s['timestamp']
            target = s['target']
            total = s['total_findings']
            crit = s['critical_count']
            high = s['high_count']
            
            # Color Status
            status_col = COLOR_SEV_INFO
            if crit > 0: status_col = COLOR_SEV_CRITICAL
            elif high > 0: status_col = COLOR_SEV_HIGH
            
            self.history_list.controls.append(
                ft.Container(
                    padding=10,
                    bgcolor=COLOR_BG_PANEL,
                    border=ft.border.only(left=ft.BorderSide(4, status_col)),
                    border_radius=5,
                    content=ft.Row([
                        ft.Column([
                            ft.Text(target, weight="bold", size=14, color="white", font_family="Hacker"),
                            ft.Text(f"Date: {timestamp} | Profile: {s['profile']}", size=11, color=COLOR_TEXT_DIM)
                        ], expand=True),
                        ft.Row([
                            ft.Container(bgcolor=COLOR_SEV_CRITICAL, padding=5, border_radius=3, content=ft.Text(f"{crit}", size=10, color="black", weight="bold"), tooltip="Critical"),
                            ft.Container(bgcolor=COLOR_SEV_HIGH, padding=5, border_radius=3, content=ft.Text(f"{high}", size=10, color="black", weight="bold"), tooltip="High"),
                            ft.Container(bgcolor=COLOR_SEV_MEDIUM, padding=5, border_radius=3, content=ft.Text(f"{s['medium_count']}", size=10, color="black", weight="bold"), tooltip="Medium"),
                            ft.Container(bgcolor=COLOR_SEV_INFO, padding=5, border_radius=3, content=ft.Text(f"{total} Total", size=10, color="black", weight="bold"), tooltip="Total Findings"),
                        ]),
                    ])
                )
            )
        self.page.update()
