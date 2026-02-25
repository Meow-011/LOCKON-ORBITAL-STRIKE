import flet as ft
from gui.theme import *
from core.database import get_scan_history, get_scan_findings, delete_scan

class HistoryTab:
    def __init__(self, page: ft.Page):
        self.page = page
        self.loaded = False
        
        self.history_list = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True, spacing=5)
        self.detail_panel = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True, spacing=5, visible=False)
        self.back_btn = ft.TextButton("← Back to History", on_click=lambda e: self.show_list_view(), visible=False)
        
        # Compare mode
        self.compare_mode = False
        self.compare_selections = []  # list of scan_ids
        self.btn_compare_toggle = ft.IconButton(
            icon=ft.Icons.COMPARE_ARROWS,
            icon_color=COLOR_TEXT_DIM,
            icon_size=18,
            tooltip="Compare two scans",
            on_click=self._toggle_compare_mode
        )
        self.btn_run_compare = ft.ElevatedButton(
            "Compare Selected",
            icon=ft.Icons.DIFFERENCE,
            visible=False,
            disabled=True,
            on_click=self._run_compare,
            style=ft.ButtonStyle(bgcolor=COLOR_ACCENT_PRIMARY, color="black", shape=ft.RoundedRectangleBorder(radius=4))
        )
        self.compare_status = ft.Text("", size=10, color=COLOR_TEXT_DIM, visible=False)
        
        self.main_view = ft.Column([
            self.back_btn,
            self.history_list,
            self.detail_panel
        ], expand=True)

    def get_content(self):
        return ft.Container(
            padding=20,
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.HISTORY, color=COLOR_ACCENT_PRIMARY),
                    ft.Text("SCAN HISTORY", size=14, weight="bold", color="white", font_family="Consolas"),
                    ft.Container(expand=True),
                    self.compare_status,
                    self.btn_run_compare,
                    self.btn_compare_toggle,
                    ft.IconButton(ft.Icons.REFRESH, icon_color=COLOR_TEXT_DIM, tooltip="Refresh", on_click=lambda e: self.load_history())
                ]),
                ft.Divider(color=COLOR_BORDER_SUBTLE),
                self.main_view
            ], expand=True)
        )

    def _calc_risk_score(self, crit, high, med, low, total):
        """Calculate risk score consistent with findings tab."""
        if total == 0: return 0.0, "LOW", COLOR_SEV_LOW
        raw = (crit * 10 + high * 5 + med * 2 + low * 0.5)
        risk = min(10.0, raw / max(total, 1))
        if crit > 0:
            risk = min(10.0, risk + crit * 0.5)
        if risk >= 7:
            return risk, "CRITICAL", COLOR_SEV_CRITICAL
        elif risk >= 4:
            return risk, "HIGH", COLOR_SEV_HIGH
        elif risk >= 2:
            return risk, "MEDIUM", COLOR_SEV_MEDIUM
        else:
            return risk, "LOW", COLOR_SEV_LOW

    def _delete_scan(self, scan_id):
        """Delete a scan with confirmation dialog."""
        def do_delete(e):
            self.page.close(dlg)
            try:
                delete_scan(scan_id)
                self.load_history()
            except Exception as ex:
                pass
        
        dlg = ft.AlertDialog(
            title=ft.Text("Delete Scan?", font_family="Consolas", weight="bold"),
            content=ft.Text("This scan and all its findings will be permanently deleted.", color=COLOR_TEXT_DIM),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(dlg)),
                ft.ElevatedButton("Delete", bgcolor=COLOR_SEV_CRITICAL, color="white", on_click=do_delete),
            ],
            bgcolor=COLOR_BG_PANEL,
        )
        self.page.open(dlg)

    def load_history(self):
        self.history_list.controls.clear()
        self.show_list_view()
        
        # Show loading skeleton
        for _ in range(3):
            skeleton = ft.Container(
                padding=12,
                bgcolor=COLOR_BG_PANEL,
                border_radius=6,
                border=ft.border.only(left=ft.BorderSide(3, COLOR_BORDER_SUBTLE)),
                animate_opacity=ft.Animation(800, "easeInOut"),
                opacity=0.5,
                content=ft.Row([
                    ft.Column([
                        ft.Container(width=200, height=14, bgcolor=COLOR_BORDER_SUBTLE, border_radius=3),
                        ft.Container(width=300, height=10, bgcolor=COLOR_BG_INPUT, border_radius=3),
                    ], spacing=8, expand=True),
                    ft.Column([
                        ft.Container(width=80, height=14, bgcolor=COLOR_BORDER_SUBTLE, border_radius=3),
                        ft.Container(width=60, height=10, bgcolor=COLOR_BG_INPUT, border_radius=3),
                    ], spacing=8, horizontal_alignment=ft.CrossAxisAlignment.END),
                ])
            )
            self.history_list.controls.append(skeleton)
        self.page.update()
        
        try:
            history = get_scan_history()
            self.history_list.controls.clear()
            
            if not history:
                self.history_list.controls.append(
                    ft.Container(
                        padding=40,
                        content=ft.Column([
                            ft.Icon(ft.Icons.INBOX, size=48, color=COLOR_TEXT_DIM),
                            ft.Text("No scan history found", size=14, color=COLOR_TEXT_DIM, text_align=ft.TextAlign.CENTER),
                            ft.Text("Completed scans will appear here.", size=11, color=COLOR_TEXT_DIM),
                        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=5),
                        alignment=ft.alignment.center
                    )
                )
            else:
                for row in history:
                    scan_id = row['id']
                    target = row['target']
                    timestamp = row['timestamp']
                    profile = row['profile']
                    total = row['total_findings']
                    crit = row['critical_count']
                    high = row['high_count']
                    med = row.get('medium_count', 0)
                    low = row.get('low_count', 0)
                    
                    sev_color = COLOR_SEV_LOW
                    if crit > 0: sev_color = COLOR_SEV_CRITICAL
                    elif high > 0: sev_color = COLOR_SEV_HIGH
                    
                    # Risk score
                    risk_val, risk_label, risk_color = self._calc_risk_score(crit, high, med, low, total)
                    
                    card = ft.Container(
                        padding=12,
                        bgcolor=COLOR_BG_PANEL,
                        border_radius=6,
                        border=ft.border.only(left=ft.BorderSide(3, sev_color)),
                        ink=True,
                        on_click=lambda e, sid=scan_id, tgt=target: self.show_scan_detail(sid, tgt),
                        content=ft.Row([
                            ft.Column([
                                ft.Text(target, size=13, weight="bold", color="white", font_family="Consolas"),
                                ft.Text(f"{timestamp} | Profile: {profile}", size=11, color=COLOR_TEXT_DIM)
                            ], expand=True, spacing=3),
                            # Risk Score badge
                            ft.Container(
                                content=ft.Column([
                                    ft.Text(f"{risk_val:.1f}", size=14, weight="bold", color=risk_color, font_family="Consolas"),
                                    ft.Text(risk_label, size=8, color=risk_color, weight="bold"),
                                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=0),
                                width=55,
                            ),
                            ft.Column([
                                ft.Text(f"{total} findings", size=12, color="white", weight="bold"),
                                ft.Row([
                                    ft.Container(
                                        content=ft.Text(f"C:{crit}", size=9, color="white", weight="bold"),
                                        bgcolor=COLOR_SEV_CRITICAL if crit > 0 else COLOR_BG_INPUT,
                                        padding=ft.padding.symmetric(horizontal=5, vertical=2),
                                        border_radius=3
                                    ),
                                    ft.Container(
                                        content=ft.Text(f"H:{high}", size=9, color="white", weight="bold"),
                                        bgcolor=COLOR_SEV_HIGH if high > 0 else COLOR_BG_INPUT,
                                        padding=ft.padding.symmetric(horizontal=5, vertical=2),
                                        border_radius=3
                                    ),
                                ], spacing=4)
                            ], horizontal_alignment=ft.CrossAxisAlignment.END, spacing=3),
                            # Delete button
                            ft.IconButton(
                                icon=ft.Icons.DELETE_OUTLINE,
                                icon_color=COLOR_TEXT_DIM,
                                icon_size=16,
                                tooltip="Delete scan",
                                on_click=lambda e, sid=scan_id: self._delete_scan(sid),
                            ),
                        ], vertical_alignment=ft.CrossAxisAlignment.CENTER)
                    )
                    self.history_list.controls.append(card)
        except Exception as ex:
            self.history_list.controls.append(
                ft.Text(f"Error loading history: {ex}", color=COLOR_SEV_CRITICAL)
            )
        
        self.loaded = True
        self.page.update()

    def _toggle_compare_mode(self, e=None):
        """Toggle compare mode on/off."""
        self.compare_mode = not self.compare_mode
        self.compare_selections.clear()
        if self.compare_mode:
            self.btn_compare_toggle.icon_color = COLOR_ACCENT_PRIMARY
            self.compare_status.value = "Select 2 scans to compare"
            self.compare_status.visible = True
            self.btn_run_compare.visible = True
            self.btn_run_compare.disabled = True
        else:
            self.btn_compare_toggle.icon_color = COLOR_TEXT_DIM
            self.compare_status.visible = False
            self.btn_run_compare.visible = False
        self.load_history()  # Reload to add/remove checkboxes
    
    def _on_compare_check(self, scan_id, checked):
        """Handle checkbox toggle in compare mode."""
        if checked and scan_id not in self.compare_selections:
            if len(self.compare_selections) >= 2:
                # Remove oldest selection
                self.compare_selections.pop(0)
            self.compare_selections.append(scan_id)
        elif not checked and scan_id in self.compare_selections:
            self.compare_selections.remove(scan_id)
        
        count = len(self.compare_selections)
        self.btn_run_compare.disabled = count != 2
        self.compare_status.value = f"Selected: {count}/2"
        try: self.page.update()
        except: pass
    
    def _run_compare(self, e=None):
        """Run comparison on selected scans."""
        if len(self.compare_selections) != 2:
            return
        
        try:
            from core.scan_diff import compare_scans, generate_diff_report
            
            diff = compare_scans(self.compare_selections[0], self.compare_selections[1])
            
            if diff.get('error'):
                self.compare_status.value = f"Error: {diff['error']}"
                self.page.update()
                return
            
            stats = diff.get('stats', {})
            s1 = diff.get('scan_1_info', {})
            s2 = diff.get('scan_2_info', {})
            
            sev_colors = {"Critical": COLOR_SEV_CRITICAL, "High": COLOR_SEV_HIGH, "Medium": COLOR_SEV_MEDIUM, "Low": COLOR_SEV_LOW, "Info": COLOR_SEV_INFO}
            
            def _make_diff_items(items, icon, color):
                rows = []
                for item in items[:20]:  # Limit display
                    sev = item.get('severity', 'Info')
                    sc = sev_colors.get(sev, COLOR_SEV_INFO)
                    rows.append(ft.Row([
                        ft.Icon(icon, size=14, color=color),
                        ft.Text(item.get('type', ''), size=11, color="white", font_family="Consolas", expand=True),
                        ft.Container(
                            content=ft.Text(sev, size=9, color="white", weight="bold"),
                            bgcolor=sc, padding=ft.padding.symmetric(horizontal=5, vertical=2), border_radius=3
                        )
                    ], spacing=5))
                if len(items) > 20:
                    rows.append(ft.Text(f"... and {len(items) - 20} more", size=10, color=COLOR_TEXT_DIM))
                return rows
            
            new_items = _make_diff_items(diff.get('new', []), ft.Icons.ADD_CIRCLE, "#f44336")
            fixed_items = _make_diff_items(diff.get('fixed', []), ft.Icons.CHECK_CIRCLE, "#4caf50")
            unchanged_items = _make_diff_items(diff.get('unchanged', []), ft.Icons.REMOVE_CIRCLE_OUTLINE, "#555")
            
            def _export_diff(e):
                path = generate_diff_report(diff)
                import os, sys
                if sys.platform == 'win32': os.startfile(os.path.dirname(path))
            
            dlg = ft.AlertDialog(
                title=ft.Row([
                    ft.Icon(ft.Icons.COMPARE_ARROWS, color=COLOR_ACCENT_PRIMARY),
                    ft.Text("SCAN COMPARISON", weight="bold", color="white", font_family="Consolas", size=16),
                ]),
                content=ft.Container(
                    width=700, height=500,
                    content=ft.Column([
                        ft.Text(f"Baseline: {s1.get('target','')} ({s1.get('timestamp','')[:10]})", size=10, color=COLOR_TEXT_DIM),
                        ft.Text(f"Current:  {s2.get('target','')} ({s2.get('timestamp','')[:10]})", size=10, color=COLOR_TEXT_DIM),
                        ft.Container(height=10),
                        # Summary cards
                        ft.Row([
                            ft.Container(content=ft.Column([
                                ft.Text(str(stats.get('new_count', 0)), size=20, weight="bold", color="#f44336"),
                                ft.Text("NEW", size=9, color="#f44336")
                            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER), bgcolor="#1a0a0a", border=ft.border.all(1, "#f44336"), border_radius=6, padding=15, expand=True),
                            ft.Container(content=ft.Column([
                                ft.Text(str(stats.get('fixed_count', 0)), size=20, weight="bold", color="#4caf50"),
                                ft.Text("FIXED", size=9, color="#4caf50")
                            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER), bgcolor="#0a1a0a", border=ft.border.all(1, "#4caf50"), border_radius=6, padding=15, expand=True),
                            ft.Container(content=ft.Column([
                                ft.Text(str(stats.get('unchanged_count', 0)), size=20, weight="bold", color="#888"),
                                ft.Text("UNCHANGED", size=9, color="#888")
                            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER), bgcolor="#111", border=ft.border.all(1, "#333"), border_radius=6, padding=15, expand=True),
                        ], spacing=10),
                        ft.Container(height=10),
                        ft.Divider(color=COLOR_BORDER_SUBTLE),
                        # Details
                        ft.Column([
                            ft.Text("\ud83d\udd34 NEW FINDINGS", size=11, weight="bold", color="#f44336", font_family="Consolas"),
                            *(new_items or [ft.Text("None", size=10, color=COLOR_TEXT_DIM)]),
                            ft.Container(height=8),
                            ft.Text("\ud83d\udfe2 FIXED", size=11, weight="bold", color="#4caf50", font_family="Consolas"),
                            *(fixed_items or [ft.Text("None", size=10, color=COLOR_TEXT_DIM)]),
                            ft.Container(height=8),
                            ft.Text("\u26aa UNCHANGED", size=11, weight="bold", color="#888", font_family="Consolas"),
                            *(unchanged_items or [ft.Text("None", size=10, color=COLOR_TEXT_DIM)]),
                        ], scroll=ft.ScrollMode.AUTO, expand=True)
                    ])
                ),
                actions=[
                    ft.TextButton("Export Diff Report", icon=ft.Icons.DOWNLOAD, on_click=_export_diff),
                    ft.TextButton("Close", on_click=lambda e: self.page.close(dlg))
                ],
                bgcolor=COLOR_SURFACE
            )
            self.page.open(dlg)
            
        except Exception as ex:
            self.compare_status.value = f"Error: {ex}"
            try: self.page.update()
            except: pass

    def show_list_view(self):
        self.history_list.visible = True
        self.detail_panel.visible = False
        self.back_btn.visible = False
        try: self.page.update()
        except Exception: pass

    def show_scan_detail(self, scan_id, target):
        self.detail_panel.controls.clear()
        self.history_list.visible = False
        self.detail_panel.visible = True
        self.back_btn.visible = True
        
        try:
            findings = get_scan_findings(scan_id)
            self.detail_panel.controls.append(
                ft.Text(f"Findings for: {target}", size=14, weight="bold", color="white", font_family="Consolas")
            )
            self.detail_panel.controls.append(ft.Divider(color=COLOR_BORDER_SUBTLE))
            
            if not findings:
                self.detail_panel.controls.append(ft.Text("No findings recorded.", color=COLOR_TEXT_DIM))
            else:
                for f in findings:
                    f_type = f['type']
                    severity = f['severity']
                    detail = f['detail']
                    border_col = COLOR_SEV_INFO
                    if severity == 'Critical': border_col = COLOR_SEV_CRITICAL
                    elif severity == 'High': border_col = COLOR_SEV_HIGH
                    elif severity == 'Medium': border_col = COLOR_SEV_MEDIUM
                    elif severity == 'Low': border_col = COLOR_SEV_LOW
                    
                    self.detail_panel.controls.append(ft.Container(
                        padding=10,
                        bgcolor="#13161c",
                        border_radius=4,
                        border=ft.border.only(left=ft.BorderSide(3, border_col)),
                        content=ft.Row([
                            ft.Container(
                                content=ft.Text(severity[:3].upper(), size=9, weight="bold", color="black"),
                                bgcolor=border_col,
                                padding=ft.padding.symmetric(horizontal=4, vertical=2),
                                border_radius=3
                            ),
                            ft.Text(f_type, weight="bold", size=12, color="white", font_family="Consolas", expand=True),
                        ])
                    ))
        except Exception as ex:
            self.detail_panel.controls.append(ft.Text(f"Error: {ex}", color=COLOR_SEV_CRITICAL))
        
        self.page.update()
