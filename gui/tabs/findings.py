import flet as ft
import os
import sys
import json
import csv
import io
from datetime import datetime
from gui.theme import *

class FindingsTab:
    def __init__(self, page: ft.Page, log_callback, on_exploit_click):
        self.page = page
        self.log_callback = log_callback
        self.on_exploit_click = on_exploit_click
        
        self.findings_data = []
        self.category_tiles = {}
        self.special_cards = {}
        self.target_url = "Target Scan"
        self.dedup_map = {}  # key=(type,detail) -> count
        self.severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        self.scan_start_time = None
        
        # --- Summary Card Components ---
        self.lbl_risk_score = ft.Text("0.0", size=28, weight="bold", color=COLOR_SEV_LOW, font_family="Consolas")
        self.lbl_risk_label = ft.Text("LOW RISK", size=11, weight="bold", color=COLOR_SEV_LOW, font_family="Consolas")
        self.lbl_total = ft.Text("0", size=20, weight="bold", color="white", font_family="Consolas")
        self.lbl_target_url = ft.Text("—", size=11, color=COLOR_TEXT_DIM, font_family="Consolas", max_lines=1, overflow=ft.TextOverflow.ELLIPSIS)
        self.lbl_scan_meta = ft.Text("", size=10, color=COLOR_TEXT_DIM, font_family="Consolas")
        
        self.sev_badge_crit = self._make_sev_counter("C", "0", COLOR_SEV_CRITICAL)
        self.sev_badge_high = self._make_sev_counter("H", "0", COLOR_SEV_HIGH)
        self.sev_badge_med = self._make_sev_counter("M", "0", COLOR_SEV_MEDIUM)
        self.sev_badge_low = self._make_sev_counter("L", "0", COLOR_SEV_LOW)
        self.sev_badge_info = self._make_sev_counter("I", "0", COLOR_SEV_INFO)
        
        self.summary_card = ft.Container(
            padding=15,
            bgcolor=COLOR_BG_PANEL,
            border_radius=8,
            border=ft.border.all(1, COLOR_BORDER),
            visible=False,  # Hidden until scan starts
            content=ft.Row([
                # Left: Risk Score
                ft.Container(
                    width=80,
                    content=ft.Column([
                        self.lbl_risk_score,
                        self.lbl_risk_label,
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=2),
                ),
                ft.VerticalDivider(width=1, color=COLOR_BORDER),
                # Center: Severity Breakdown
                ft.Column([
                    ft.Row([self.lbl_total, ft.Text("FINDINGS", size=10, color=COLOR_TEXT_DIM, font_family="Consolas")], spacing=5),
                    ft.Row([
                        self.sev_badge_crit,
                        self.sev_badge_high,
                        self.sev_badge_med,
                        self.sev_badge_low,
                        self.sev_badge_info,
                    ], spacing=4),
                ], spacing=8, expand=True),
                # Right: Target
                ft.Column([
                    self.lbl_target_url,
                    self.lbl_scan_meta,
                ], horizontal_alignment=ft.CrossAxisAlignment.END, spacing=2),
            ], vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=15)
        )
        
        # --- Empty State ---
        self.empty_state = ft.Container(
            padding=60,
            content=ft.Column([
                ft.Icon(ft.Icons.SHIELD_OUTLINED, size=56, color=COLOR_TEXT_DIM),
                ft.Text("No vulnerabilities found yet", size=16, color=COLOR_TEXT_DIM, weight="bold"),
                ft.Text("Start a scan from the MISSION tab to see results here.", size=12, color=COLOR_TEXT_DIM),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=10),
            alignment=ft.alignment.center,
        )
        
        self.findings_scroll = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True, controls=[self.empty_state])
        self.findings_container = ft.Container(
            content=self.findings_scroll, 
            expand=True, 
            bgcolor=COLOR_SURFACE, 
            border_radius=6, 
            padding=10
        )
        
        # --- Severity Filter Bar ---
        self.active_filter = "ALL"
        self.filter_buttons = {}
        filter_defs = [
            ("ALL", COLOR_ACCENT_PRIMARY),
            ("CRIT", COLOR_SEV_CRITICAL),
            ("HIGH", COLOR_SEV_HIGH), 
            ("MED", COLOR_SEV_MEDIUM),
            ("LOW", COLOR_SEV_LOW),
            ("INFO", COLOR_SEV_INFO),
        ]
        for label, color in filter_defs:
            btn = ft.Container(
                content=ft.Text(label, size=10, weight="bold", color="white" if label == "ALL" else COLOR_TEXT_DIM, font_family="Consolas"),
                bgcolor=color if label == "ALL" else "transparent",
                border=ft.border.all(1, color),
                border_radius=4,
                padding=ft.padding.symmetric(horizontal=8, vertical=4),
                on_click=lambda e, l=label, c=color: self._on_severity_filter(l, c),
                ink=True,
            )
            self.filter_buttons[label] = btn
        
        self.filter_bar = ft.Row(
            [self.filter_buttons[k] for k in self.filter_buttons],
            spacing=4, visible=False,
        )
        
        # --- Collapse/Expand All ---
        self.all_expanded = True
        self.btn_toggle_all = ft.IconButton(
            icon=ft.Icons.UNFOLD_LESS,
            icon_color=COLOR_TEXT_DIM,
            icon_size=18,
            tooltip="Collapse All",
            on_click=self._toggle_all_tiles,
            visible=False,
        )
    
    def _make_sev_counter(self, label, value, color):
        return ft.Container(
            padding=ft.padding.symmetric(horizontal=6, vertical=3),
            bgcolor=ft.Colors.with_opacity(0.15, color),
            border=ft.border.all(1, ft.Colors.with_opacity(0.3, color)),
            border_radius=4,
            content=ft.Row([
                ft.Container(width=6, height=6, border_radius=3, bgcolor=color),
                ft.Text(label, size=9, color=color, weight="bold"),
                ft.Text(value, size=11, color="white", weight="bold", key=f"sev_{label}"),
            ], spacing=4),
        )
        
    def get_content(self):
        self.export_dropdown = ft.PopupMenuButton(
            icon=ft.Icons.SAVE_ALT,
            icon_color=COLOR_TEXT_DIM,
            tooltip="Export Report",
            visible=False,
            items=[
                ft.PopupMenuItem(text="Export HTML Report", icon=ft.Icons.DESCRIPTION, on_click=lambda e: self.export_html()),
                ft.PopupMenuItem(text="Export PDF Report", icon=ft.Icons.PICTURE_AS_PDF, on_click=lambda e: self.export_pdf()),
                ft.PopupMenuItem(text="Export JSON", icon=ft.Icons.DATA_OBJECT, on_click=lambda e: self.export_json()),
                ft.PopupMenuItem(text="Export CSV", icon=ft.Icons.TABLE_CHART, on_click=lambda e: self.export_csv()),
            ]
        )
        return ft.Container(padding=25, bgcolor=COLOR_SURFACE, border_radius=8, content=ft.Column([
            ft.Row([
                ft.Icon(ft.Icons.BUG_REPORT, color=COLOR_ACCENT_PRIMARY), 
                ft.Text("VULNERABILITY REPORT", size=14, weight="bold", color="white", font_family="Consolas"), 
                ft.Container(expand=True),
                self.filter_bar,
                self.btn_toggle_all,
                self.export_dropdown
            ], vertical_alignment=ft.CrossAxisAlignment.CENTER),
            ft.Divider(color=COLOR_BORDER_SUBTLE),
            self.summary_card,
            self.findings_container
        ]))

    def clear(self):
        self.findings_scroll.controls.clear()
        self.findings_scroll.controls.append(self.empty_state)
        self.empty_state.visible = True
        self.category_tiles.clear()
        self.findings_data.clear()
        self.special_cards.clear()
        self.dedup_map.clear()
        self.severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        self.summary_card.visible = False
        self.scan_start_time = None
        self.export_dropdown.visible = False
        self.filter_bar.visible = False
        self.btn_toggle_all.visible = False
        self.active_filter = "ALL"
        self._update_summary()

    def _ensure_reports_dir(self):
        reports_dir = "reports"
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
        return reports_dir

    def export_html(self):
        if not self.findings_data: return
        try:
            from core.reporter import generate_html_report
            path = generate_html_report(self.target_url, self.findings_data)
            self.log_callback(f"\U0001f4c4 HTML Report exported: {path}")
            if sys.platform == 'win32': os.startfile(os.path.dirname(path))
            # Toast notification
            try:
                self.page.snack_bar = ft.SnackBar(
                    ft.Row([
                        ft.Icon(ft.Icons.CHECK_CIRCLE, color="white", size=18),
                        ft.Text(f"Report exported: {os.path.basename(path)}", color="white", weight="bold")
                    ]), bgcolor="#2e7d32", duration=4000
                )
                self.page.snack_bar.open = True
                self.page.update()
            except Exception: pass
        except Exception as ex:
            self.log_callback(f"Report Error: {ex}")
            try:
                self.page.snack_bar = ft.SnackBar(
                    ft.Row([
                        ft.Icon(ft.Icons.ERROR, color="white", size=18),
                        ft.Text(f"Export failed: {ex}", color="white")
                    ]), bgcolor=COLOR_SEV_CRITICAL, duration=4000
                )
                self.page.snack_bar.open = True
                self.page.update()
            except Exception: pass

    def export_json(self):
        if not self.findings_data: return
        try:
            reports_dir = self._ensure_reports_dir()
            filename = f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            path = os.path.join(reports_dir, filename)
            export_data = {
                "target": self.target_url,
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(self.findings_data),
                "findings": self.findings_data
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
            self.log_callback(f"📄 JSON exported: {path}")
            if sys.platform == 'win32': os.startfile(os.path.dirname(path))
        except Exception as ex:
            self.log_callback(f"JSON Export Error: {ex}")

    def export_csv(self):
        if not self.findings_data: return
        try:
            reports_dir = self._ensure_reports_dir()
            filename = f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            path = os.path.join(reports_dir, filename)
            fields = ['type', 'severity', 'category', 'detail', 'evidence', 'remediation', 'exploit_type']
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
                writer.writeheader()
                for finding in self.findings_data:
                    row = {k: str(finding.get(k, '')) for k in fields}
                    writer.writerow(row)
            self.log_callback(f"📄 CSV exported: {path}")
            if sys.platform == 'win32': os.startfile(os.path.dirname(path))
        except Exception as ex:
            self.log_callback(f"CSV Export Error: {ex}")
    def export_pdf(self):
        if not self.findings_data: return
        try:
            from core.pdf_reporter import generate_pdf_report
            path = generate_pdf_report(self.target_url, self.findings_data)
            ext = os.path.splitext(path)[1].upper().lstrip('.')
            self.log_callback(f"\U0001f4c4 {ext} Report exported: {path}")
            if sys.platform == 'win32': os.startfile(os.path.dirname(path))
            try:
                msg = f"Report exported: {os.path.basename(path)}"
                if ext == 'HTML':
                    msg += " (PDF libraries not found — use 'pip install weasyprint' for native PDF)"
                self.page.snack_bar = ft.SnackBar(
                    ft.Row([
                        ft.Icon(ft.Icons.CHECK_CIRCLE, color="white", size=18),
                        ft.Text(msg, color="white", weight="bold")
                    ]), bgcolor="#2e7d32", duration=5000
                )
                self.page.snack_bar.open = True
                self.page.update()
            except Exception: pass
        except Exception as ex:
            self.log_callback(f"PDF Export Error: {ex}")

    # Legacy compatibility alias
    def save_report_click(self, e):
        self.export_html()

    def get_category_tile(self, category):
        if category not in self.category_tiles:
            content_col = ft.Column(spacing=5)
            
            # Severity badges for this category
            cat_sev_badges = ft.Row([
                ft.Container(
                    content=ft.Text("C:0", size=9, color="white", weight="bold"),
                    bgcolor=COLOR_BG_INPUT,
                    padding=ft.padding.symmetric(horizontal=5, vertical=2),
                    border_radius=3,
                    key="badge_c"
                ),
                ft.Container(
                    content=ft.Text("H:0", size=9, color="white", weight="bold"),
                    bgcolor=COLOR_BG_INPUT,
                    padding=ft.padding.symmetric(horizontal=5, vertical=2),
                    border_radius=3,
                    key="badge_h"
                ),
                ft.Container(
                    content=ft.Text("M:0", size=9, color="white", weight="bold"),
                    bgcolor=COLOR_BG_INPUT,
                    padding=ft.padding.symmetric(horizontal=5, vertical=2),
                    border_radius=3,
                    key="badge_m"
                ),
            ], spacing=4)
            
            tile = ft.ExpansionTile(
                title=ft.Text(f"{category}", weight="bold", font_family="Consolas", color="white", no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS),
                subtitle=ft.Column([
                    ft.Text("0 issues found", size=11, color=COLOR_TEXT_DIM),
                    cat_sev_badges,
                ], spacing=4),
                leading=ft.Icon(ft.Icons.FOLDER_SPECIAL, color=COLOR_ACCENT_PRIMARY),
                controls=[ft.Container(padding=ft.padding.only(left=20, top=5, bottom=10), content=content_col)],
                bgcolor=COLOR_BG_PANEL,
                collapsed_bgcolor=COLOR_BG_PANEL,
                shape=ft.RoundedRectangleBorder(radius=6),
                collapsed_shape=ft.RoundedRectangleBorder(radius=6),
                initially_expanded=self.category_tiles.get(category, {}).get("is_expanded", True),
                on_change=lambda e, cat=category: self.update_tile_state(cat, e.data == "true")
            )
            self.findings_scroll.controls.append(tile)
            self.category_tiles[category] = {
                "tile": tile, "count": 0, "controls": content_col.controls,
                "severe_count": 0, "is_expanded": True,
                "sev_badges": cat_sev_badges,
                "cat_sevs": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            }
        return self.category_tiles[category]

    def update_tile_state(self, category, is_expanded):
        if category in self.category_tiles:
            self.category_tiles[category]["is_expanded"] = is_expanded

    def show_finding_details(self, finding):
        # Copied from main.py show_finding_details
        evidence_text = str(finding.get('evidence', 'No evidence provided.'))
        sev = finding.get('severity', 'Info')
        sev_color = COLOR_SEV_INFO
        if sev == 'Critical': sev_color = COLOR_SEV_CRITICAL
        elif sev == 'High': sev_color = COLOR_SEV_HIGH
        elif sev == 'Medium': sev_color = COLOR_SEV_MEDIUM
        elif sev == 'Low': sev_color = COLOR_SEV_LOW
        
        # Build CVSS/CWE/OWASP badge row
        cvss_score = finding.get('cvss_score', 0)
        cvss_vector = finding.get('cvss_vector', '')
        cwe_id = finding.get('cwe', '')
        owasp_ref = finding.get('owasp', '')
        
        cvss_color = COLOR_SEV_LOW
        if cvss_score >= 9.0: cvss_color = COLOR_SEV_CRITICAL
        elif cvss_score >= 7.0: cvss_color = COLOR_SEV_HIGH
        elif cvss_score >= 4.0: cvss_color = COLOR_SEV_MEDIUM
        
        # Standards badges row
        standards_badges = []
        standards_badges.append(ft.Container(
            content=ft.Text(f"CVSS {cvss_score}", size=11, weight="bold", color="black"),
            bgcolor=cvss_color, padding=ft.padding.symmetric(horizontal=6, vertical=3), border_radius=4
        ))
        if cwe_id:
            standards_badges.append(ft.Container(
                content=ft.Text(cwe_id, size=10, weight="bold", color="white"),
                bgcolor="#333", padding=ft.padding.symmetric(horizontal=6, vertical=3), border_radius=4,
                border=ft.border.all(1, "#555")
            ))
        if owasp_ref:
            standards_badges.append(ft.Container(
                content=ft.Text(owasp_ref, size=10, weight="bold", color="#2196f3"),
                bgcolor="#0d1b2a", padding=ft.padding.symmetric(horizontal=6, vertical=3), border_radius=4,
                border=ft.border.all(1, "#2196f3")
            ))
        if cvss_vector:
            standards_badges.append(ft.Text(cvss_vector, size=9, color=COLOR_TEXT_DIM, selectable=True))

        # Build remediation section
        remediation_guide = finding.get('remediation_guide', {})
        fix_steps = remediation_guide.get('fix_steps', []) if isinstance(remediation_guide, dict) else []
        code_example = remediation_guide.get('code_example', '') if isinstance(remediation_guide, dict) else ''
        references = remediation_guide.get('references', []) if isinstance(remediation_guide, dict) else []
        risk_desc = remediation_guide.get('risk', '') if isinstance(remediation_guide, dict) else ''
        
        remediation_content = []
        if risk_desc:
            remediation_content.append(ft.Text(f"Risk: {risk_desc}", size=12, color=COLOR_SEV_HIGH, italic=True))
        if fix_steps:
            remediation_content.append(ft.Text("FIX STEPS:", size=11, weight="bold", color=COLOR_SEV_INFO))
            for i, step in enumerate(fix_steps, 1):
                remediation_content.append(ft.Text(f"  {i}. {step}", size=12, color="white"))
        if code_example:
            remediation_content.append(ft.Container(height=5))
            remediation_content.append(ft.Text("CODE EXAMPLE:", size=11, weight="bold", color=COLOR_SEV_INFO))
            remediation_content.append(ft.Container(
                padding=8, bgcolor="#000", border_radius=4, border=ft.border.all(1, "#333"),
                content=ft.Text(code_example, font_family="Consolas", size=11, color="#33FF33", selectable=True)
            ))
        if references:
            remediation_content.append(ft.Text("REFERENCES:", size=11, weight="bold", color=COLOR_SEV_INFO))
            for ref in references:
                remediation_content.append(ft.Text(f"  → {ref}", size=11, color="#2196f3", selectable=True))

        dlg = ft.AlertDialog(
            title=ft.Row([
                ft.Icon(ft.Icons.BUG_REPORT, color=sev_color),
                ft.Text(finding.get('type'), weight="bold", font_family="Consolas", color="white", size=18, expand=True),
                ft.Container(
                    content=ft.Text(sev.upper(), color="black", weight="bold", size=10),
                    bgcolor=sev_color, padding=5, border_radius=4
                )
            ]),
            content=ft.Container(
                width=850,
                height=600,
                content=ft.Column([
                    # Standards badges
                    ft.Row(standards_badges, spacing=8, wrap=True),
                    ft.Divider(color=COLOR_BORDER),
                    ft.Text("VULNERABILITY DETAILS", size=12, weight="bold", color=COLOR_TEXT_DIM, font_family="Consolas"),
                    ft.Container(
                        padding=10, 
                        bgcolor=COLOR_BG_INPUT, 
                        border_radius=6,
                        content=ft.Text(finding.get('detail'), size=14, color=COLOR_TEXT_MAIN)
                    ),
                    ft.Divider(color=COLOR_BORDER),
                    ft.Row([
                        ft.Text("TECHNICAL EVIDENCE", size=12, weight="bold", color=COLOR_TEXT_DIM, font_family="Consolas"),
                        ft.IconButton(ft.Icons.COPY, icon_size=14, tooltip="Copy Evidence", on_click=lambda e: self.page.set_clipboard(evidence_text))
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ft.Container(
                        expand=True,
                        bgcolor="#000000",
                        border=ft.border.all(1, COLOR_BORDER),
                        border_radius=4,
                        padding=15,
                        content=ft.Column([
                            ft.Text(evidence_text, font_family="Consolas", size=13, color="#33FF33", selectable=True)
                        ], scroll=ft.ScrollMode.AUTO)
                    ),
                    ft.Container(height=5),
                    ft.Container(
                        padding=10,
                        bgcolor="black",
                        border_radius=6,
                        border=ft.border.all(1, COLOR_SEV_INFO),
                        content=ft.Column([
                            ft.Row([ft.Icon(ft.Icons.BUILD, color=COLOR_SEV_INFO, size=16), ft.Text("HOW TO FIX", weight="bold", color=COLOR_SEV_INFO, size=12)]),
                            *remediation_content
                        ] if remediation_content else [
                            ft.Row([ft.Icon(ft.Icons.SHIELD, color=COLOR_SEV_INFO, size=16), ft.Text("REMEDIATION", weight="bold", color=COLOR_SEV_INFO, size=12)]),
                            ft.Text(finding.get('remediation', 'No remediation available.'), italic=True, color="white", size=13)
                        ], scroll=ft.ScrollMode.AUTO, spacing=4)
                    )
                ], spacing=8)
            ),
            actions=[
                ft.TextButton("CLOSE", on_click=lambda e: self.page.close(dlg), style=ft.ButtonStyle(color=COLOR_TEXT_DIM))
            ],
            bgcolor=COLOR_BG_PANEL,
            shape=ft.RoundedRectangleBorder(radius=8)
        )
        self.page.open(dlg)

    def _on_severity_filter(self, label, color):
        """Filter category tiles by severity."""
        self.active_filter = label
        sev_map = {"CRIT": "Critical", "HIGH": "High", "MED": "Medium", "LOW": "Low", "INFO": "Info"}
        
        # Update button styles
        for btn_label, btn in self.filter_buttons.items():
            if btn_label == label:
                btn.bgcolor = color
                btn.content.color = "white"
            else:
                btn.bgcolor = "transparent"
                btn.content.color = COLOR_TEXT_DIM
        
        # Filter category tiles
        if label == "ALL":
            for cat_data in self.category_tiles.values():
                cat_data["tile"].visible = True
        else:
            target_sev = sev_map.get(label, "Info")
            for cat_data in self.category_tiles.values():
                has_sev = cat_data["cat_sevs"].get(target_sev, 0) > 0
                cat_data["tile"].visible = has_sev
        
        try: self.page.update()
        except Exception: pass

    def _toggle_all_tiles(self, e=None):
        """Collapse or expand all category tiles."""
        self.all_expanded = not self.all_expanded
        for cat_data in self.category_tiles.values():
            tile = cat_data["tile"]
            # We can't programmatically toggle ExpansionTile easily,
            # but we can set initially_expanded for future tiles
            cat_data["is_expanded"] = self.all_expanded
        
        if self.all_expanded:
            self.btn_toggle_all.icon = ft.Icons.UNFOLD_LESS
            self.btn_toggle_all.tooltip = "Collapse All"
        else:
            self.btn_toggle_all.icon = ft.Icons.UNFOLD_MORE
            self.btn_toggle_all.tooltip = "Expand All"
        
        try: self.page.update()
        except Exception: pass

    def _update_summary(self):
        """Refresh the summary card with current counts."""
        total = len(self.findings_data)
        self.lbl_total.value = str(total)
        self.lbl_target_url.value = f"\U0001f3af {self.target_url}"
        
        # Update severity counters
        for badge, key in [(self.sev_badge_crit, "Critical"), (self.sev_badge_high, "High"),
                           (self.sev_badge_med, "Medium"), (self.sev_badge_low, "Low"),
                           (self.sev_badge_info, "Info")]:
            badge.content.controls[2].value = str(self.severity_counts[key])
        
        # Risk score (weighted: C=10, H=5, M=2, L=0.5, I=0)
        raw_score = (self.severity_counts["Critical"] * 10 +
                     self.severity_counts["High"] * 5 +
                     self.severity_counts["Medium"] * 2 +
                     self.severity_counts["Low"] * 0.5)
        risk = min(10.0, raw_score / max(total, 1) if total > 0 else 0)
        # Adjust: scale up if many criticals
        if self.severity_counts["Critical"] > 0:
            risk = min(10.0, risk + self.severity_counts["Critical"] * 0.5)
        
        self.lbl_risk_score.value = f"{risk:.1f}"
        if risk >= 7:
            self.lbl_risk_label.value = "CRITICAL"
            self.lbl_risk_score.color = COLOR_SEV_CRITICAL
            self.lbl_risk_label.color = COLOR_SEV_CRITICAL
        elif risk >= 4:
            self.lbl_risk_label.value = "HIGH RISK"
            self.lbl_risk_score.color = COLOR_SEV_HIGH
            self.lbl_risk_label.color = COLOR_SEV_HIGH
        elif risk >= 2:
            self.lbl_risk_label.value = "MEDIUM"
            self.lbl_risk_score.color = COLOR_SEV_MEDIUM
            self.lbl_risk_label.color = COLOR_SEV_MEDIUM
        else:
            self.lbl_risk_label.value = "LOW RISK"
            self.lbl_risk_score.color = COLOR_SEV_LOW
            self.lbl_risk_label.color = COLOR_SEV_LOW

    def add_finding(self, finding):
        self.findings_data.append(finding)
        
        # Hide empty state, show summary
        if self.empty_state.visible:
            self.empty_state.visible = False
        if not self.summary_card.visible:
            self.summary_card.visible = True
            self.export_dropdown.visible = True
            self.filter_bar.visible = True
            self.btn_toggle_all.visible = True
            import time as _time
            self.scan_start_time = _time.time()
        severity = finding.get('severity', 'Info')
        category = finding.get('category', 'Uncategorized')
        f_type = finding.get('type')
        detail = finding.get('detail', '')
        
        # [DEDUPLICATION] Group identical findings by (type, detail)
        dedup_key = (f_type, detail)
        if dedup_key in self.dedup_map:
            self.dedup_map[dedup_key]['count'] += 1
            count = self.dedup_map[dedup_key]['count']
            badge = self.dedup_map[dedup_key]['badge']
            badge.value = f"×{count}"
            badge.visible = True
            try: self.page.update()
            except Exception: pass
            return
        
        # [AGGREGATION LOGIC]
        if f_type in ["Open Port", "Subdomain Found"]:
            if f_type in self.special_cards:
                ui_data = self.special_cards[f_type]
                val = finding.get('detail', '').replace('Port ', '').replace(' is open', '')
                if f_type == "Subdomain Found": val = finding.get('evidence', '')
                
                if val not in ui_data['items']:
                    ui_data['items'].append(val)
                    count = len(ui_data['items'])
                    ui_data['count_widget'].value = f"{count} Items Found"
                    ui_data['list_widget'].controls.append(ft.Text(f"• {val}", font_family="Consolas", size=11, color="#33FF33"))
                    self.page.update()
                return

        border_col = COLOR_SEV_INFO
        if severity == 'Critical': border_col = COLOR_SEV_CRITICAL
        elif severity == 'High': border_col = COLOR_SEV_HIGH
        elif severity == 'Medium': border_col = COLOR_SEV_MEDIUM
        elif severity == 'Low': border_col = COLOR_SEV_LOW

        evidence_preview = str(finding.get('evidence', ''))
        if len(evidence_preview) > 100: evidence_preview = evidence_preview[:100] + "..."

        action_button = ft.Container()
        has_exploit = False
        if finding.get('exploit_type'):
            has_exploit = True
            self.log_callback(f"⚡ Exploit Available for: {finding.get('type')}") 
            
            action_button = ft.ElevatedButton(
                "⚡ C2", 
                bgcolor=COLOR_SEV_CRITICAL, 
                color="white", 
                icon=ft.Icons.TERMINAL, 
                style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=4), padding=5), 
                height=25,
                width=90,
                content=ft.Row([ft.Icon(ft.Icons.TERMINAL, size=12), ft.Text("PWN", size=10)], alignment=ft.MainAxisAlignment.CENTER),
                on_click=lambda e, f=finding: self.on_exploit_click(e, f)
            )

        # [SPECIAL CARD CREATION]
        content_body = ft.Column([
            ft.Text(finding.get('detail'), size=11, color=COLOR_TEXT_DIM, max_lines=2, overflow=ft.TextOverflow.ELLIPSIS),
            ft.Container(
                margin=ft.margin.only(top=5), 
                padding=8, 
                bgcolor="#0d1117", 
                border_radius=4, 
                border=ft.border.all(1, "#3d4450"), 
                content=ft.Text(f"> {evidence_preview}", font_family="Consolas", size=10, color="#8b949e")
            )
        ])
        
        if f_type in ["Open Port", "Subdomain Found"]:
             # Initialize aggregation UI
             val = finding.get('detail', '').replace('Port ', '').replace(' is open', '')
             if f_type == "Subdomain Found": val = finding.get('evidence', '')
             
             count_label = ft.Text("1 Items Found", size=11, color=COLOR_SEV_INFO, weight="bold")
             item_list = ft.Column([ft.Text(f"• {val}", font_family="Consolas", size=11, color="#33FF33")], spacing=2)
             
             content_body = ft.Column([
                 count_label,
                 ft.Container(
                    margin=ft.margin.only(top=5), 
                    padding=8, 
                    bgcolor="black", 
                    border_radius=4, 
                    border=ft.border.all(1, "#30363d"), 
                    content=item_list
                )
             ])
             self.special_cards[f_type] = {'count_widget': count_label, 'list_widget': item_list, 'items': [val]}

        # [DEDUP] Count badge for duplicate findings
        dedup_badge = ft.Text("", size=11, weight="bold", color=border_col, visible=False)

        card = ft.Container(
            padding=12, 
            bgcolor="#13161c", 
            border_radius=6, 
            border=ft.border.only(left=ft.BorderSide(3, border_col)), 
            content=ft.Column([
                ft.Row([
                    ft.Container(
                        content=ft.Text(severity[:3].upper(), size=9, weight="bold", color="black"), 
                        bgcolor=border_col, 
                        padding=ft.padding.symmetric(horizontal=4, vertical=2), 
                        border_radius=3
                    ), 
                    ft.Text(finding.get('type'), weight="bold", size=13, color="white", font_family="Consolas", expand=True, no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS), 
                    # CVSS score badge (color based on CVSS score, not severity)
                    ft.Container(
                        content=ft.Text(f"{finding.get('cvss_score', 0)}", size=10, weight="bold", color="black"),
                        bgcolor=(
                            COLOR_SEV_CRITICAL if finding.get('cvss_score', 0) >= 9.0 else
                            COLOR_SEV_HIGH if finding.get('cvss_score', 0) >= 7.0 else
                            COLOR_SEV_MEDIUM if finding.get('cvss_score', 0) >= 4.0 else
                            COLOR_SEV_LOW
                        ),
                        padding=ft.padding.symmetric(horizontal=5, vertical=2), border_radius=3,
                        tooltip=finding.get('cvss_vector', ''),
                    ) if finding.get('cvss_score') else ft.Container(),
                    # CWE badge
                    ft.Text(finding.get('cwe', ''), size=9, color=COLOR_TEXT_DIM) if finding.get('cwe') else ft.Container(),
                    dedup_badge,
                    action_button, 
                    ft.IconButton(ft.Icons.OPEN_IN_NEW, icon_color=COLOR_TEXT_DIM, tooltip="View Details", icon_size=18, on_click=lambda e, f=finding: self.show_finding_details(f))
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                content_body
            ])
        )
        
        # Register for deduplication
        self.dedup_map[dedup_key] = {'count': 1, 'badge': dedup_badge}
        
        cat_data = self.get_category_tile(category)
        cat_data["controls"].insert(0, card)
        cat_data["count"] += 1
        if severity in ["Critical", "High"]:
             cat_data["severe_count"] += 1
        
        # Track per-category severity
        sev_key = severity if severity in cat_data["cat_sevs"] else "Info"
        cat_data["cat_sevs"][sev_key] += 1
        
        # Track global severity
        self.severity_counts[sev_key] = self.severity_counts.get(sev_key, 0) + 1
             
        # Update Tile Style + Severity Badges
        cat_data["tile"].title.value = f"{category} ({cat_data['count']})"
        cat_data["tile"].subtitle.controls[0].value = f"{cat_data['severe_count']} Critical/High Issues"
        
        # Update per-category severity badges
        badges = cat_data["sev_badges"].controls
        c_count = cat_data["cat_sevs"]["Critical"]
        h_count = cat_data["cat_sevs"]["High"]
        m_count = cat_data["cat_sevs"]["Medium"]
        badges[0].content.value = f"C:{c_count}"
        badges[0].bgcolor = COLOR_SEV_CRITICAL if c_count > 0 else COLOR_BG_INPUT
        badges[1].content.value = f"H:{h_count}"
        badges[1].bgcolor = COLOR_SEV_HIGH if h_count > 0 else COLOR_BG_INPUT
        badges[2].content.value = f"M:{m_count}"
        badges[2].bgcolor = COLOR_SEV_MEDIUM if m_count > 0 else COLOR_BG_INPUT
        
        if cat_data["severe_count"] > 0:
            cat_data["tile"].leading.color = COLOR_SEV_CRITICAL
            cat_data["tile"].title.color = COLOR_SEV_CRITICAL
        elif cat_data["count"] > 0:
            cat_data["tile"].leading.color = COLOR_SEV_MEDIUM
        
        # Update global summary
        self._update_summary()
        
        self.page.update()
