import flet as ft
import os
import sys
from gui.theme import *

class FindingsTab:
    def __init__(self, page: ft.Page, log_callback, on_exploit_click):
        self.page = page
        self.log_callback = log_callback
        self.on_exploit_click = on_exploit_click
        
        self.findings_data = []
        self.category_tiles = {}
        self.special_cards = {}
        
        self.findings_scroll = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True) 
        self.findings_container = ft.Container(
            content=self.findings_scroll, 
            expand=True, 
            bgcolor=COLOR_BG_INPUT, 
            border_radius=6, 
            border=ft.border.all(1, COLOR_BORDER), 
            padding=5
        )
        
    def get_content(self):
        return ft.Container(padding=20, content=ft.Column([
            ft.Row([
                ft.Icon(ft.Icons.BUG_REPORT, color=COLOR_SEV_HIGH), 
                ft.Text("VULNERABILITY REPORT", size=14, weight="bold", color="white", font_family="Hacker"), 
                ft.Container(expand=True), 
                ft.IconButton(ft.Icons.SAVE, icon_color=COLOR_TEXT_DIM, on_click=self.save_report_click)
            ]),
            ft.Divider(color=COLOR_BORDER), 
            self.findings_container
        ]))

    def clear(self):
        self.findings_scroll.controls.clear()
        self.category_tiles.clear()
        self.findings_data.clear()
        self.special_cards.clear()

    def save_report_click(self, e):
        # We need the URL. Since we don't store it here, maybe pass it? 
        # Or just generate from findings data. 
        # The original code used url_input.value. 
        # I'll just use "Target" string for now or accept it in clear/init.
        if not self.findings_data: return
        try:
            from core.reporter import generate_html_report
            # Assuming the first finding has target info or just generic
            path = generate_html_report("Target Scan", self.findings_data)
            self.log_callback(f"📄 Report exported: {path}")
            if sys.platform == 'win32': os.startfile(os.path.dirname(path))
        except Exception as ex: 
            self.log_callback(f"Report Error: {ex}")

    def get_category_tile(self, category):
        if category not in self.category_tiles:
            content_col = ft.Column(spacing=5)
            tile = ft.ExpansionTile(
                title=ft.Text(f"{category}", weight="bold", font_family="Hacker", color="white"),
                subtitle=ft.Text("0 issues found", size=11, color=COLOR_TEXT_DIM),
                leading=ft.Icon(ft.Icons.FOLDER_SPECIAL, color=COLOR_TEXT_DIM),
                controls=[ft.Container(padding=ft.padding.only(left=20, top=5, bottom=10), content=content_col)],
                bgcolor=COLOR_BG_PANEL,
                collapsed_bgcolor=COLOR_BG_PANEL,
                shape=ft.RoundedRectangleBorder(radius=6),
                collapsed_shape=ft.RoundedRectangleBorder(radius=6),
                initially_expanded=self.category_tiles.get(category, {}).get("is_expanded", True),
                on_change=lambda e, cat=category: self.update_tile_state(cat, e.data == "true")
            )
            self.findings_scroll.controls.append(tile)
            self.category_tiles[category] = {"tile": tile, "count": 0, "controls": content_col.controls, "severe_count": 0, "is_expanded": True}
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
        
        dlg = ft.AlertDialog(
            title=ft.Row([
                ft.Icon(ft.Icons.BUG_REPORT, color=sev_color),
                ft.Text(finding.get('type'), weight="bold", font_family="Hacker", color="white", size=18, expand=True),
                ft.Container(
                    content=ft.Text(sev.upper(), color="black", weight="bold", size=10),
                    bgcolor=sev_color, padding=5, border_radius=4
                )
            ]),
            content=ft.Container(
                width=850,
                height=600,
                content=ft.Column([
                    ft.Text("VULNERABILITY DETAILS", size=12, weight="bold", color=COLOR_TEXT_DIM, font_family="Hacker"),
                    ft.Container(
                        padding=10, 
                        bgcolor=COLOR_BG_INPUT, 
                        border_radius=6,
                        content=ft.Text(finding.get('detail'), size=14, color=COLOR_TEXT_MAIN)
                    ),
                    ft.Divider(color=COLOR_BORDER),
                    ft.Row([
                        ft.Text("TECHNICAL EVIDENCE", size=12, weight="bold", color=COLOR_TEXT_DIM, font_family="Hacker"),
                        ft.IconButton(ft.Icons.COPY, icon_size=14, tooltip="Copy Evidence", on_click=lambda e: self.page.set_clipboard(evidence_text))
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ft.Container(
                        expand=True,
                        bgcolor="#000000",
                        border=ft.border.all(1, COLOR_BORDER),
                        border_radius=4,
                        padding=15,
                        content=ft.Column([
                            ft.Text(evidence_text, font_family="Hacker", size=13, color="#33FF33", selectable=True)
                        ], scroll=ft.ScrollMode.AUTO)
                    ),
                    ft.Container(height=10),
                    ft.Container(
                        padding=10,
                        bgcolor="black",
                        border_radius=6,
                        border=ft.border.all(1, COLOR_SEV_INFO),
                        content=ft.Column([
                            ft.Row([ft.Icon(ft.Icons.SHIELD, color=COLOR_SEV_INFO, size=16), ft.Text("REMEDIATION STRATEGY", weight="bold", color=COLOR_SEV_INFO, size=12)]),
                            ft.Text(finding.get('remediation', 'No remediation available.'), italic=True, color="white", size=13)
                        ])
                    )
                ], spacing=10)
            ),
            actions=[
                ft.TextButton("CLOSE", on_click=lambda e: self.page.close_dialog(), style=ft.ButtonStyle(color=COLOR_TEXT_DIM))
            ],
            bgcolor=COLOR_BG_PANEL,
            shape=ft.RoundedRectangleBorder(radius=8)
        )
        self.page.dialog = dlg
        dlg.open = True
        self.page.update()

    def add_finding(self, finding):
        self.findings_data.append(finding)
        severity = finding.get('severity', 'Info')
        category = finding.get('category', 'Uncategorized')
        f_type = finding.get('type')
        
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
                    ui_data['list_widget'].controls.append(ft.Text(f"• {val}", font_family="Hacker", size=11, color="#33FF33"))
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
                on_click=lambda e: self.on_exploit_click(e, finding)
            )

        # [SPECIAL CARD CREATION]
        content_body = ft.Column([
            ft.Text(finding.get('detail'), size=11, color=COLOR_TEXT_DIM, max_lines=2, overflow=ft.TextOverflow.ELLIPSIS),
            ft.Container(
                margin=ft.margin.only(top=5), 
                padding=8, 
                bgcolor="black", 
                border_radius=4, 
                border=ft.border.all(1, "#30363d"), 
                content=ft.Text(f"> {evidence_preview}", font_family="Hacker", size=10, color=border_col)
            )
        ])
        
        if f_type in ["Open Port", "Subdomain Found"]:
             # Initialize aggregation UI
             val = finding.get('detail', '').replace('Port ', '').replace(' is open', '')
             if f_type == "Subdomain Found": val = finding.get('evidence', '')
             
             count_label = ft.Text("1 Items Found", size=11, color=COLOR_SEV_INFO, weight="bold")
             item_list = ft.Column([ft.Text(f"• {val}", font_family="Hacker", size=11, color="#33FF33")], spacing=2)
             
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
                    ft.Text(finding.get('type'), weight="bold", size=13, color="white", font_family="Hacker", expand=True, no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS), 
                    action_button, 
                    ft.IconButton(ft.Icons.OPEN_IN_NEW, icon_color=COLOR_TEXT_DIM, tooltip="View Details", icon_size=18, on_click=lambda e: self.show_finding_details(finding))
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                content_body
            ])
        )
        
        cat_data = self.get_category_tile(category)
        cat_data["controls"].insert(0, card)
        cat_data["count"] += 1
        if severity in ["Critical", "High"]:
             cat_data["severe_count"] += 1
             
        # Update Tile Style
        cat_data["tile"].title.value = f"{category} ({cat_data['count']})"
        cat_data["tile"].subtitle.value = f"{cat_data['severe_count']} Critical/High Issues"
        
        if cat_data["severe_count"] > 0:
            cat_data["tile"].icon_color = COLOR_SEV_CRITICAL
            cat_data["tile"].title.color = COLOR_SEV_CRITICAL
        elif cat_data["count"] > 0:
            cat_data["tile"].icon_color = COLOR_SEV_MEDIUM
        
        self.page.update()
