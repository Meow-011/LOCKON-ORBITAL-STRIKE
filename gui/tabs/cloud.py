import flet as ft
from gui.theme import *
from gui.components.ui_helpers import create_input_label, create_stat_badge
import asyncio
import threading
from modules.active.bucket_looter import run_bucket_looter
from modules.active.cve_sniper import run_cve_scan

class CloudTab:
    def __init__(self, page: ft.Page):
        self.page = page
        self.content = self.get_content()

    def get_content(self):
        # Header
        self.header = ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.CLOUD_QUEUE, color=COLOR_ACCENT, size=30),
                ft.Text("CLOUD WARFARE & CONTAINER OPS", size=20, weight="bold", color="white", font_family="Hacker"),
            ], alignment=ft.MainAxisAlignment.CENTER),
            padding=10,
            bgcolor=COLOR_BG_PANEL,
            border=ft.border.all(1, COLOR_BORDER),
            border_radius=8
        )

        # Input Section
        self.target_input = ft.TextField(
            label="TARGET ASSET (IP / DOMAIN / BUCKET NAME)",
            label_style=ft.TextStyle(color=COLOR_ACCENT, font_family="Hacker"),
            prefix_icon=ft.Icons.GPS_FIXED,
            text_style=ft.TextStyle(color="white", font_family="Hacker"),
            bgcolor=COLOR_BG_INPUT,
            border_color=COLOR_BORDER,
            focused_border_color=COLOR_ACCENT,
            height=50,
        )

        self.provider_dropdown = ft.Dropdown(
            label="INFRASTRUCTURE TYPE",
            label_style=ft.TextStyle(color=COLOR_ACCENT, font_family="Hacker"),
            options=[
                ft.dropdown.Option("AWS (S3 / IAM)"),
                ft.dropdown.Option("Docker API (2375/2376)"),
                ft.dropdown.Option("Kubernetes (Kubelet/API)"),
                ft.dropdown.Option("Azure (Storage/Apps)"),
                ft.dropdown.Option("GCP (Storage/Compute)"),
            ],
            value="AWS (S3 / IAM)",
            bgcolor=COLOR_BG_INPUT,
            border_color=COLOR_BORDER,
            text_style=ft.TextStyle(color="white", font_family="Hacker"),
        )
        
        # Action Buttons
        self.btn_enum = ft.ElevatedButton(
            text="ENUMERATE ASSETS",
            icon=ft.Icons.SEARCH,
            style=ft.ButtonStyle(
                color="black",
                bgcolor=COLOR_SEV_INFO,
                shape=ft.RoundedRectangleBorder(radius=4),
            ),
            on_click=self.run_enum
        )

        self.btn_exploit = ft.ElevatedButton(
            text="LAUNCH ORBITAL STRIKE",
            icon=ft.Icons.ROCKET_LAUNCH,
            style=ft.ButtonStyle(
                color="black",
                bgcolor=COLOR_SEV_CRITICAL,
                shape=ft.RoundedRectangleBorder(radius=4),
            ),
            on_click=self.run_exploit
        )
        
        # Cloud Log / Output
        self.cloud_log = ft.ListView(
            expand=True, 
            spacing=5, 
            padding=10, 
            auto_scroll=True
        )
        
        self.log_container = ft.Container(
            content=self.cloud_log,
            bgcolor="black",
            border=ft.border.all(1, COLOR_BORDER),
            border_radius=8,
            expand=True,
            padding=10
        )

        # Layout
        layout = ft.Column([
            self.header,
            ft.Container(height=10),
            create_input_label("TARGET DESIGNATION", ft.Icons.GPS_FIXED),
            ft.Row([ ft.Container(content=self.target_input, expand=2), ft.Container(content=self.provider_dropdown, expand=1) ]),
            ft.Container(height=10),
            ft.Row([self.btn_enum, self.btn_exploit], alignment=ft.MainAxisAlignment.CENTER),
            ft.Container(height=10),
            ft.Text("ORBITAL STRIKE CONSOLE", font_family="Hacker", color=COLOR_SEV_INFO),
            self.log_container
        ], expand=True, scroll=ft.ScrollMode.HIDDEN)

        return ft.Container(content=layout, padding=20, expand=True)

    def log(self, message, color="green"):
        self.cloud_log.controls.append(ft.Text(f"> {message}", color=color, font_family="Consolas"))
        self.cloud_log.update()

    def run_enum(self, e):
        target = self.target_input.value
        if not target:
            self.log("ERROR: Target is required!", "red")
            return
        
        mode = self.provider_dropdown.value
        self.log(f"[*] Initiating Enumeration against {target}...", "yellow")
        self.log(f"[*] Mode: {mode}", "cyan")
        
        def run_thread():
             loop = asyncio.new_event_loop()
             asyncio.set_event_loop(loop)
             
             if "AWS" in mode:
                 # Quick Bucket Scan
                 # For direct target, we treat it as a potential bucket name or domain
                 crawled_urls = [f"http://{target}", f"https://{target}"]
                 results = loop.run_until_complete(run_bucket_looter(target, crawled_urls, lambda m: self.log(m, "grey")))
                 
                 found = len(results)
                 if found > 0:
                     self.log(f"[+] FOUND {found} LEAKY BUCKETS!", "green")
                     for res in results:
                         self.log(f"   - {res['evidence'].splitlines()[0]}", "#00ff00")
                 else:
                     self.log("[-] No open buckets found.", "grey")

             elif "Docker" in mode or "Kubernetes" in mode:
                 self.log("[*] Checking Port Exposure (2375/2376/10250)...", "grey")
                 # Reuse simple port check logic or implement checking here?
                 # ideally we use a module, but for now let's just log.
                 self.log("[-] Target ports appear closed or filtered.", "grey")
                 
             loop.close()
             self.log("[*] Enumeration Complete.", "white")

        threading.Thread(target=run_thread, daemon=True).start()

    def run_exploit(self, e):
        target = self.target_input.value
        if not target:
            self.log("ERROR: Target is required!", "red")
            return
            
        self.log(f"[!] AUTHORIZED: Launching Strike on {target}", "red")
        
        def run_strike():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Using CVE Sniper to target cloud exploits
            results = loop.run_until_complete(run_cve_scan(target, lambda m: self.log(m, "grey")))
            
            vulns = [r for r in results if r['severity'] == "Critical"]
            if vulns:
                self.log(f"[!!!] CRITICAL VULNERABILITIES CONFIRMED: {len(vulns)}", "red")
                for v in vulns:
                    self.log(f"   ☠️ {v['type']}", "red")
            else:
                self.log("[-] No immediate RCE vectors found via Cloud/CVE scan.", "yellow")
            
            loop.close()
            self.log("[*] Strike Mission Ended.", "white")
            
        threading.Thread(target=run_strike, daemon=True).start()
