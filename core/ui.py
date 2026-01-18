import customtkinter as ctk
import threading
from datetime import datetime
from tkinter import messagebox
import webbrowser

from core.scanner import ScannerThread
from core.database import get_scan_history

class LockonApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Grid Configuration ---
        self.grid_columnconfigure(1, weight=1)  # Main Content ขยายได้
        self.grid_columnconfigure(2, weight=0)  # Terminal คงที่ (หรือขยายนิดหน่อย)
        self.grid_rowconfigure(0, weight=1)

        # --- 1. LEFT SIDEBAR (Menu) ---
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="LOCKON\nSUITE", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.btn_dashboard = ctk.CTkButton(self.sidebar_frame, text="Dashboard", command=self.show_dashboard)
        self.btn_dashboard.grid(row=1, column=0, padx=20, pady=10)
        
        self.btn_history = ctk.CTkButton(self.sidebar_frame, text="History", command=self.show_history)
        self.btn_history.grid(row=2, column=0, padx=20, pady=10)

        # Status Bar ด้านล่างซ้าย
        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="Status: Ready", text_color="gray")
        self.status_label.grid(row=5, column=0, padx=20, pady=20)

        # --- 2. MAIN CONTENT (Center) ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=10)
        self.main_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        self.main_frame.grid_rowconfigure(2, weight=1) # ให้ตารางขยาย
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Target Input Area
        self.input_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        self.url_entry = ctk.CTkEntry(self.input_frame, placeholder_text="https://target.com", height=40, font=("Consolas", 14))
        self.url_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.scan_profile = ctk.CTkOptionMenu(self.input_frame, values=["Quick Scan", "Full Scan", "SQLi Only", "XSS Only"])
        self.scan_profile.pack(side="left", padx=(0, 10))

        self.btn_scan = ctk.CTkButton(self.input_frame, text="START ATTACK", fg_color="#b30000", hover_color="#800000", command=self.start_scan)
        self.btn_scan.pack(side="left")

        # Findings Label
        self.lbl_findings = ctk.CTkLabel(self.main_frame, text="VULNERABILITY REPORT", font=ctk.CTkFont(size=16, weight="bold"))
        self.lbl_findings.grid(row=1, column=0, sticky="w", padx=20, pady=(10, 0))

        # Findings Scrollable List (แทนตาราง)
        self.findings_frame = ctk.CTkScrollableFrame(self.main_frame, label_text="Findings List")
        self.findings_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

        # --- 3. RIGHT TERMINAL (Logs) ---
        self.terminal_frame = ctk.CTkFrame(self, width=300, corner_radius=0)
        self.terminal_frame.grid(row=0, column=2, sticky="nsew")
        self.terminal_frame.grid_rowconfigure(1, weight=1)

        self.lbl_term = ctk.CTkLabel(self.terminal_frame, text=">_ LIVE TERMINAL", font=("Consolas", 14, "bold"), text_color="#00ff00")
        self.lbl_term.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        self.terminal_text = ctk.CTkTextbox(self.terminal_frame, font=("Consolas", 12), text_color="#00ff00", fg_color="black")
        self.terminal_text.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.terminal_text.configure(state="disabled") # Read-only

        # Variables
        self.is_scanning = False
        self.scanner_thread = None

    def log(self, message):
        """ ฟังก์ชันสำหรับเพิ่มข้อความลงใน Terminal """
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}\n"
        
        self.terminal_text.configure(state="normal")
        self.terminal_text.insert("end", formatted_msg)
        self.terminal_text.see("end") # Auto scroll
        self.terminal_text.configure(state="disabled")

    def add_finding(self, finding):
        """ เพิ่มผลลัพธ์ลงในตาราง Findings """
        # สร้าง Card เล็กๆ สำหรับแต่ละ Finding
        card = ctk.CTkFrame(self.findings_frame, fg_color="#2b2b2b")
        card.pack(fill="x", padx=5, pady=5)
        
        severity_color = "#00ff00" # Low (Green)
        if finding['severity'] == 'High': severity_color = "#ff3333" # Red
        elif finding['severity'] == 'Medium': severity_color = "#ffaa00" # Orange
        
        ctk.CTkLabel(card, text=f"[{finding['severity']}]", text_color=severity_color, width=60).pack(side="left", padx=10)
        ctk.CTkLabel(card, text=finding['type'], font=("Arial", 14, "bold")).pack(side="left", padx=10)
        ctk.CTkLabel(card, text=finding['detail']).pack(side="left", padx=10, fill="x", expand=True)
        
        # ปุ่มดูรายละเอียดเพิ่มเติม (Mockup)
        # ctk.CTkButton(card, text="Details", width=60, height=24).pack(side="right", padx=10)

    def start_scan(self):
        if self.is_scanning:
            messagebox.showwarning("Busy", "Scanning is already in progress!")
            return

        target = self.url_entry.get()
        if not target.startswith("http"):
            messagebox.showerror("Error", "Invalid URL! Please include http:// or https://")
            return

        # UI Update
        self.is_scanning = True
        self.btn_scan.configure(text="SCANNING...", state="disabled", fg_color="gray")
        self.status_label.configure(text="Status: Scanning...", text_color="#ffaa00")
        self.log(f"🚀 Initializing scan on: {target}")
        
        # Clear Findings
        for widget in self.findings_frame.winfo_children():
            widget.destroy()

        # Start Thread
        self.scanner_thread = ScannerThread(
            target=target,
            profile=self.scan_profile.get(),
            log_callback=self.log,
            finding_callback=self.add_finding,
            finish_callback=self.on_scan_finished
        )
        self.scanner_thread.start()

    def on_scan_finished(self):
        self.is_scanning = False
        self.btn_scan.configure(text="START ATTACK", state="normal", fg_color="#b30000")
        self.status_label.configure(text="Status: Ready", text_color="gray")
        self.log("🏁 Scan process finished.")
        messagebox.showinfo("Complete", "Vulnerability Scan Completed!")

    def show_dashboard(self):
        # Logic สลับหน้า (ยังไม่จำเป็นต้องทำใน MVP นี้เพราะหน้าเดียวจบ)
        pass

    def show_history(self):
        # เปิดหน้าต่าง History (Popup)
        pass