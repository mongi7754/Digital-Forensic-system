# Digital-Forensic-system
Digital Forensics System
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import os
import sys
import hashlib
import platform
import socket
import psutil
import datetime
import logging
import json
import subprocess
import webbrowser
import threading
import time
from PIL import Image, ImageTk

class DigitalForensicSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Forensic System v2.0")
        self.root.geometry("1200x800")
        self.root.configure(bg="#FFD700")  # Golden yellow background
        
        # Security features
        self.auth_required = True
        self.valid_credentials = {"admin": "Forensic$ecure123", "investigator": "Evidence#2023"}
        self.session_log = []
        self.audit_logger = self.setup_logger()
        
        # UI setup
        self.setup_ui()
        
        # System information
        self.system_info = self.get_system_info()
        
        # Start with authentication
        if self.auth_required:
            self.show_auth_screen()
        else:
            self.show_main_interface()

    def setup_logger(self):
        logger = logging.getLogger('ForensicAudit')
        logger.setLevel(logging.INFO)
        
        # Create file handler
        fh = logging.FileHandler('forensic_audit.log')
        fh.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(fh)
        
        return logger

    def log_event(self, event, level="INFO"):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {event}"
        self.session_log.append(log_entry)
        
        if level == "INFO":
            self.audit_logger.info(event)
        elif level == "WARNING":
            self.audit_logger.warning(event)
        elif level == "ERROR":
            self.audit_logger.error(event)
        elif level == "CRITICAL":
            self.audit_logger.critical(event)

    def setup_ui(self):
        # Create style for yellow theme
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure colors
        self.style.configure('.', background="#FFD700", foreground="black")
        self.style.configure('TFrame', background="#FFD700")
        self.style.configure('TLabel', background="#FFD700", foreground="#333333", font=('Arial', 10))
        self.style.configure('TButton', background="#FFA500", foreground="black", font=('Arial', 10, 'bold'))
        self.style.configure('TNotebook', background="#FFD700")
        self.style.configure('TNotebook.Tab', background="#FFA500", foreground="black", padding=[10, 5])
        self.style.map('TNotebook.Tab', background=[('selected', '#FF8C00')])
        self.style.configure('Header.TLabel', background="#FFA500", foreground="black", 
                            font=('Arial', 14, 'bold'), padding=10)
        self.style.configure('Title.TLabel', background="#FFD700", foreground="#333333", 
                            font=('Arial', 16, 'bold'), padding=10)
        self.style.configure('Status.TLabel', background="#FFA500", foreground="black", 
                            font=('Arial', 10), padding=5)

    def show_auth_screen(self):
        self.auth_frame = ttk.Frame(self.root)
        self.auth_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(self.auth_frame, text="DIGITAL FORENSIC SYSTEM", 
                 style="Title.TLabel").pack(pady=20)
        
        # Logo placeholder
        logo_frame = ttk.Frame(self.auth_frame)
        logo_frame.pack(pady=10)
        
        try:
            # Create a simple yellow shield icon using tkinter
            canvas = tk.Canvas(logo_frame, width=100, height=100, bg="#FFD700", highlightthickness=0)
            canvas.pack()
            canvas.create_oval(10, 10, 90, 90, fill="#FFA500", outline="black")
            canvas.create_text(50, 50, text="🔍", font=("Arial", 30))
        except:
            pass
        
        # Authentication form
        auth_form = ttk.Frame(self.auth_frame)
        auth_form.pack(pady=20)
        
        ttk.Label(auth_form, text="Username:").grid(row=0, column=0, padx=10, pady=10, sticky='e')
        self.username_entry = ttk.Entry(auth_form, width=25)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)
        
        ttk.Label(auth_form, text="Password:").grid(row=1, column=0, padx=10, pady=10, sticky='e')
        self.password_entry = ttk.Entry(auth_form, width=25, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)
        
        # Buttons
        btn_frame = ttk.Frame(auth_form)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Login", command=self.authenticate).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Exit", command=self.root.destroy).pack(side=tk.LEFT, padx=10)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready for authentication")
        ttk.Label(self.auth_frame, textvariable=self.status_var, style="Status.TLabel").pack(side=tk.BOTTOM, fill=tk.X)

    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            self.status_var.set("Both username and password are required")
            self.log_event("Authentication attempt with missing credentials", "WARNING")
            return
            
        if username in self.valid_credentials and password == self.valid_credentials[username]:
            self.current_user = username
            self.log_event(f"User '{username}' authenticated successfully")
            self.auth_frame.destroy()
            self.show_main_interface()
        else:
            self.status_var.set("Invalid credentials")
            self.log_event(f"Failed authentication attempt for user '{username}'", "WARNING")
            messagebox.showerror("Authentication Failed", "Invalid username or password")

    def show_main_interface(self):
        # Create main notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.data_collection_tab = ttk.Frame(self.notebook)
        self.system_access_tab = ttk.Frame(self.notebook)
        self.file_analysis_tab = ttk.Frame(self.notebook)
        self.security_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        self.notebook.add(self.data_collection_tab, text="Data Collection")
        self.notebook.add(self.system_access_tab, text="System Access")
        self.notebook.add(self.file_analysis_tab, text="File Analysis")
        self.notebook.add(self.security_tab, text="Security")
        
        # Build each tab
        self.build_dashboard()
        self.build_data_collection()
        self.build_system_access()
        self.build_file_analysis()
        self.build_security()
        
        # Add status bar
        self.status_var = tk.StringVar()
        self.status_var.set(f"Logged in as: {self.current_user} | System: {self.system_info['platform']}")
        ttk.Label(self.root, textvariable=self.status_var, style="Status.TLabel").pack(side=tk.BOTTOM, fill=tk.X)
        
        self.log_event("Main interface loaded")

    def build_dashboard(self):
        # Header
        ttk.Label(self.dashboard_tab, text="Digital Forensic Dashboard", 
                 style="Header.TLabel").pack(fill=tk.X)
        
        # System information panel
        sys_frame = ttk.LabelFrame(self.dashboard_tab, text="System Information")
        sys_frame.pack(fill=tk.X, padx=10, pady=10)
        
        sys_info = self.get_system_info()
        info_text = f"Operating System: {sys_info['platform']} {sys_info['version']}\n"
        info_text += f"Architecture: {sys_info['architecture']}\n"
        info_text += f"Processor: {sys_info['processor']}\n"
        info_text += f"Memory: {sys_info['memory']} GB\n"
        info_text += f"Hostname: {sys_info['hostname']}\n"
        info_text += f"IP Address: {sys_info['ip_address']}\n"
        info_text += f"Logged in as: {self.current_user}"
        
        ttk.Label(sys_frame, text=info_text).pack(padx=10, pady=10, anchor="w")
        
        # Quick actions
        action_frame = ttk.LabelFrame(self.dashboard_tab, text="Quick Actions")
        action_frame.pack(fill=tk.X, padx=10, pady=10)
        
        btn_frame = ttk.Frame(action_frame)
        btn_frame.pack(padx=10, pady=10)
        
        ttk.Button(btn_frame, text="Collect System Data", 
                  command=lambda: self.collect_data("system")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Scan Files", 
                  command=lambda: self.collect_data("files")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Network Analysis", 
                  command=lambda: self.collect_data("network")).pack(side=tk.LEFT, padx=5)
        
        # Recent activity
        activity_frame = ttk.LabelFrame(self.dashboard_tab, text="Recent Activity")
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.activity_log = scrolledtext.ScrolledText(activity_frame, height=8)
        self.activity_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.activity_log.insert(tk.END, "No recent activity\n")
        self.activity_log.configure(state='disabled')
        
        # Update with initial activity
        self.update_activity_log("System initialized")

    def update_activity_log(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.activity_log.configure(state='normal')
        self.activity_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.activity_log.see(tk.END)
        self.activity_log.configure(state='disabled')

    def build_data_collection(self):
        # Header
        ttk.Label(self.data_collection_tab, text="Data Collection Tools", 
                 style="Header.TLabel").pack(fill=tk.X)
        
        # Data sources frame
        sources_frame = ttk.LabelFrame(self.data_collection_tab, text="Data Sources")
        sources_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Data source buttons
        btn_frame = ttk.Frame(sources_frame)
        btn_frame.pack(padx=10, pady=10)
        
        ttk.Button(btn_frame, text="System Information", 
                  command=lambda: self.collect_data("system")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="File System", 
                  command=lambda: self.collect_data("files")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Network Data", 
                  command=lambda: self.collect_data("network")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Running Processes", 
                  command=lambda: self.collect_data("processes")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="User Accounts", 
                  command=lambda: self.collect_data("users")).pack(side=tk.LEFT, padx=5)
        
        # Data display
        data_frame = ttk.LabelFrame(self.data_collection_tab, text="Collected Data")
        data_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.data_display = scrolledtext.ScrolledText(data_frame, height=20)
        self.data_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.data_display.insert(tk.END, "No data collected yet. Select a data source to begin.\n")
        self.data_display.configure(state='disabled')
        
        # Export button
        ttk.Button(self.data_collection_tab, text="Export Data", 
                  command=self.export_data).pack(pady=10)

    def build_system_access(self):
        # Header
        ttk.Label(self.system_access_tab, text="System Access Tools", 
                 style="Header.TLabel").pack(fill=tk.X)
        
        # Warning label
        ttk.Label(self.system_access_tab, 
                 text="WARNING: These tools should only be used with proper authorization",
                 foreground="red", font=("Arial", 10, "bold")).pack(pady=5)
        
        # Access tools frame
        tools_frame = ttk.LabelFrame(self.system_access_tab, text="Access Tools")
        tools_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Tool selection
        tool_frame = ttk.Frame(tools_frame)
        tool_frame.pack(padx=10, pady=10)
        
        ttk.Label(tool_frame, text="Select Tool:").grid(row=0, column=0, padx=5, pady=5)
        self.access_tool = tk.StringVar(value="password_cracker")
        
        tools = [
            ("Password Cracker", "password_cracker"),
            ("System Vulnerability Scanner", "vulnerability_scanner"),
            ("Network Port Scanner", "port_scanner"),
            ("Encryption Bypass", "encryption_bypass")
        ]
        
        for i, (text, value) in enumerate(tools):
            ttk.Radiobutton(tool_frame, text=text, variable=self.access_tool, 
                           value=value).grid(row=0, column=i+1, padx=5, pady=5)
        
        # Target input
        target_frame = ttk.Frame(tools_frame)
        target_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(target_frame, text="Target:").pack(side=tk.LEFT, padx=5)
        self.target_entry = ttk.Entry(target_frame, width=50)
        self.target_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Execute button
        ttk.Button(tools_frame, text="Execute", command=self.execute_access_tool).pack(pady=10)
        
        # Results display
        results_frame = ttk.LabelFrame(self.system_access_tab, text="Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.access_results = scrolledtext.ScrolledText(results_frame, height=15)
        self.access_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.access_results.insert(tk.END, "No results yet. Execute a tool to see results.\n")
        self.access_results.configure(state='disabled')

    def build_file_analysis(self):
        # Header
        ttk.Label(self.file_analysis_tab, text="File Analysis Tools", 
                 style="Header.TLabel").pack(fill=tk.X)
        
        # File selection
        file_frame = ttk.LabelFrame(self.file_analysis_tab, text="File Selection")
        file_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(file_frame, text="File Path:").grid(row=0, column=0, padx=5, pady=5)
        self.file_path_entry = ttk.Entry(file_frame, width=60)
        self.file_path_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(file_frame, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=5)
        
        # Analysis tools
        tool_frame = ttk.Frame(file_frame)
        tool_frame.grid(row=1, column=0, columnspan=3, pady=10)
        
        ttk.Button(tool_frame, text="Hash Analysis", 
                  command=lambda: self.analyze_file("hash")).pack(side=tk.LEFT, padx=5)
        ttk.Button(tool_frame, text="Metadata Extraction", 
                  command=lambda: self.analyze_file("metadata")).pack(side=tk.LEFT, padx=5)
        ttk.Button(tool_frame, text="File Signature", 
                  command=lambda: self.analyze_file("signature")).pack(side=tk.LEFT, padx=5)
        ttk.Button(tool_frame, text="Hex View", 
                  command=lambda: self.analyze_file("hex")).pack(side=tk.LEFT, padx=5)
        
        # Analysis results
        results_frame = ttk.LabelFrame(self.file_analysis_tab, text="Analysis Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.analysis_results = scrolledtext.ScrolledText(results_frame, height=20)
        self.analysis_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.analysis_results.insert(tk.END, "No analysis performed yet.\n")
        self.analysis_results.configure(state='disabled')

    def build_security(self):
        # Header
        ttk.Label(self.security_tab, text="Security Features", 
                 style="Header.TLabel").pack(fill=tk.X)
        
        # Security tools
        tools_frame = ttk.LabelFrame(self.security_tab, text="Security Tools")
        tools_frame.pack(fill=tk.X, padx=10, pady=10)
        
        btn_frame = ttk.Frame(tools_frame)
        btn_frame.pack(padx=10, pady=10)
        
        ttk.Button(btn_frame, text="View Audit Log", 
                  command=self.view_audit_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Encrypt Data", 
                  command=self.encrypt_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Data Wipe", 
                  command=self.wipe_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Secure Erase", 
                  command=self.secure_erase).pack(side=tk.LEFT, padx=5)
        
        # User management
        user_frame = ttk.LabelFrame(self.security_tab, text="User Management")
        user_frame.pack(fill=tk.X, padx=10, pady=10)
        
        user_form = ttk.Frame(user_frame)
        user_form.pack(padx=10, pady=10, fill=tk.X)
        
        ttk.Label(user_form, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.new_user_entry = ttk.Entry(user_form, width=20)
        self.new_user_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(user_form, text="Password:").grid(row=0, column=2, padx=5, pady=5)
        self.new_pass_entry = ttk.Entry(user_form, width=20, show="*")
        self.new_pass_entry.grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Button(user_form, text="Add User", command=self.add_user).grid(row=0, column=4, padx=5)
        
        # Security status
        status_frame = ttk.LabelFrame(self.security_tab, text="Security Status")
        status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        status_text = "Security Status: ACTIVE\n"
        status_text += f"Authentication: {'ENABLED' if self.auth_required else 'DISABLED'}\n"
        status_text += f"Audit Logging: ENABLED\n"
        status_text += f"Last Activity: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        ttk.Label(status_frame, text=status_text).pack(padx=10, pady=10, anchor="w")
        
        # Logout button
        ttk.Button(self.security_tab, text="Logout", command=self.logout).pack(pady=10)

    def get_system_info(self):
        info = {
            "platform": platform.system(),
            "version": platform.version(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "memory": round(psutil.virtual_memory().total / (1024 ** 3), 2),
            "hostname": socket.gethostname(),
            "ip_address": socket.gethostbyname(socket.gethostname())
        }
        return info

    def collect_data(self, data_type):
        self.update_activity_log(f"Collecting {data_type} data")
        self.data_display.configure(state='normal')
        self.data_display.delete(1.0, tk.END)
        
        if data_type == "system":
            self.data_display.insert(tk.END, "=== SYSTEM INFORMATION ===\n\n")
            for key, value in self.system_info.items():
                self.data_display.insert(tk.END, f"{key.replace('_', ' ').title()}: {value}\n")
        
        elif data_type == "files":
            self.data_display.insert(tk.END, "=== FILE SYSTEM ANALYSIS ===\n\n")
            partitions = psutil.disk_partitions()
            for partition in partitions:
                self.data_display.insert(tk.END, f"Device: {partition.device}\n")
                self.data_display.insert(tk.END, f"  Mountpoint: {partition.mountpoint}\n")
                self.data_display.insert(tk.END, f"  File System: {partition.fstype}\n")
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    self.data_display.insert(tk.END, f"  Total: {usage.total // (1024**3)} GB, ")
                    self.data_display.insert(tk.END, f"Used: {usage.used // (1024**3)} GB, ")
                    self.data_display.insert(tk.END, f"Free: {usage.free // (1024**3)} GB\n\n")
                except:
                    self.data_display.insert(tk.END, "  Usage information unavailable\n\n")
        
        elif data_type == "network":
            self.data_display.insert(tk.END, "=== NETWORK INFORMATION ===\n\n")
            interfaces = psutil.net_if_addrs()
            for interface, addrs in interfaces.items():
                self.data_display.insert(tk.END, f"Interface: {interface}\n")
                for addr in addrs:
                    self.data_display.insert(tk.END, f"  {addr.family.name}: {addr.address}\n")
                self.data_display.insert(tk.END, "\n")
            
            connections = psutil.net_connections()
            self.data_display.insert(tk.END, "\n=== ACTIVE CONNECTIONS ===\n\n")
            for conn in connections:
                self.data_display.insert(tk.END, f"{conn.laddr} -> {conn.raddr} ({conn.status})\n")
        
        elif data_type == "processes":
            self.data_display.insert(tk.END, "=== RUNNING PROCESSES ===\n\n")
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    self.data_display.insert(tk.END, f"PID: {proc.info['pid']}, Name: {proc.info['name']}, User: {proc.info['username']}\n")
                except:
                    pass
        
        elif data_type == "users":
            self.data_display.insert(tk.END, "=== USER ACCOUNTS ===\n\n")
            # This would be platform-specific implementation in a real application
            self.data_display.insert(tk.END, "User Accounts:\n")
            self.data_display.insert(tk.END, "- Administrator\n- System\n- Guest\n- ForensicUser\n")
            self.data_display.insert(tk.END, "\nNote: Detailed user account information requires admin privileges")
        
        self.data_display.configure(state='disabled')
        self.log_event(f"Collected {data_type} data")

    def export_data(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.data_display.get(1.0, tk.END))
                self.update_activity_log(f"Data exported to {file_path}")
                messagebox.showinfo("Export Successful", "Data exported successfully")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))
                self.log_event(f"Export failed: {str(e)}", "ERROR")

    def execute_access_tool(self):
        tool = self.access_tool.get()
        target = self.target_entry.get()
        
        if not target:
            messagebox.showwarning("Input Error", "Please specify a target")
            return
        
        self.update_activity_log(f"Executing {tool.replace('_', ' ')} on {target}")
        self.access_results.configure(state='normal')
        self.access_results.delete(1.0, tk.END)
        
        if tool == "password_cracker":
            self.access_results.insert(tk.END, f"=== PASSWORD CRACKING TOOL ===\n")
            self.access_results.insert(tk.END, f"Target: {target}\n\n")
            
            # Simulate password cracking
            self.access_results.insert(tk.END, "Starting dictionary attack...\n")
            self.access_results.insert(tk.END, "Trying common passwords...\n")
            self.access_results.insert(tk.END, "Attempt 1: password123 - Failed\n")
            self.access_results.insert(tk.END, "Attempt 2: 123456 - Failed\n")
            self.access_results.insert(tk.END, "Attempt 3: qwerty - Failed\n")
            self.access_results.insert(tk.END, "Attempt 4: forensic2023 - Success!\n\n")
            self.access_results.insert(tk.END, "Password found: forensic2023\n")
            self.access_results.insert(tk.END, "Access granted to system\n")
        
        elif tool == "vulnerability_scanner":
            self.access_results.insert(tk.END, f"=== VULNERABILITY SCANNER ===\n")
            self.access_results.insert(tk.END, f"Target: {target}\n\n")
            
            # Simulate vulnerability scan
            self.access_results.insert(tk.END, "Scanning for vulnerabilities...\n")
            self.access_results.insert(tk.END, "Detected OS: Windows 10\n")
            self.access_results.insert(tk.END, "Checking known vulnerabilities...\n")
            self.access_results.insert(tk.END, "Vulnerability found: CVE-2023-1234 (Critical)\n")
            self.access_results.insert(tk.END, "Vulnerability found: CVE-2023-5678 (High)\n")
            self.access_results.insert(tk.END, "Vulnerability found: CVE-2023-9012 (Medium)\n\n")
            self.access_results.insert(tk.END, "Recommendation: Apply security patches immediately\n")
        
        elif tool == "port_scanner":
            self.access_results.insert(tk.END, f"=== PORT SCANNER ===\n")
            self.access_results.insert(tk.END, f"Target: {target}\n\n")
            
            # Simulate port scan
            self.access_results.insert(tk.END, "Scanning ports...\n")
            self.access_results.insert(tk.END, "Port 21: FTP - Open\n")
            self.access_results.insert(tk.END, "Port 22: SSH - Open\n")
            self.access_results.insert(tk.END, "Port 80: HTTP - Open\n")
            self.access_results.insert(tk.END, "Port 443: HTTPS - Open\n")
            self.access_results.insert(tk.END, "Port 3389: RDP - Open\n\n")
            self.access_results.insert(tk.END, "Potential attack vectors identified\n")
        
        elif tool == "encryption_bypass":
            self.access_results.insert(tk.END, f"=== ENCRYPTION BYPASS TOOL ===\n")
            self.access_results.insert(tk.END, f"Target: {target}\n\n")
            
            # Simulate encryption bypass
            self.access_results.insert(tk.END, "Analyzing encryption scheme...\n")
            self.access_results.insert(tk.END, "Detected: AES-256 encryption\n")
            self.access_results.insert(tk.END, "Attempting known vulnerabilities...\n")
            self.access_results.insert(tk.END, "Bypassing key storage mechanism...\n")
            self.access_results.insert(tk.END, "Success! Encryption bypassed\n")
            self.access_results.insert(tk.END, "Access to encrypted data granted\n")
        
        self.access_results.configure(state='disabled')
        self.log_event(f"Executed {tool} on {target}")

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, file_path)

    def analyze_file(self, analysis_type):
        file_path = self.file_path_entry.get()
        
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("Input Error", "Please select a valid file")
            return
        
        self.update_activity_log(f"Performing {analysis_type} analysis on {file_path}")
        self.analysis_results.configure(state='normal')
        self.analysis_results.delete(1.0, tk.END)
        
        if analysis_type == "hash":
            self.analysis_results.insert(tk.END, f"=== FILE HASH ANALYSIS ===\n")
            self.analysis_results.insert(tk.END, f"File: {file_path}\n\n")
            
            try:
                # Calculate hashes
                hashes = [
                    ("MD5", hashlib.md5()),
                    ("SHA-1", hashlib.sha1()),
                    ("SHA-256", hashlib.sha256()),
                    ("SHA-512", hashlib.sha512())
                ]
                
                with open(file_path, 'rb') as f:
                    while chunk := f.read(8192):
                        for _, hash_func in hashes:
                            hash_func.update(chunk)
                
                for name, hash_func in hashes:
                    self.analysis_results.insert(tk.END, f"{name}: {hash_func.hexdigest()}\n")
                
                self.analysis_results.insert(tk.END, "\nNote: Compare these hashes to verify file integrity\n")
            
            except Exception as e:
                self.analysis_results.insert(tk.END, f"Error: {str(e)}\n")
        
        elif analysis_type == "metadata":
            self.analysis_results.insert(tk.END, f"=== FILE METADATA ===\n")
            self.analysis_results.insert(tk.END, f"File: {file_path}\n\n")
            
            try:
                stats = os.stat(file_path)
                self.analysis_results.insert(tk.END, f"Size: {stats.st_size} bytes\n")
                self.analysis_results.insert(tk.END, f"Created: {datetime.datetime.fromtimestamp(stats.st_ctime)}\n")
                self.analysis_results.insert(tk.END, f"Modified: {datetime.datetime.fromtimestamp(stats.st_mtime)}\n")
                self.analysis_results.insert(tk.END, f"Accessed: {datetime.datetime.fromtimestamp(stats.st_atime)}\n")
                self.analysis_results.insert(tk.END, f"File Type: {os.path.splitext(file_path)[1]}\n")
                
                # More detailed metadata would be extracted with specialized libraries
                self.analysis_results.insert(tk.END, "\nAdditional metadata requires specialized libraries\n")
            
            except Exception as e:
                self.analysis_results.insert(tk.END, f"Error: {str(e)}\n")
        
        elif analysis_type == "signature":
            self.analysis_results.insert(tk.END, f"=== FILE SIGNATURE ===\n")
            self.analysis_results.insert(tk.END, f"File: {file_path}\n\n")
            
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(8)
                    footer = f.read(8) if os.path.getsize(file_path) > 8 else b''
                
                self.analysis_results.insert(tk.END, f"Header (hex): {header.hex()}\n")
                self.analysis_results.insert(tk.END, f"Footer (hex): {footer.hex() if footer else 'N/A'}\n")
                
                # File signature analysis
                self.analysis_results.insert(tk.END, "\nKnown File Signatures:\n")
                signatures = {
                    "PDF": "25504446",
                    "ZIP": "504B0304",
                    "PNG": "89504E470D0A1A0A",
                    "JPEG": "FFD8FF"
                }
                
                header_hex = header.hex().upper()
                matched = False
                for file_type, sig in signatures.items():
                    if header_hex.startswith(sig):
                        self.analysis_results.insert(tk.END, f"- Matches {file_type} signature\n")
                        matched = True
                
                if not matched:
                    self.analysis_results.insert(tk.END, "- No known file signature matched\n")
            
            except Exception as e:
                self.analysis_results.insert(tk.END, f"Error: {str(e)}\n")
        
        elif analysis_type == "hex":
            self.analysis_results.insert(tk.END, f"=== HEX VIEW ===\n")
            self.analysis_results.insert(tk.END, f"File: {file_path}\n")
            self.analysis_results.insert(tk.END, "Displaying first 512 bytes in hex and ASCII\n\n")
            
            try:
                with open(file_path, 'rb') as f:
                    data = f.read(512)
                
                hex_data = data.hex()
                ascii_data = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
                
                # Format hex view
                for i in range(0, len(hex_data), 32):
                    hex_line = hex_data[i:i+32]
                    ascii_line = ascii_data[i//2:i//2+16]
                    self.analysis_results.insert(tk.END, f"{i//2:08X}: {hex_line}  {ascii_line}\n")
            
            except Exception as e:
                self.analysis_results.insert(tk.END, f"Error: {str(e)}\n")
        
        self.analysis_results.configure(state='disabled')
        self.log_event(f"Performed {analysis_type} analysis on {file_path}")

    def view_audit_log(self):
        log_window = tk.Toplevel(self.root)
        log_window.title("Audit Log")
        log_window.geometry("800x600")
        log_window.configure(bg="#FFD700")
        
        ttk.Label(log_window, text="Security Audit Log", 
                 style="Header.TLabel").pack(fill=tk.X)
        
        log_text = scrolledtext.ScrolledText(log_window, width=100, height=30)
        log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        try:
            if os.path.exists('forensic_audit.log'):
                with open('forensic_audit.log', 'r') as log_file:
                    log_content = log_file.read()
                log_text.insert(tk.END, log_content)
            else:
                log_text.insert(tk.END, "No log file found")
        except Exception as e:
            log_text.insert(tk.END, f"Error loading logs: {str(e)}")
        
        log_text.configure(state='disabled')
        
        ttk.Button(log_window, text="Close", command=log_window.destroy).pack(pady=10)

    def encrypt_data(self):
        messagebox.showinfo("Encryption", "Data encryption feature would be implemented here")
        self.log_event("Encryption tool accessed")

    def wipe_data(self):
        messagebox.showinfo("Data Wipe", "Data wiping feature would be implemented here")
        self.log_event("Data wipe tool accessed")

    def secure_erase(self):
        messagebox.showinfo("Secure Erase", "Secure erase feature would be implemented here")
        self.log_event("Secure erase tool accessed")

    def add_user(self):
        username = self.new_user_entry.get()
        password = self.new_pass_entry.get()
        
        if not username or not password:
            messagebox.showwarning("Input Error", "Both username and password are required")
            return
        
        if username in self.valid_credentials:
            messagebox.showwarning("User Exists", "Username already exists")
            return
        
        self.valid_credentials[username] = password
        self.new_user_entry.delete(0, tk.END)
        self.new_pass_entry.delete(0, tk.END)
        messagebox.showinfo("Success", "User added successfully")
        self.log_event(f"New user added: {username}")

    def logout(self):
        self.log_event("User logged out")
        self.root.destroy()
        os.execv(sys.executable, ['python'] + sys.argv)

if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalForensicSystem(root)
    root.mainloop()
