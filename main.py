#!/usr/bin/env python3
"""
Network Security Scanner GUI Application
By: Devon Mann
IT359 Network Security Scanner Project
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from vulnerability_scanner import VulnerabilityScanner
from anomaly_detector import AnomalyDetector
import threading
from datetime import datetime
import os
import json
from PIL import Image, ImageTk

# Import scanner modules
from network_scanner import NetworkScanner
from wifi_scanner import WiFiScanner

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Security Scanner")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
    
    # Initialize scanner modules
        self.network_scanner = NetworkScanner()
        self.wifi_scanner = WiFiScanner()
    
    # Set initial scan mode based on environment - ADD THESE LINES
        env = self.wifi_scanner.detect_environment()
        initial_mode = "windows" if env == "wsl2" else "auto"
        self.wifi_scanner.set_scan_mode(initial_mode)
    
    # Create data directory if it doesn't exist
        if not os.path.exists('data'):
            os.makedirs('data')
    
        self.setup_gui()
    
    def setup_gui(self):
        """Setup the main GUI layout"""
        # Create main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = tk.Label(main_frame, 
                              text="🛰️ Network Security Scanner", 
                              font=('Arial', 18, 'bold'),
                              fg='white',
                              bg='#2b2b2b')
        title_label.pack(pady=10)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create tabs
        self.setup_main_menu_tab()
        self.setup_network_scanner_tab()
        self.setup_wifi_scanner_tab()
        self.setup_vulnerability_scanner_tab()
        self.setup_anomaly_detector_tab()
        self.setup_results_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = tk.Label(main_frame, 
                             textvariable=self.status_var,
                             relief=tk.SUNKEN, 
                             anchor=tk.W,
                             fg='white',
                             bg='#404040')
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
    
    def setup_main_menu_tab(self):
        """Setup the main menu tab"""
        main_tab = ttk.Frame(self.notebook)
        self.notebook.add(main_tab, text="🏠 Main Menu")
        
        welcome_frame = ttk.LabelFrame(main_tab, text="Welcome", padding=20)
        welcome_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        welcome_text = """Welcome to the Network Security Scanner!

This tool provides various security scanning capabilities:

🔍 Network Scanner - Discover hosts and scan ports
📡 WiFi Scanner - Discover wireless networks and clients
🔒 Vulnerability Scanner - Scan for known vulnerabilities
🚨 Anomaly Detector - Monitor for suspicious traffic patterns
🔒 Password Auditor - (Coming Soon)
📡 Traffic Analyzer - (Coming Soon)

Select a tool from the tabs above to get started."""
        
        welcome_label = tk.Label(welcome_frame, 
                                text=welcome_text,
                                font=('Arial', 12),
                                justify=tk.LEFT,
                                fg='white',
                                bg='#2b2b2b')
        welcome_label.pack(anchor=tk.W, pady=10)
        
        # Quick actions frame
        actions_frame = ttk.LabelFrame(main_tab, text="Quick Actions", padding=20)
        actions_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(actions_frame, 
                  text="🚀 Quick Network Scan",
                  command=self.quick_network_scan).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(actions_frame,
                  text="📡 Quick WiFi Scan", 
                  command=self.quick_wifi_scan).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(actions_frame,
                  text="📊 View Recent Results",
                  command=self.show_recent_results).pack(side=tk.LEFT, padx=5)
    
    def setup_network_scanner_tab(self):
        """Setup the network scanner tab"""
        network_tab = ttk.Frame(self.notebook)
        self.notebook.add(network_tab, text="🔍 Network Scanner")
        
        # Configuration frame
        config_frame = ttk.LabelFrame(network_tab, text="Scan Configuration", padding=15)
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Target selection
        ttk.Label(config_frame, text="Target:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.target_var = tk.StringVar(value="192.168.1.0/24")
        target_entry = ttk.Entry(config_frame, textvariable=self.target_var, width=20)
        target_entry.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        # Scan type selection
        ttk.Label(config_frame, text="Scan Type:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.scan_type_var = tk.StringVar(value="basic")
        ttk.Radiobutton(config_frame, text="Basic Discovery", variable=self.scan_type_var, value="basic").grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(config_frame, text="Detailed Scan", variable=self.scan_type_var, value="detailed").grid(row=1, column=2, sticky=tk.W, padx=5)
        
        # Control buttons
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=10)
        
        ttk.Button(button_frame, 
                  text="🚀 Start Scan",
                  command=self.start_network_scan).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame,
                  text="💾 Save Results",
                  command=self.save_network_results).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame,
                  text="⏹️ Stop Scan",
                  command=self.stop_network_scan).pack(side=tk.LEFT, padx=5)
        
        # Progress frame
        self.network_progress_frame = ttk.LabelFrame(network_tab, text="Scan Progress", padding=15)
        self.network_progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.network_progress_var = tk.DoubleVar()
        network_progress_bar = ttk.Progressbar(self.network_progress_frame, variable=self.network_progress_var, maximum=100)
        network_progress_bar.pack(fill=tk.X, pady=5)
        
        self.network_progress_label = tk.Label(self.network_progress_frame, text="Ready to scan", fg='white', bg='#2b2b2b')
        self.network_progress_label.pack()
        
        # Results area
        results_frame = ttk.LabelFrame(network_tab, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.network_results_text = scrolledtext.ScrolledText(results_frame, height=20, bg='#1e1e1e', fg='white')
        self.network_results_text.pack(fill=tk.BOTH, expand=True)
    
    def setup_wifi_scanner_tab(self):
        """Setup the WiFi scanner tab with mode toggle"""
        wifi_tab = ttk.Frame(self.notebook)
        self.notebook.add(wifi_tab, text="📡 WiFi Scanner")
    
        # Configuration frame
        config_frame = ttk.LabelFrame(wifi_tab, text="WiFi Scan Configuration", padding=15)
        config_frame.pack(fill=tk.X, padx=10, pady=5)
    
        # Scan Mode Toggle
        ttk.Label(config_frame, text="Scan Mode:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.scan_mode_var = tk.StringVar(value="auto")
        mode_frame = ttk.Frame(config_frame)
        mode_frame.grid(row=0, column=1, columnspan=3, sticky=tk.W, pady=5)
    
        ttk.Radiobutton(mode_frame, text="Auto Detect", variable=self.scan_mode_var, 
                   value="auto", command=self.on_scan_mode_change).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="Linux Native", variable=self.scan_mode_var, 
                   value="linux", command=self.on_scan_mode_change).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="Windows (WSL2)", variable=self.scan_mode_var, 
                   value="windows", command=self.on_scan_mode_change).pack(side=tk.LEFT, padx=5)
    
        # Interface selection
        ttk.Label(config_frame, text="Wireless Interface:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.wifi_interface_var = tk.StringVar()
        self.wifi_interface_combo = ttk.Combobox(config_frame, textvariable=self.wifi_interface_var, width=20)
        self.wifi_interface_combo.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
    
        # Refresh interfaces button
        ttk.Button(config_frame, text="🔄 Refresh Interfaces", 
              command=self.refresh_wifi_interfaces).grid(row=1, column=2, sticky=tk.W, padx=5)
    
        # Environment detection display
        self.env_label = tk.Label(config_frame, text="", fg='blue', bg='#2b2b2b')
        self.env_label.grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=5)
    
        # Scan duration
        ttk.Label(config_frame, text="Scan Duration (seconds):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.scan_duration_var = tk.IntVar(value=30)
        ttk.Spinbox(config_frame, from_=10, to=300, textvariable=self.scan_duration_var, width=10).grid(row=3, column=1, sticky=tk.W, pady=5, padx=5)
    
        # Control buttons
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=4, column=0, columnspan=4, pady=10)
    
        ttk.Button(button_frame, 
              text="📡 Start WiFi Scan",
              command=self.start_wifi_scan).pack(side=tk.LEFT, padx=5)
    
        ttk.Button(button_frame,
              text="📊 Generate Network Graph",
              command=self.generate_network_graph).pack(side=tk.LEFT, padx=5)
    
        ttk.Button(button_frame,
              text="👥 Generate Client Graph", 
              command=self.generate_client_graph).pack(side=tk.LEFT, padx=5)
    
        ttk.Button(button_frame,
              text="⏹️ Stop Scan",
              command=self.stop_wifi_scan).pack(side=tk.LEFT, padx=5)
    
        
        # Progress frame
        self.wifi_progress_frame = ttk.LabelFrame(wifi_tab, text="Scan Progress", padding=15)
        self.wifi_progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.wifi_progress_var = tk.DoubleVar()
        wifi_progress_bar = ttk.Progressbar(self.wifi_progress_frame, variable=self.wifi_progress_var, maximum=100)
        wifi_progress_bar.pack(fill=tk.X, pady=5)
        
        self.wifi_progress_label = tk.Label(self.wifi_progress_frame, text="Ready to scan", fg='white', bg='#2b2b2b')
        self.wifi_progress_label.pack()
        
        # Results area with paned window
        results_paned = ttk.PanedWindow(wifi_tab, orient=tk.HORIZONTAL)
        results_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Text results frame
        text_frame = ttk.LabelFrame(results_paned, text="Scan Results", padding=10)
        results_paned.add(text_frame, weight=1)
        
        self.wifi_results_text = scrolledtext.ScrolledText(text_frame, height=20, bg='#1e1e1e', fg='white')
        self.wifi_results_text.pack(fill=tk.BOTH, expand=True)
        
        # Graph frame
        graph_frame = ttk.LabelFrame(results_paned, text="Network Graph", padding=10)
        results_paned.add(graph_frame, weight=1)
        
        # Canvas for displaying graphs
        self.graph_canvas = tk.Canvas(graph_frame, bg='#1e1e1e', highlightthickness=0)
        self.graph_canvas.pack(fill=tk.BOTH, expand=True)
        
        self.graph_label = tk.Label(graph_frame, text="Graph will appear here", 
                                   fg='gray', bg='#1e1e1e')
        self.graph_label.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        # Set initial paned window position
        results_paned.sashpos(0, 600)
        
        # Refresh interfaces on startup
        self.refresh_wifi_interfaces()

    def setup_vulnerability_scanner_tab(self):
        """Setup the vulnerability scanner tab"""
        vuln_tab = ttk.Frame(self.notebook)
        self.notebook.add(vuln_tab, text="🔒 Vuln Scanner")
    
    # Initialize vulnerability scanner
        self.vuln_scanner = VulnerabilityScanner()
    
    # Configuration frame
        config_frame = ttk.LabelFrame(vuln_tab, text="Vulnerability Scan Configuration", padding=15)
        config_frame.pack(fill=tk.X, padx=10, pady=5)
    
    # Target selection
        ttk.Label(config_frame, text="Target:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.vuln_target_var = tk.StringVar(value="192.168.1.1")
        ttk.Entry(config_frame, textvariable=self.vuln_target_var, width=20).grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
    
    # Scan type
        ttk.Label(config_frame, text="Scan Type:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.vuln_scan_type_var = tk.StringVar(value="single")
        ttk.Radiobutton(config_frame, text="Single Host", variable=self.vuln_scan_type_var, 
                    value="single").grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(config_frame, text="Network Range", variable=self.vuln_scan_type_var, 
                    value="network").grid(row=1, column=2, sticky=tk.W, padx=5)
    
    # API Key (optional)
        ttk.Label(config_frame, text="Vulners API Key (optional):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.vuln_api_key_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.vuln_api_key_var, width=30, show="*").grid(row=2, column=1, columnspan=2, sticky=tk.W, pady=5, padx=5)
    
    # Control buttons
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=10)
    
        ttk.Button(button_frame, 
                text="🔍 Start Vulnerability Scan",
                command=self.start_vuln_scan).pack(side=tk.LEFT, padx=5)
    
        ttk.Button(button_frame,
                text="💾 Save Results",
                command=self.save_vuln_results).pack(side=tk.LEFT, padx=5)
    
        ttk.Button(button_frame,
                text="📋 Generate Report",
                command=self.generate_vuln_report).pack(side=tk.LEFT, padx=5)
    
        ttk.Button(button_frame,
                text="⏹️ Stop Scan",
                command=self.stop_vuln_scan).pack(side=tk.LEFT, padx=5)
    
    # Progress frame
        self.vuln_progress_frame = ttk.LabelFrame(vuln_tab, text="Scan Progress", padding=15)
        self.vuln_progress_frame.pack(fill=tk.X, padx=10, pady=5)
    
        self.vuln_progress_var = tk.DoubleVar()
        vuln_progress_bar = ttk.Progressbar(self.vuln_progress_frame, variable=self.vuln_progress_var, maximum=100)
        vuln_progress_bar.pack(fill=tk.X, pady=5)
    
        self.vuln_progress_label = tk.Label(self.vuln_progress_frame, text="Ready to scan", fg='white', bg='#2b2b2b')
        self.vuln_progress_label.pack()
    
    # Results area with paned window
        results_paned = ttk.PanedWindow(vuln_tab, orient=tk.HORIZONTAL)
        results_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    # Summary frame
        summary_frame = ttk.LabelFrame(results_paned, text="Scan Summary", padding=10)
        results_paned.add(summary_frame, weight=1)
    
        self.vuln_summary_text = scrolledtext.ScrolledText(summary_frame, height=20, bg='#1e1e1e', fg='white')
        self.vuln_summary_text.pack(fill=tk.BOTH, expand=True)
    
    # Details frame
        details_frame = ttk.LabelFrame(results_paned, text="Vulnerability Details", padding=10)
        results_paned.add(details_frame, weight=2)
    
        self.vuln_details_text = scrolledtext.ScrolledText(details_frame, height=20, bg='#1e1e1e', fg='white')
        self.vuln_details_text.pack(fill=tk.BOTH, expand=True)
    
    # Set initial paned window position
        results_paned.sashpos(0, 400)

    def setup_anomaly_detector_tab(self):
        """Setup the network anomaly detection tab"""
        anomaly_tab = ttk.Frame(self.notebook)
        self.notebook.add(anomaly_tab, text="🚨 Anomaly Detector")
    
    # Initialize anomaly detector
        self.anomaly_detector = AnomalyDetector()
    
    # Configuration frame
        config_frame = ttk.LabelFrame(anomaly_tab, text="Anomaly Detection Configuration", padding=15)
        config_frame.pack(fill=tk.X, padx=10, pady=5)
    
    # Interface selection
        ttk.Label(config_frame, text="Network Interface:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.anomaly_interface_var = tk.StringVar()
        self.anomaly_interface_combo = ttk.Combobox(config_frame, textvariable=self.anomaly_interface_var, width=15)
        self.anomaly_interface_combo.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
    
    # Get available interfaces
        self.refresh_anomaly_interfaces()
    
    # Monitoring duration
        ttk.Label(config_frame, text="Duration (seconds):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.anomaly_duration_var = tk.IntVar(value=60)
        ttk.Spinbox(config_frame, from_=10, to=3600, textvariable=self.anomaly_duration_var, width=10).grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
    
    # Control buttons
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=10)
    
        ttk.Button(button_frame, 
                text="🚀 Start Monitoring",
                command=self.start_anomaly_monitoring).pack(side=tk.LEFT, padx=5)
    
        ttk.Button(button_frame,
                text="📊 Generate Traffic Graph",
                command=self.generate_traffic_graph).pack(side=tk.LEFT, padx=5)
    
        ttk.Button(button_frame,
                text="💾 Save Results",
                command=self.save_anomaly_results).pack(side=tk.LEFT, padx=5)
    
        ttk.Button(button_frame,
                text="⏹️ Stop Monitoring",
                command=self.stop_anomaly_monitoring).pack(side=tk.LEFT, padx=5)
    
    # Status frame
        self.anomaly_status_frame = ttk.LabelFrame(anomaly_tab, text="Monitoring Status", padding=15)
        self.anomaly_status_frame.pack(fill=tk.X, padx=10, pady=5)
    
        self.anomaly_status_label = tk.Label(self.anomaly_status_frame, text="Not monitoring", fg='white', bg='#2b2b2b')
        self.anomaly_status_label.pack()
    
    # Results area with paned window
        results_paned = ttk.PanedWindow(anomaly_tab, orient=tk.VERTICAL)
        results_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    # Anomalies frame
        anomalies_frame = ttk.LabelFrame(results_paned, text="Detected Anomalies", padding=10)
        results_paned.add(anomalies_frame, weight=1)
    
        self.anomalies_text = scrolledtext.ScrolledText(anomalies_frame, height=10, bg='#1e1e1e', fg='white')
        self.anomalies_text.pack(fill=tk.BOTH, expand=True)
    
    # Statistics frame
        stats_frame = ttk.LabelFrame(results_paned, text="Traffic Statistics", padding=10)
        results_paned.add(stats_frame, weight=1)
    
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=10, bg='#1e1e1e', fg='white')
        self.stats_text.pack(fill=tk.BOTH, expand=True)
    
    # Set initial paned window position
        results_paned.sashpos(0, 200)
    
    def setup_results_tab(self):
        """Setup the results tab"""
        results_tab = ttk.Frame(self.notebook)
        self.notebook.add(results_tab, text="📊 Results")
        
        # Results management frame
        management_frame = ttk.LabelFrame(results_tab, text="Results Management", padding=15)
        management_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(management_frame, 
                  text="📁 Load Results",
                  command=self.load_results).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(management_frame,
                  text="🗑️ Clear Results",
                  command=self.clear_results).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(management_frame,
                  text="📋 Export Results",
                  command=self.export_results).pack(side=tk.LEFT, padx=5)
        
        # Results display area
        display_frame = ttk.LabelFrame(results_tab, text="Stored Results", padding=10)
        display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(display_frame, height=20, bg='#1e1e1e', fg='white')
        self.results_text.pack(fill=tk.BOTH, expand=True)
    
    # Network Scanner Methods
    def start_network_scan(self):
        """Start network scan in separate thread"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target to scan")
            return
        
        self.update_network_progress("Starting network scan...", 0)
        self.log_network_result(f"🔍 Starting {self.scan_type_var.get()} scan on: {target}")
        
        thread = threading.Thread(target=self._run_network_scan, args=(target,))
        thread.daemon = True
        thread.start()
    
    def _run_network_scan(self, target):
        """Run network scan in background thread"""
        try:
            if self.scan_type_var.get() == "basic":
                self.update_network_progress("Performing basic discovery...", 30)
                results = self.network_scanner.basic_scan(target)
                
                self.update_network_progress("Processing results...", 90)
                self.log_network_result(f"✅ Basic scan completed. Found {len(results)} active hosts")
                
                # Display results
                for host in results:
                    self.log_network_result(f"   🖥️  {host['ip']} - {host['hostname']} ({host['status']})")
                    
            else:  # detailed scan
                self.update_network_progress("Performing detailed scan...", 30)
                results = self.network_scanner.detailed_scan(target)
                
                self.update_network_progress("Processing results...", 90)
                self.log_network_result(f"✅ Detailed scan completed. Found {len(results)} hosts")
                
                # Display results
                for host in results:
                    self.log_network_result(f"   🖥️  {host['ip']} - {host['hostname']}")
                    if 'os_guess' in host:
                        self.log_network_result(f"      OS: {host['os_guess']}")
                    if host['ports']:
                        self.log_network_result(f"      Open ports: {len(host['ports'])}")
                        for port in host['ports'][:5]:  # Show first 5 ports
                            self.log_network_result(f"        {port['port']}/{port['protocol']} - {port['service']}")
            
            self.update_network_progress("Scan completed", 100)
            
        except Exception as e:
            self.log_network_result(f"❌ Network scan error: {e}")
            self.update_network_progress("Scan failed", 0)
    
    def update_network_progress(self, message, value=None):
        """Update network progress bar and label"""
        if value is not None:
            self.network_progress_var.set(value)
        self.network_progress_label.config(text=message)
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def log_network_result(self, message):
        """Add message to network results text area"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        self.network_results_text.insert(tk.END, formatted_message)
        self.network_results_text.see(tk.END)
        self.root.update_idletasks()
    
    def stop_network_scan(self):
        """Stop network scan"""
        self.network_scanner.stop_scan()
        self.log_network_result("⏹️ Network scan stopped by user")
        self.update_network_progress("Scan stopped", 0)
    
    def save_network_results(self):
        """Save network scan results"""
        try:
            filename = self.network_scanner.save_results()
            self.log_network_result(f"💾 Results saved to: {filename}")
            messagebox.showinfo("Save Successful", f"Results saved to {filename}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Could not save results: {e}")
    
    # WiFi Scanner Methods (these were already in your code)
    def refresh_wifi_interfaces(self):
        """Refresh list of wireless interfaces based on current mode"""
        try:
            interfaces = self.wifi_scanner.get_interface_list()
            self.wifi_interface_combo['values'] = interfaces
            if interfaces:
                self.wifi_interface_var.set(interfaces[0])
            else:
                self.wifi_interface_var.set('')
        
        # Update environment display
            env = self.wifi_scanner.detect_environment()
            mode = self.scan_mode_var.get()
            env_text = f"Detected: {env.upper()} | Mode: {mode.upper()} | Interfaces: {len(interfaces)} found"
            self.env_label.config(text=env_text)
        
        except Exception as e:
            messagebox.showerror("Error", f"Could not detect wireless interfaces: {e}")
    
    def update_wifi_progress(self, message, value=None):
        """Update WiFi progress bar and label"""
        if value is not None:
            self.wifi_progress_var.set(value)
        self.wifi_progress_label.config(text=message)
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def log_wifi_result(self, message):
        """Add message to WiFi results text area"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        self.wifi_results_text.insert(tk.END, formatted_message)
        self.wifi_results_text.see(tk.END)
        self.root.update_idletasks()
    
    def start_wifi_scan(self):
        """Start WiFi scan in separate thread"""
        interface = self.wifi_interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select a wireless interface")
            return
        
        # Check dependencies with better error reporting
        missing_tools = self.wifi_scanner.check_dependencies()
        if missing_tools:
            env = self.wifi_scanner.detect_environment()
            mode = self.scan_mode_var.get()
        
            error_msg = f"Missing dependencies:\n" + "\n".join(missing_tools)
        
            if mode == "windows" or (mode == "auto" and env == "wsl2"):
                error_msg += "\n\nFor Windows mode in WSL2:"
                error_msg += "\n- Ensure WSL2 can run Windows commands"
                error_msg += "\n- Try running manually: 'cmd.exe /c netsh wlan show interfaces'"
            else:
                error_msg += "\n\nFor Linux mode:"
                error_msg += "\n- Install aircrack-ng: 'sudo apt install aircrack-ng'"
        
            messagebox.showerror("Missing Dependencies", error_msg)
            return
    
        self.update_wifi_progress("Starting WiFi scan...", 0)
        self.log_wifi_result(f"📡 Starting WiFi scan on interface: {interface}")
        self.log_wifi_result(f"🔧 Mode: {self.scan_mode_var.get()}, Environment: {self.wifi_scanner.detect_environment()}")
    
        thread = threading.Thread(target=self._run_wifi_scan, args=(interface,))
        thread.daemon = True
        thread.start()
    
    def _run_wifi_scan(self, interface):
        """Run WiFi scan in background thread with better logging"""
        monitor_interface = None
        try:
            env = self.wifi_scanner.detect_environment()
            mode = self.scan_mode_var.get()
            self.log_wifi_result(f"🔍 Environment: {env}, Scan Mode: {mode}")
        
            if mode == "linux" or (mode == "auto" and env == "linux"):
            # Linux scanning path
                self.update_wifi_progress("Starting monitor mode...", 10)
                self.log_wifi_result("Putting interface into monitor mode...")
            
                monitor_interface = self.wifi_scanner.start_monitor_mode(interface)
                if not monitor_interface:
                    raise Exception("Failed to start monitor mode")
            
                self.log_wifi_result(f"Monitor mode started on: {monitor_interface}")
            
                duration = self.scan_duration_var.get()
                self.update_wifi_progress(f"Scanning for {duration} seconds...", 30)
            
                networks, clients = self.wifi_scanner.scan_networks(monitor_interface, duration)
            
            else:
            # Windows scanning path
                self.log_wifi_result("Using Windows networking tools via WSL2...")
                self.update_wifi_progress("Querying Windows WiFi information...", 30)
            
                duration = self.scan_duration_var.get()
                networks, clients = self.wifi_scanner.scan_networks(interface, duration)
        
            self.update_wifi_progress("Processing results...", 90)
            self.log_wifi_result(f"✅ Scan completed. Found {len(networks)} networks and {len(clients)} clients")
        
        # Display networks
            if networks:
                self.log_wifi_result("\n📶 Discovered Networks:")
                for network in networks:
                    essid = network.get('essid', 'Unknown').strip()
                    bssid = network.get('bssid', 'Unknown').strip()
                    channel = network.get('channel', 'Unknown').strip()
                    power = network.get('power', 'Unknown').strip()
                    privacy = network.get('privacy', 'Unknown').strip()
                
                    self.log_wifi_result(f"   📡 {essid}")
                    self.log_wifi_result(f"      MAC: {bssid}")
                    self.log_wifi_result(f"      Channel: {channel}, Power: {power} dBm")
                    self.log_wifi_result(f"      Security: {privacy}")
            else:
                self.log_wifi_result("\n⚠️ No networks found - trying alternative method...")
            # Try a simpler scan as fallback
                try:
                    simple_result = subprocess.run(
                        ['cmd.exe', '/c', 'cd', 'C:\\', '&&', 'netsh', 'wlan', 'show', 'networks'], 
                        capture_output=True, text=True, timeout=10
                    )
                    if simple_result.stdout:
                        self.log_wifi_result("Raw netsh output:")
                        for line in simple_result.stdout.split('\n')[:20]:  # First 20 lines
                            if line.strip():
                                self.log_wifi_result(f"   {line.strip()}")
                except:
                    pass
        
        # Display clients
            if clients:
                self.log_wifi_result(f"\n👥 Clients in ARP table: {len(clients)}")
                for client in clients[:10]:  # Show first 10
                    self.log_wifi_result(f"   📱 {client.get('station_mac', 'Unknown')}")
        
            self.update_wifi_progress("Scan completed", 100)
        
        except Exception as e:
            self.log_wifi_result(f"❌ WiFi scan error: {e}")
            self.update_wifi_progress("Scan failed", 0)
        finally:
            if monitor_interface:
                try:
                    self.log_wifi_result("Restoring interface...")
                    self.wifi_scanner.stop_monitor_mode(monitor_interface)
                    self.log_wifi_result("Interface restored")
                except Exception as e:
                    self.log_wifi_result(f"Warning: Could not restore interface: {e}")
    
    def generate_network_graph(self):
        """Generate and display network graph"""
        if not self.wifi_scanner.scan_results.get('networks'):
            messagebox.showerror("Error", "No scan results available. Please run a scan first.")
            return
        
        thread = threading.Thread(target=self._generate_network_graph_thread)
        thread.daemon = True
        thread.start()
    
    def _generate_network_graph_thread(self):
        """Generate network graph in background thread"""
        try:
            self.update_wifi_progress("Generating network graph...", 0)
            
            graph_file = self.wifi_scanner.generate_network_graph()
            
            self.update_wifi_progress("Loading graph...", 90)
            self._display_graph_image(graph_file)
            
            self.update_wifi_progress("Network graph generated", 100)
            self.log_wifi_result("📊 Network graph generated successfully")
            
        except Exception as e:
            self.log_wifi_result(f"❌ Graph generation error: {e}")
            self.update_wifi_progress("Graph generation failed", 0)
    
    def generate_client_graph(self):
        """Generate and display client graph"""
        if not self.wifi_scanner.scan_results.get('clients'):
            messagebox.showerror("Error", "No client data available. Please run a scan first.")
            return
        
        thread = threading.Thread(target=self._generate_client_graph_thread)
        thread.daemon = True
        thread.start()
    
    def _generate_client_graph_thread(self):
        """Generate client graph in background thread"""
        try:
            self.update_wifi_progress("Generating client graph...", 0)
            
            graph_file = self.wifi_scanner.generate_client_graph()
            
            self.update_wifi_progress("Loading graph...", 90)
            self._display_graph_image(graph_file)
            
            self.update_wifi_progress("Client graph generated", 100)
            self.log_wifi_result("👥 Client graph generated successfully")
            
        except Exception as e:
            self.log_wifi_result(f"❌ Client graph error: {e}")
            self.update_wifi_progress("Graph generation failed", 0)
    
    def _display_graph_image(self, image_path):
        """Display graph image on canvas"""
        try:
            # Load and display image
            image = Image.open(image_path)
            
            # Get canvas dimensions
            self.graph_canvas.update()
            canvas_width = self.graph_canvas.winfo_width()
            canvas_height = self.graph_canvas.winfo_height()
            
            # Resize image to fit canvas while maintaining aspect ratio
            image.thumbnail((canvas_width - 20, canvas_height - 20), Image.Resampling.LANCZOS)
            
            # Convert to PhotoImage
            photo = ImageTk.PhotoImage(image)
            
            # Clear canvas and display image
            self.graph_canvas.delete("all")
            self.graph_label.place_forget()  # Hide placeholder label
            
            # Center the image on canvas
            x = (canvas_width - image.width) // 2
            y = (canvas_height - image.height) // 2
            self.graph_canvas.create_image(x, y, anchor=tk.NW, image=photo)
            
            # Keep reference to prevent garbage collection
            self.graph_canvas.image = photo
            
        except Exception as e:
            self.log_wifi_result(f"❌ Error displaying graph: {e}")

    def on_scan_mode_change(self):
        """Handle scan mode change"""
        mode = self.scan_mode_var.get()
        self.wifi_scanner.set_scan_mode(mode)
    
    # Update environment display
        env = self.wifi_scanner.detect_environment()
        env_text = f"Detected: {env.upper()} | Mode: {mode.upper()}"
        self.env_label.config(text=env_text)
    
    # Refresh interfaces for the new mode
        self.refresh_wifi_interfaces()
    
    def stop_wifi_scan(self):
        """Stop WiFi scan"""
        self.wifi_scanner.stop_scan()
        self.log_wifi_result("⏹️ WiFi scan stopped by user")
        self.update_wifi_progress("Scan stopped", 0)
    
    # Results Tab Methods
    def load_results(self):
        """Load results from file"""
        filename = filedialog.askopenfilename(
            initialdir="data",
            title="Select results file",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*"))
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    results = json.load(f)
                
                self.results_text.delete(1.0, tk.END)
                self.results_text.insert(tk.END, json.dumps(results, indent=2))
                messagebox.showinfo("Success", f"Loaded results from {os.path.basename(filename)}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not load file: {e}")
    
    def clear_results(self):
        """Clear results display"""
        self.results_text.delete(1.0, tk.END)
    
    def export_results(self):
        """Export results to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=(("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*"))
        )
        
        if filename:
            try:
                content = self.results_text.get(1.0, tk.END)
                with open(filename, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not export results: {e}")
    
    # Main Menu Methods
    def quick_network_scan(self):
        """Quick network scan from main menu"""
        self.notebook.select(1)  # Switch to network scanner tab
        self.target_var.set("192.168.1.0/24")
        self.scan_type_var.set("basic")
        messagebox.showinfo("Quick Scan", 
                          "Ready for quick network scan!\n\nTarget: 192.168.1.0/24\nScan Type: Basic Discovery\n\nClick 'Start Scan' to begin.")
    
    def quick_wifi_scan(self):
        """Quick WiFi scan from main menu"""
        self.notebook.select(2)  # Switch to WiFi scanner tab
        self.start_wifi_scan()
    
    def show_recent_results(self):
        """Show recent scan results"""
        # Check for recent result files
        result_files = []
        if os.path.exists('data'):
            for file in os.listdir('data'):
                if file.startswith(('scan_results_', 'wifi_scan_results_')):
                    result_files.append(file)
        
        if not result_files:
            messagebox.showinfo("Recent Results", "No recent scan results found.")
            return
        
        # Show most recent file
        latest_file = sorted(result_files)[-1]
        filepath = os.path.join('data', latest_file)
        
        try:
            with open(filepath, 'r') as f:
                results = json.load(f)
            
            # Create a simple results viewer
            results_window = tk.Toplevel(self.root)
            results_window.title(f"Results: {latest_file}")
            results_window.geometry("800x600")
            
            text_area = scrolledtext.ScrolledText(results_window, wrap=tk.WORD)
            text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            text_area.insert(tk.END, json.dumps(results, indent=2))
            text_area.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Could not load results: {e}")

    def refresh_anomaly_interfaces(self):
        """Refresh list of network interfaces for anomaly detection"""
        try:
        # Get available network interfaces
            import netifaces
            interfaces = netifaces.interfaces()
            self.anomaly_interface_combo['values'] = interfaces
            if interfaces:
                self.anomaly_interface_var.set(interfaces[0])
        except ImportError:
        # Fallback if netifaces not installed
            self.anomaly_interface_combo['values'] = ['eth0', 'wlan0', 'any']
            self.anomaly_interface_var.set('any')

# Vulnerability Scanner Methods
    def start_vuln_scan(self):
        """Start vulnerability scan"""
        target = self.vuln_target_var.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target to scan")
            return
    
    # Set API key if provided
        api_key = self.vuln_api_key_var.get()
        if api_key:
            self.vuln_scanner.set_api_key(api_key)
    
        self.update_vuln_progress("Starting vulnerability scan...", 0)
        self.log_vuln_result(f"🔍 Starting vulnerability scan on: {target}")
    
        thread = threading.Thread(target=self._run_vuln_scan, args=(target,))
        thread.daemon = True
        thread.start()

    def _run_vuln_scan(self, target):
        """Run vulnerability scan in background thread"""
        try:
            scan_type = self.vuln_scan_type_var.get()
        
            if scan_type == "single":
                self.update_vuln_progress(f"Scanning host {target}...", 30)
                results = self.vuln_scanner.scan_host(target)
            else:
                self.update_vuln_progress(f"Scanning network range {target}...", 30)
                results = self.vuln_scanner.scan_network(target)
        
            self.update_vuln_progress("Processing results...", 90)
        
        # Update UI with results
            self.display_vuln_results(results)
        
            self.update_vuln_progress("Scan completed", 100)
        
        except Exception as e:
            self.log_vuln_result(f"❌ Vulnerability scan error: {e}")
            self.update_vuln_progress("Scan failed", 0)

    def update_vuln_progress(self, message, value=None):
        """Update vulnerability scan progress"""
        if value is not None:
            self.vuln_progress_var.set(value)
        self.vuln_progress_label.config(text=message)
        self.status_var.set(message)
        self.root.update_idletasks()

    def log_vuln_result(self, message):
        """Add message to vulnerability results"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        self.vuln_summary_text.insert(tk.END, formatted_message)
        self.vuln_summary_text.see(tk.END)
        self.root.update_idletasks()

    def display_vuln_results(self, results):
        """Display vulnerability scan results"""
    # Clear previous results
        self.vuln_summary_text.delete(1.0, tk.END)
        self.vuln_details_text.delete(1.0, tk.END)
    
        if not results.get('hosts'):
            self.log_vuln_result("No hosts found or scanned.")
            return
    
    # Display summary
        total_vulns = sum(len(host.get('vulnerabilities', [])) for host in results['hosts'])
        self.log_vuln_result(f"✅ Scan completed. Found {total_vulns} vulnerabilities across {len(results['hosts'])} hosts")
    
    # Display details
        for host in results['hosts']:
            self.vuln_details_text.insert(tk.END, f"\n{'='*60}\n")
            self.vuln_details_text.insert(tk.END, f"Host: {host['ip']}\n")
            self.vuln_details_text.insert(tk.END, f"Risk Level: {host['risk_level']}\n")
            self.vuln_details_text.insert(tk.END, f"Vulnerabilities: {len(host.get('vulnerabilities', []))}\n")
        
            for vuln in host.get('vulnerabilities', []):
                self.vuln_details_text.insert(tk.END, f"\n{'─'*40}\n")
                self.vuln_details_text.insert(tk.END, f"Title: {vuln.get('title', 'Unknown')}\n")
                self.vuln_details_text.insert(tk.END, f"CVSS Score: {vuln.get('cvss_score', 'Unknown')}\n")
                self.vuln_details_text.insert(tk.END, f"Port: {vuln.get('port', 'Unknown')}\n")
                self.vuln_details_text.insert(tk.END, f"Description: {vuln.get('description', 'No description')}\n")
    
        self.vuln_details_text.see(tk.END)

    def save_vuln_results(self):
        """Save vulnerability scan results"""
        try:
            filename = self.vuln_scanner.save_results()
            self.log_vuln_result(f"💾 Results saved to: {filename}")
            messagebox.showinfo("Save Successful", f"Results saved to {filename}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Could not save results: {e}")

    def generate_vuln_report(self):
        """Generate vulnerability report"""
        try:
            report = self.vuln_scanner.generate_report()
            self.vuln_summary_text.delete(1.0, tk.END)
            self.vuln_summary_text.insert(tk.END, report)
            self.log_vuln_result("📋 Report generated")
        except Exception as e:
            messagebox.showerror("Report Error", f"Could not generate report: {e}")

    def stop_vuln_scan(self):
        """Stop vulnerability scan"""
        self.vuln_scanner.stop_scan()
        self.log_vuln_result("⏹️ Vulnerability scan stopped by user")
        self.update_vuln_progress("Scan stopped", 0)

# Anomaly Detection Methods
    def start_anomaly_monitoring(self):
        """Start anomaly detection monitoring"""
        interface = self.anomaly_interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select a network interface")
            return
    
        duration = self.anomaly_duration_var.get()
    
        self.anomaly_status_label.config(text=f"Monitoring {interface} for {duration} seconds...", fg='yellow')
        self.anomalies_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
    
        self.anomalies_text.insert(tk.END, "🚨 Starting anomaly detection...\n")
        self.stats_text.insert(tk.END, "📊 Starting traffic analysis...\n")
    
        thread = threading.Thread(target=self._run_anomaly_monitoring, args=(interface, duration))
        thread.daemon = True
        thread.start()

    def _run_anomaly_monitoring(self, interface, duration):
        """Run anomaly monitoring in background thread"""
        try:
            self.anomaly_detector.start_monitoring(interface, duration)
        
        # Wait for monitoring to complete
            time.sleep(duration + 2)  # Add buffer for analysis
        
        # Get results
            results = self.anomaly_detector.get_results()
        
        # Update UI
            self.display_anomaly_results(results)
        
            self.anomaly_status_label.config(text="Monitoring completed", fg='green')
        
        except Exception as e:
            self.anomalies_text.insert(tk.END, f"❌ Monitoring error: {e}\n")
            self.anomaly_status_label.config(text="Monitoring failed", fg='red')

    def display_anomaly_results(self, results):
        """Display anomaly detection results"""
    # Display anomalies
        self.anomalies_text.insert(tk.END, "\n" + "="*60 + "\n")
        self.anomalies_text.insert(tk.END, "DETECTED ANOMALIES:\n")
        self.anomalies_text.insert(tk.END, "="*60 + "\n")
    
        if results.get('anomalies'):
            for anomaly in results['anomalies']:
                severity_color = {
                    'Critical': 'red',
                    'High': 'orange',
                    'Medium': 'yellow',
                    'Low': 'green'
                }.get(anomaly['severity'], 'white')
            
                self.anomalies_text.insert(tk.END, 
                    f"\n[{anomaly['severity']}] {anomaly['type']}\n")
                self.anomalies_text.insert(tk.END, 
                    f"   {anomaly['description']}\n")
                self.anomalies_text.insert(tk.END, 
                    f"   Time: {anomaly['timestamp']}\n")
        else:
            self.anomalies_text.insert(tk.END, "\n✅ No anomalies detected\n")
    
    # Display statistics
        self.stats_text.insert(tk.END, "\n" + "="*60 + "\n")
        self.stats_text.insert(tk.END, "TRAFFIC STATISTICS:\n")
        self.stats_text.insert(tk.END, "="*60 + "\n")
    
        stats = results.get('statistics', {})
        if stats:
            self.stats_text.insert(tk.END, f"\nTotal Packets: {stats.get('total_packets', 0)}\n")
            self.stats_text.insert(tk.END, f"Packet Rate: {stats.get('packet_rate', 0)} packets/sec\n")
            self.stats_text.insert(tk.END, f"Avg Packet Size: {stats.get('avg_packet_size', 0)} bytes\n")
        
            self.stats_text.insert(tk.END, f"\nProtocol Distribution:\n")
            for proto, count in stats.get('protocol_distribution', {}).items():
                self.stats_text.insert(tk.END, f"  {proto}: {count}\n")
        
            self.stats_text.insert(tk.END, f"\nTop Source IPs:\n")
            for ip, count in stats.get('top_source_ips', {}).items():
                self.stats_text.insert(tk.END, f"  {ip}: {count} packets\n")
        
            self.stats_text.insert(tk.END, f"\nTop Ports:\n")
            for port, count in stats.get('top_ports', {}).items():
                self.stats_text.insert(tk.END, f"  Port {port}: {count} packets\n")

    def generate_traffic_graph(self):
        """Generate and display traffic graph"""
        try:
            graph_file = self.anomaly_detector.generate_traffic_graph()
            if graph_file:
            # Create a new window to display the graph
                graph_window = tk.Toplevel(self.root)
                graph_window.title("Traffic Analysis Graph")
                graph_window.geometry("1000x800")
            
            # Load and display image
                image = Image.open(graph_file)
                photo = ImageTk.PhotoImage(image)
            
                label = tk.Label(graph_window, image=photo)
                label.image = photo  # Keep a reference
                label.pack(padx=10, pady=10)
            
            # Add close button
                ttk.Button(graph_window, text="Close", 
                        command=graph_window.destroy).pack(pady=10)
            
                self.anomalies_text.insert(tk.END, "\n📊 Traffic graph generated\n")
            else:
                self.anomalies_text.insert(tk.END, "\n⚠️ Could not generate traffic graph\n")
        except Exception as e:
            self.anomalies_text.insert(tk.END, f"\n❌ Graph generation error: {e}\n")

    def save_anomaly_results(self):
        """Save anomaly detection results"""
        try:
            filename = self.anomaly_detector.save_results()
            self.anomalies_text.insert(tk.END, f"\n💾 Results saved to: {filename}\n")
            messagebox.showinfo("Save Successful", f"Results saved to {filename}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Could not save results: {e}")

    def stop_anomaly_monitoring(self):
        """Stop anomaly monitoring"""
        self.anomaly_detector.stop_monitoring()
        self.anomaly_status_label.config(text="Monitoring stopped", fg='orange')
        self.anomalies_text.insert(tk.END, "\n⏹️ Monitoring stopped by user\n")

def main():
    """Main application entry point"""
    try:
        root = tk.Tk()
        app = ScannerGUI(root)
        root.mainloop()
    except KeyboardInterrupt:
        print("\n👋 Application closed by user")
    except Exception as e:
        print(f"❌ Application error: {e}")

if __name__ == "__main__":
    main()