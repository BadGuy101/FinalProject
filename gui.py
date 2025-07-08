import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, simpledialog
import threading
import psutil
import os
import sys
import json
from datetime import datetime
import logging
from queue import Queue
from utils.feature_aggregator import aggregate_features
from utils.notifications import notify_user

class AdvoShieldGUI:
    """Comprehensive GUI for Adware Detection System combining all features"""

    def __init__(self, security_manager, system_monitor, file_scanner, quarantine_manager, 
                 report_generator, network_sniffer, network_analyzer= None, threat_intel=None, ml_engine=None):
        
        self.network_analyzer = network_analyzer
        self.scan_cancelled = False
        self.root = tk.Tk()
        self.root.title("AdvoShield - Advanced Adware Detection System")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')
        
        # Initialize core components
        self.security_manager = security_manager
        self.system_monitor = system_monitor
        self.file_scanner = file_scanner
        self.quarantine_manager = quarantine_manager
        self.network_sniffer = network_sniffer
        self.report_generator = report_generator
        self.threat_intel = threat_intel
        self.ml_engine = ml_engine
        
        # Thread-safe communication
        self.scan_queue = Queue()
        self.scan_active = False
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use("default")  # or "clam"

        self.style.theme_use('clam')
        self._configure_styles()
        
        # Build GUI components
        self._create_menu()
        self._create_status_bar()
        self._create_main_panels()
        self._create_controls_section()
        self._create_scan_results_section()
        self._create_log_viewer()
        self._create_threat_level_indicator()
        
        # Start background updates
        self._update_system_stats()
        self._update_process_list()
        self._process_scan_queue()
        self._check_network_alerts()
        
        # Initialize logging bridge
        self._setup_logging_bridge()
        self.root.after(5000, self._check_lockdown_flag)

    def _configure_styles(self):
        """Configure custom widget styles"""
        self.style.configure('TButton', padding=6, relief='flat', background='#4a7a8c', foreground='white')
        self.style.configure('Title.TLabel', font=('Helvetica', 14, 'bold'), background='#1e1e1e', foreground='white')
        self.style.configure('Status.TFrame', background='#333333')
        self.style.configure('TFrame', background='#1e1e1e')
        self.style.configure('TLabel', background='#1e1e1e', foreground='white')
        self.style.map('Critical.TProgressBar',
                      foreground=[('!disabled', '#ff4444'), ('disabled', '#ff4444')],
                      background=[('!disabled', '#ffe6e6'), ('disabled', '#ffe6e6')])

    def _configure_treeview_tags(self):
        """Configure background colors for severity levels"""
        self.threat_display.tag_configure('high', background='#ffcccc', foreground='black')
        self.threat_display.tag_configure('medium', background='#fff3cd', foreground='black')
        self.threat_display.tag_configure('low', background='#d4edda', foreground='black')


    def _create_menu(self):
        """Create the main menu bar"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg='#333', fg='white')
        file_menu.add_command(label="New Scan", command=self.new_scan)
        file_menu.add_command(label="Load Dataset", command=self.load_dataset)
        file_menu.add_command(label="Load Report", command=self.load_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Scan menu
        scan_menu = tk.Menu(menubar, tearoff=0, bg='#333', fg='white')
        scan_menu.add_command(label="Quick Scan", command=lambda: self.start_scan('quick'))
        scan_menu.add_command(label="Full Scan", command=lambda: self.start_scan('full'))
        scan_menu.add_command(label="Custom Scan", command=self.custom_scan)
        menubar.add_cascade(label="Scan", menu=scan_menu)
        
        # ML menu
        ml_menu = tk.Menu(menubar, tearoff=0, bg='#333', fg='white')
        ml_menu.add_command(label="Train Model", command=self.train_model)
        ml_menu.add_command(label="Model Info", command=self.show_model_info)
        menubar.add_cascade(label="Machine Learning", menu=ml_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0, bg='#333', fg='white')
        view_menu.add_checkbutton(label="Show Threat Details", variable=tk.BooleanVar())
        view_menu.add_checkbutton(label="Show System Metrics", variable=tk.BooleanVar())
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg='#333', fg='white')
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
        self.lockdown_banner = ttk.Label(self.root, text="", background="red", foreground="white", font=('Arial', 12, 'bold'))
        self.lockdown_banner.pack(fill=tk.X)


    def _create_status_bar(self):
        """Create the status bar at bottom"""
        status_frame = ttk.Frame(self.root, style='Status.TFrame')
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.threat_status = ttk.Label(status_frame, text="Threats Detected: 0", width=20)
        self.threat_status.pack(side=tk.LEFT, padx=5)
        
        self.scan_status = ttk.Label(status_frame, text="Last Scan: Never")
        self.scan_status.pack(side=tk.LEFT, padx=5)
        
        self.sys_status = ttk.Label(status_frame, text="System: Normal")
        self.sys_status.pack(side=tk.RIGHT, padx=5)

    def _create_threat_level_indicator(self):
        """Create threat level indicator"""
        self.threat_level_frame = ttk.Frame(self.root)
        self.threat_level_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        self.threat_level_label = ttk.Label(self.threat_level_frame, text="Threat Level:", font=('Helvetica', 10))
        self.threat_level_label.pack(side=tk.LEFT)
        
        self.threat_level = ttk.Label(self.threat_level_frame, text="Low", foreground="green", font=('Helvetica', 10, 'bold'))
        self.threat_level.pack(side=tk.LEFT, padx=5)

    def _create_main_panels(self):
        """Create main content panels"""
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel - System Overview
        left_panel = ttk.Frame(main_frame, width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.Y)
        
        ttk.Label(left_panel, text="System Overview", style='Title.TLabel').pack(pady=5)
        
        # Resource gauges
        self.cpu_gauge = ttk.Progressbar(left_panel, length=200, mode='determinate')
        self.cpu_gauge.pack(pady=5)
        ttk.Label(left_panel, text="CPU Usage").pack()
        
        self.mem_gauge = ttk.Progressbar(left_panel, length=200, mode='determinate')
        self.mem_gauge.pack(pady=5)
        ttk.Label(left_panel, text="Memory Usage").pack()
        
        # Process list
        ttk.Label(left_panel, text="Active Processes", style='Title.TLabel').pack(pady=5)
        self.process_list = ttk.Treeview(left_panel, columns=('name', 'pid', 'cpu'), show='headings', height=10)
        self.process_list.heading('name', text='Process Name')
        self.process_list.heading('pid', text='PID')
        self.process_list.heading('cpu', text='CPU %')
        self.process_list.pack(fill=tk.X, pady=5)
        
        # Right panel - Main content
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Threat visualization
        ttk.Label(right_panel, text="Threat Detection", style='Title.TLabel').pack(pady=5)
        self.threat_display = ttk.Treeview(right_panel, columns=('type', 'severity', 'path'), show='headings', height=15)
        self.threat_display.heading('type', text='Threat Type')
        self.threat_display.heading('severity', text='Severity')
        self.threat_display.heading('path', text='Location')
        self.threat_display.pack(fill=tk.BOTH, expand=True)
        self._configure_treeview_tags()


        ttk.Label(right_panel, text="Live Threat Feed (Recent)", style='Title.TLabel').pack(pady=5)
        self.threat_feed = tk.Listbox(right_panel, height=4)
        self.threat_feed.pack(fill=tk.X)

        self._configure_treeview_tags()




    def _create_controls_section(self):
        """Create scan control buttons"""
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(control_frame, text="Quick Scan", command=lambda: self.start_scan('quick')).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Full Scan", command=lambda: self.start_scan('full')).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Stop Scan", command=self.stop_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Train Model", command=self.train_model).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Quarantine", command=self.show_quarantine).pack(side=tk.RIGHT, padx=5)
        ttk.Button(control_frame, text="Generate Report", command=self.generate_report).pack(side=tk.RIGHT, padx=5)

    def _create_scan_results_section(self):
        """Create the scan results display"""
        pass  # Already handled in _create_main_panels

    def _create_log_viewer(self):
        """Create the logging/console section"""
        log_frame = ttk.Frame(self.root)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        ttk.Label(log_frame, text="System Logs", style='Title.TLabel').pack(anchor=tk.W)
        self.log_view = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10, bg='#2d2d2d', fg='white')
        self.log_view.pack(fill=tk.BOTH, expand=True)

    def _setup_logging_bridge(self):
        """Bridge Python logging to GUI log viewer"""
        class GUILogHandler(logging.Handler):
            def __init__(self, gui):
                super().__init__()
                self.gui = gui

            def emit(self, record):
                self.gui.log(self.format(record), record.levelname)

        handler = GUILogHandler(self)
        handler.setFormatter(logging.Formatter('%(message)s'))
        logging.getLogger().addHandler(handler)

    def load_dataset(self):
        """Load dataset for ML training"""
        if not self.ml_engine:
            messagebox.showerror("Error", "ML Engine not configured")
            return

        file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if not file_path:
            self.log("Dataset load canceled.")
            return

        try:
            import pandas as pd
            preview_df = pd.read_csv(file_path, nrows=1)
            columns = list(preview_df.columns)
        except Exception as e:
            self.log(f"Failed to preview columns: {e}", level="ERROR")
            self.scan_status.config(text="Preview failed")
            return

        def on_confirm():
            selected = combo.get()
            popup.destroy()
            try:
                self.ml_engine.load_dataset(file_path, label_column=selected)
                self.log(f"Dataset loaded: {file_path}")
                self.log(f"Features: {self.ml_engine.X.shape}, Labels: {self.ml_engine.y.shape}")
                self.scan_status.config(text="Dataset loaded")
            except Exception as e:
                self.log(f"Failed to load dataset: {e}", level="ERROR")
                self.scan_status.config(text="Dataset load failed")

        popup = tk.Toplevel(self.root)
        popup.title("Select Label Column")
        popup.geometry("300x100")
        tk.Label(popup, text="Select label column:").pack(pady=5)
        combo = ttk.Combobox(popup, values=columns, state="readonly")
        combo.set(columns[-1])  # Default to last
        combo.pack(pady=5)
        ttk.Button(popup, text="Confirm", command=on_confirm).pack(pady=5)

    def train_model(self):
        """Train ML model"""
        if not self.ml_engine:
            messagebox.showerror("Error", "ML Engine not configured")
            return

        try:
            datasets = list(self.ml_engine.datasets.keys())
            if not datasets:
                self.log("No dataset loaded for training", level="WARNING")
                return
            dataset_name = datasets[0]
            self.ml_engine.preprocess_dataset(dataset_name)
            self.ml_engine.train_model("random_forest", dataset_name=dataset_name)
            self.log("Model trained successfully.")
            self.scan_status.config(text="Model trained")
        except Exception as e:
            self.log(f"Model training failed: {e}", level="ERROR")
            self.scan_status.config(text="Training failed")

    def _update_system_stats(self):
        """Periodically update system resource gauges"""
        try:
            cpu_percent = psutil.cpu_percent()
            mem_percent = psutil.virtual_memory().percent
            
            self.cpu_gauge['value'] = cpu_percent
            self.mem_gauge['value'] = mem_percent
            
            # Update threat level based on system metrics
            threat_level = "Low"
            threat_color = "green"
            if cpu_percent > 80 or mem_percent > 80:
                threat_level = "High"
                threat_color = "red"
            elif cpu_percent > 60 or mem_percent > 60:
                threat_level = "Medium"
                threat_color = "orange"
            
            self.threat_level.config(text=threat_level, foreground=threat_color)
            self.sys_status.config(text=f"CPU: {cpu_percent}% | Mem: {mem_percent}%")
        except Exception as e:
            logging.error(f"Error updating system stats: {e}")
        
        self.root.after(2000, self._update_system_stats)

    def _update_process_list(self):
        """Update the process list periodically"""
        try:
            for item in self.process_list.get_children():
                self.process_list.delete(item)
                
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    self.process_list.insert('', 'end', values=(
                        proc.info['name'],
                        proc.info['pid'],
                        f"{proc.info['cpu_percent']:.1f}%"
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logging.error(f"Error updating process list: {e}")
        
        self.root.after(5000, self._update_process_list)

    def _process_scan_queue(self):
        """Process scan results from the queue"""
        try:
            while not self.scan_queue.empty():
                result = self.scan_queue.get_nowait()
                self._handle_scan_results(result)
        except Exception as e:
            logging.error(f"Error processing scan queue: {e}")
        
        self.root.after(100, self._process_scan_queue)

    def start_scan(self, scan_type):
        """Initiate a system scan"""
        if self.scan_active:
            messagebox.showwarning("Scan in Progress", "A scan is already running")
            return
        
        self.scan_cancelled = False
        self.scan_active = True
        self.log(f"Starting {scan_type} scan...")
        self.scan_status.config(text=f"Scanning: {scan_type} in progress")
        
        scan_thread = threading.Thread(
            target=self._run_scan_background,
            args=(scan_type,),
            daemon=True
        )
        scan_thread.start()
        

    def _run_scan_background(self, scan_type):
        """Background scan process"""
        try:
            if scan_type == 'quick':
                result = self.file_scanner.scan_directory(os.getcwd(), recursive=False)
            elif scan_type == 'full':
                result = self.file_scanner.scan_directory("C:\\" if sys.platform == 'win32' else "/", recursive=True)
            
            self.scan_queue.put(result)
        except Exception as e:
            self.log(f"Scan error: {str(e)}", level="ERROR")
        finally:
            self.scan_active = False
        if self.scan_cancelled:
            return

    def _handle_scan_results(self, results):
        """Process and display scan results with context-aware ML verdict"""
        self.root.after(0, lambda: self.scan_status.config(text=f"Last Scan: {datetime.now().strftime('%Y-%m-%d %H:%M')}"))

        threats_found = 0
        for item in results.get('scan_results', []):
            try:
                # Context-aware ML features
                system_metrics = self.system_monitor.get_usage_snapshot() if hasattr(self.system_monitor, 'get_usage_snapshot') else {}
                security_data = self.security_manager.get_suspicious_process_metrics() if hasattr(self.security_manager, 'get_suspicious_process_metrics') else {}
                network_data = self.network_sniffer.get_summary() if self.network_sniffer and hasattr(self.network_sniffer, 'get_summary') else {}

                feature_vector = aggregate_features(item, system_metrics, network_data, security_data)
                ml_verdict = self.ml_engine.predict(feature_vector) if self.ml_engine else True

                if ml_verdict:  # 1 = malicious
                    item['is_malicious'] = True
                    self._add_threat_to_display(item)
                    self.quarantine_manager.quarantine_file(
                        item['file_path'],
                        {'threat_type': 'adware', 'threat_level': item['threat_level']}
                    )
                    threats_found += 1

            except Exception as e:
                self.log(f"ML Prediction Error: {e}", level="ERROR")

        # Show scan summary
        self.threat_status.config(text=f"Threats Detected: {threats_found}")
        self.log(f"Scan completed: {threats_found} threats found")

        # Generate report if needed
        if threats_found > 0:
            try:
                report_path = self.report_generator.generate_report(results)
                self.log(f"Report generated: {report_path}")
            except Exception as e:
                self.log(f"Report generation error: {e}", level="ERROR")

        # Autorun threat detection
        try:
            if hasattr(self.security_manager, 'check_autorun_threats'):
                autorun_threats = self.security_manager.check_autorun_threats()
                if autorun_threats:
                    self.log("Autorun threats detected:\n" + "\n".join(autorun_threats))
                    notify_user("Autorun Threats Detected", "\n".join(autorun_threats[:3]))
                    for threat in autorun_threats:
                        self.threat_display.insert('', 'end', values=(
                            "Autorun Persistence",
                            "Medium",
                            threat
                        ))
        except Exception as e:
            self.log(f"Autorun threat check failed: {e}", level="ERROR")

            """
            severity    Background color    tag used
            High        Light Red           High
            Medium      Light Yellow        Medium
            Low         Light Green         Low
            """
    def _add_threat_to_display(self, threat_info):
        """Add detected threat to the threat display with severity-based row coloring"""
        detection = threat_info['detections'][0]
        
        threat_type = detection['type']
        severity = detection['severity'].capitalize()
        file_path = threat_info['file_path']

        tag = severity.lower()  # 'high', 'medium', 'low'

        self.threat_display.insert(
            '', 'end',
            values=(threat_type, severity, file_path),
            tags=(tag,)
        )
        if 'detections' not in threat_info or not threat_info['detections']:
            return



    def new_scan(self):
        """Initiate a new advanced adware scan with system context reset"""
        confirm = messagebox.askyesno(
            "Confirm New Scan", 
            "This will clear previous results and start a new full system scan.\nDo you want to continue?"
        )
        if not confirm:
            self.log("New scan cancelled by user.")
            return

        # Clear previous scan results
        for item in self.threat_display.get_children():
            self.threat_display.delete(item)
        self.threat_status.config(text="Threats Detected: 0")
        self.scan_status.config(text="Last Scan: Initializing...")

        self.log("Previous results cleared. Preparing for a new scan...")

        # Reset logs and quarantine info if needed
        self.log_view.delete('1.0', tk.END)
        if hasattr(self.quarantine_manager, 'clear_temp_quarantine'):
            self.quarantine_manager.clear_temp_quarantine()

        # Collect system metrics for context-aware scanning
        self.log("Collecting system metrics for intelligent scan.")
        try:
            system_metrics = self.system_monitor.collect_comprehensive_metrics()
            features = []
            if hasattr(self.security_manager, 'generate_security_context'):
                features = self.security_manager.generate_security_context(system_metrics)
            self.log("System context collected successfully.")
        except Exception as e:
            self.log(f"Error collecting system metrics: {e}", level="ERROR")
            features = []

        # Trigger scan with advanced analysis
        def threaded_scan():
            try:
                self.log("Starting comprehensive scan in background thread...")
                result = self.file_scanner.scan_directory(
                    "C:\\" if sys.platform == "win32" else "/", 
                    recursive=True, 
                    context_features=features
                )
                self.scan_queue.put(result)
            except Exception as e:
                self.log(f"New scan error: {str(e)}", level="ERROR")

        threading.Thread(target=threaded_scan, daemon=True).start()

    def stop_scan(self):
        """Stop the current scan"""
        if hasattr(self.file_scanner, 'stop_scan'):
            self.file_scanner.stop_scan()
            self.scan_active = False
            self.scan_cancelled = True
            self.log("Scan stopped by user")
            self.scan_status.config(text="Scan: Stopped by user")
        else:
            self.log("Stop scan not supported by current scanner", level="WARNING")

    def show_quarantine(self):
        """Display quarantine management window"""
        quarantine_win = tk.Toplevel(self.root)
        quarantine_win.title("Quarantine Management")
        quarantine_win.geometry("800x600")
        
        # List quarantined files
        q_frame = ttk.Frame(quarantine_win)
        q_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        q_list = ttk.Treeview(q_frame, columns=('id', 'path', 'date', 'threat'), show='headings')
        q_list.heading('id', text='ID')
        q_list.heading('path', text='Original Path')
        q_list.heading('date', text='Quarantine Date')
        q_list.heading('threat', text='Threat Type')
        q_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(q_frame, orient="vertical", command=q_list.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        q_list.configure(yscrollcommand=scrollbar.set)
        
        # Populate list
        for item in self.quarantine_manager.list_quarantined_files():
            q_list.insert('', 'end', values=(
                item['id'],
                item['original_path'],
                item['quarantine_date'],
                item.get('threat_info', {}).get('threat_type', 'Unknown')
            ))
        
        # Control buttons
        btn_frame = ttk.Frame(q_frame)
        btn_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5)
        
        ttk.Button(btn_frame, text="Restore", 
                  command=lambda: self._restore_file(q_list)).pack(pady=5)
        ttk.Button(btn_frame, text="Delete", 
                  command=lambda: self._delete_quarantine(q_list)).pack(pady=5)
        ttk.Button(btn_frame, text="Refresh", 
                  command=lambda: self._refresh_quarantine_list(q_list)).pack(pady=5)

    def _restore_file(self, q_list):
        """Restore selected file from quarantine"""
        selected = q_list.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a file to restore")
            return
        
        item = q_list.item(selected[0])
        file_id = item['values'][0]
        
        try:
            result = self.quarantine_manager.restore_file(file_id)
            if result:
                messagebox.showinfo("Success", f"File restored to: {result}")
                self._refresh_quarantine_list(q_list)
            else:
                messagebox.showerror("Error", "Failed to restore file")
        except Exception as e:
            messagebox.showerror("Error", f"Restore failed: {str(e)}")

    def _delete_quarantine(self, q_list):
        """Permanently delete quarantined file"""
        selected = q_list.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a file to delete")
            return
        
        item = q_list.item(selected[0])
        file_id = item['values'][0]
        
        confirm = messagebox.askyesno(
            "Confirm Delete", 
            "Permanently delete this quarantined file?\nThis cannot be undone."
        )
        if confirm:
            try:
                if self.quarantine_manager.delete_quarantined_file(file_id):
                    messagebox.showinfo("Success", "File permanently deleted")
                    self._refresh_quarantine_list(q_list)
                else:
                    messagebox.showerror("Error", "Failed to delete file")
            except Exception as e:
                messagebox.showerror("Error", f"Delete failed: {str(e)}")

    def _refresh_quarantine_list(self, q_list):
        """Refresh the quarantine list display"""
        for item in q_list.get_children():
            q_list.delete(item)
            
        for item in self.quarantine_manager.list_quarantined_files():
            q_list.insert('', 'end', values=(
                item['id'],
                item['original_path'],
                item['quarantine_date'],
                item.get('threat_info', {}).get('threat_type', 'Unknown')
            ))

    def generate_report(self):
        """Generate a report from current scan results"""
        try:
            # Get all displayed threats
            threats = []
            for item in self.threat_display.get_children():
                values = self.threat_display.item(item, 'values')
                threats.append({
                    'type': values[0],
                    'severity': values[1],
                    'path': values[2]
                })
            
            if not threats:
                messagebox.showinfo("No Threats", "No threats detected to generate report")
                return
            
            report_data = {
                'scan_date': datetime.now().isoformat(),
                'threats_found': len(threats),
                'threat_details': threats,
                'system_info': self.system_monitor.get_system_info()
            }
            
            report_path = self.report_generator.generate_report(report_data)
            messagebox.showinfo("Report Generated", f"Report saved to:\n{report_path}")
            self.log(f"Report generated: {report_path}")
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate report: {str(e)}")
            self.log(f"Report generation failed: {str(e)}", level="ERROR")

    def load_report(self):
        """Load a saved scan report"""
        file_path = filedialog.askopenfilename(filetypes=[("Report Files", "*.json *.txt")])
        if not file_path:
            return
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            self.log("Report loaded:")
            self.log(content)
        except Exception as e:
            self.log(f"Failed to load report: {e}", level="ERROR")
        with open(file_path, 'r') as f:
            if file_path.endswith('.json'):
                report = json.load(f)
                self.log(json.dumps(report, indent=2))
            else:
                self.log(f.read())

    def custom_scan(self):
        """Initiate a custom scan with user-defined parameters"""
        folder = filedialog.askdirectory()
        if not folder:
            self.log("Custom scan canceled.")
            return

        self.log(f"Starting custom scan in: {folder}")

        def run_custom():
            try:
                result = self.file_scanner.scan_directory(folder, recursive=True)
                self.log(f"Scan completed. Result: {result}")
            except Exception as e:
                self.log(f"Custom scan error: {e}", level="ERROR")

        threading.Thread(target=run_custom, daemon=True).start()

    def show_model_info(self):
        """Show information about the current ML model"""
        if not self.ml_engine:
            messagebox.showerror("Error", "ML Engine not configured")
            return

        try:
            info = self.ml_engine.get_model_info()
            messagebox.showinfo("Model Information", info)
        except Exception as e:
            messagebox.showerror("Error", f"Could not get model info: {str(e)}")

    def show_docs(self):
        """Show documentation"""
        # Implementation would display documentation
        messagebox.showinfo("Documentation", "Help documentation will be displayed here.")

    def show_about(self):
        """Show about dialog"""
        about_win = tk.Toplevel(self.root)
        about_win.title("About")
        about_win.geometry("400x300")
        
        ttk.Label(about_win, text="AdvoShield - Adware Detection", 
                 font=('Helvetica', 12, 'bold')).pack(pady=10)
        ttk.Label(about_win, text="Version 2.0").pack()
        ttk.Label(about_win, text="\nAdvanced threat detection and removal tool\n").pack()
        ttk.Label(about_win, text="© 2023 Security Solutions Inc.").pack(side=tk.BOTTOM, pady=10)

    def log(self, message, level="INFO"):
        """Add entry to log viewer and threat feed"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_view.insert(tk.END, f"[{timestamp}] {level}: {message}\n")
        self.log_view.see(tk.END)

        # Also log to Python logging system
        if level == "ERROR":
            logging.error(message)
        elif level == "WARNING":
            logging.warning(message)
        else:
            logging.info(message)

        # ✅ Push to live threat feed if relevant
        if "threat" in message.lower() or "quarantined" in message.lower():
            self._push_threat_feed(message)

    def _check_network_alerts(self):
        """Fetch and process alerts from NetworkSniffer."""
        try:
            if self.network_sniffer:
                alerts = self.network_sniffer.get_alerts()
                for alert in alerts:
                    # GUI Log
                    self.log(alert, level="WARNING")

                    # Threat display
                    self.threat_display.insert('', 'end', values=(
                        "Network Activity", "Medium", alert
                    ))

                    # Popup alert
                    notify_user("Suspicious Network Activity", alert)
        except Exception as e:
            self.log(f"Network sniffer error: {e}", level="ERROR")

        self.root.after(5000, self._check_network_alerts)

    def _check_lockdown_flag(self):
        if os.path.exists("lockdown.flag"):
            self.lockdown_banner.config(text="🚨 SYSTEM IN QUARANTINE MODE — ACTIONS DISABLED")
            self._disable_critical_ui()
        else:
            self.lockdown_banner.config(text="")

        self.root.after(5000, self._check_lockdown_flag)
    def _disable_critical_ui(self):
        for child in self.root.winfo_children():
            if isinstance(child, ttk.Button):
                child.config(state="disabled")

    def _push_threat_feed(self, entry: str):
        self.threat_feed.insert(0, entry)
        if self.threat_feed.size() > 4:
            self.threat_feed.delete(tk.END)


    def run(self):
        """Start the GUI main loop"""
        self.root.mainloop()