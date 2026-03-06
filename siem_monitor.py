import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime
import re
import json
import threading
import time
import os
import subprocess

class LogAnalyzer:
    """Analyzes logs for suspicious activities"""
    
    def __init__(self):
        self.suspicious_commands = [
            'sudo su', 'su -', 'su ', 'whoami', 'chmod 777', 'chmod +x', 'rm -rf',
            'wget', 'curl', 'nc -', 'nc ', 'netcat', '/bin/bash', '/bin/sh',
            'useradd', 'usermod', 'passwd', 'chown root', 'chgrp root',
            'iptables', 'ufw', 'systemctl', 'service ', 'kill -9',
            'pkill', 'nmap', 'tcpdump', 'wireshark', 'hydra',
            'john', 'aircrack', 'metasploit', 'msfconsole',
            'python -m http.server', 'python -m SimpleHTTPServer',-
            'base64', 'echo ', 'eval', 'exec', '&&', '||', ';',
            'bash -i', 'sh -i', '/dev/tcp', 'mkfifo'
        ]
        
        self.critical_files = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '/etc/hosts', '/etc/ssh/sshd_config', '/root/',
            '/etc/crontab', '/var/log/', '/boot/'
        ]
        
        self.severity_levels = {
            'CRITICAL': '#ff0000',
            'HIGH': '#ff6600',
            'MEDIUM': '#ffaa00',
            'LOW': '#ffff00',
            'INFO': '#00ff00'
        }
    
    def analyze_log_entry(self, log_entry):
        """Analyze a single log entry for threats"""
        threats = []
        severity = 'INFO'
        
        # Handle zsh history format (: timestamp:0;command)
        cleaned_log = log_entry
        if log_entry.startswith(':') and ';' in log_entry:
            # Extract command from zsh history format
            parts = log_entry.split(';', 1)
            if len(parts) > 1:
                cleaned_log = parts[1].strip()
        
        log_lower = cleaned_log.lower()
        
        # Check for suspicious commands
        for cmd in self.suspicious_commands:
            if cmd.lower() in log_lower:
                threats.append(f"Suspicious command detected: {cmd}")
                severity = self._escalate_severity(severity, 'HIGH')
        
        # Check for critical file access
        for file_path in self.critical_files:
            if file_path.lower() in log_lower:
                threats.append(f"Critical file access: {file_path}")
                severity = self._escalate_severity(severity, 'CRITICAL')
        
        # Check for failed authentication
        if any(term in log_lower for term in ['failed', 'failure', 'denied', 'invalid']):
            if any(auth in log_lower for auth in ['password', 'authentication', 'login']):
                threats.append("Failed authentication attempt")
                severity = self._escalate_severity(severity, 'MEDIUM')
        
        # Check for privilege escalation
        if 'sudo' in log_lower or ('su ' in log_lower):
            threats.append("Privilege escalation detected")
            severity = self._escalate_severity(severity, 'HIGH')
        
        return {
            'log': cleaned_log if cleaned_log != log_entry else log_entry,
            'original': log_entry,
            'threats': threats,
            'severity': severity,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def _escalate_severity(self, current, new):
        """Escalate severity level"""
        levels = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        current_idx = levels.index(current)
        new_idx = levels.index(new)
        return levels[max(current_idx, new_idx)]


class AlertManager:
    """Manages security alerts and statistics"""
    
    def __init__(self):
        self.alerts = []
        self.stats = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
    
    def add_alert(self, alert_data):
        """Add new alert"""
        self.alerts.append(alert_data)
        self.stats[alert_data['severity']] += 1
    
    def get_recent_alerts(self, count=10):
        """Get most recent alerts"""
        return self.alerts[-count:]
    
    def get_statistics(self):
        """Get alert statistics"""
        return self.stats
    
    def export_alerts(self, filename):
        """Export alerts to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.alerts, f, indent=4)
            return True
        except Exception as e:
            return False


class FileMonitor:
    """Smart file monitor that handles different file types"""
    
    def __init__(self, callback):
        self.callback = callback
        self.monitoring = False
        self.monitor_thread = None
        self.log_file_path = None
        self.last_position = 0
        self.file_size = 0
        self.processed_lines = set()
        self.is_shell_history = False
        self.check_interval = 1.0  # Default check interval
    
    def start_monitoring(self, file_path):
        """Start monitoring the log file"""
        # Expand home directory path
        file_path = os.path.expanduser(file_path)
        
        if not os.path.exists(file_path):
            return False, "File does not exist"
        
        try:
            # Detect if this is a shell history file
            self.is_shell_history = self._is_shell_history_file(file_path)
            
            # Test if file is readable and get initial state
            with open(file_path, 'r', errors='ignore') as f:
                # For syslog, start from current position (like original code)
                # For history, read all
                if self.is_shell_history:
                    self.last_position = 0  # Start from beginning for history
                else:
                    self.last_position = f.tell()  # Start from current position for syslog
                
                self.file_size = os.path.getsize(file_path)
            
            self.log_file_path = file_path
            self.monitoring = True
            
            # Set check interval - use 1 second for both (like original code)
            self.check_interval = 1.0
            
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            
            file_type = "Shell History" if self.is_shell_history else "System Log"
            return True, f"Monitoring started ({file_type} mode)"
        except PermissionError:
            return False, "Permission denied. Try running as sudo or use a different file."
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def _is_shell_history_file(self, file_path):
        """Detect if file is a shell history file"""
        history_patterns = ['.zsh_history', '.bash_history', '.history', 'history']
        return any(pattern in file_path.lower() for pattern in history_patterns)
    
    def stop_monitoring(self):
        """Stop monitoring the log file"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
    
    def force_reload(self):
        """Force reload the entire file from current position"""
        if not self.log_file_path or not self.monitoring:
            return 0
        
        new_lines_count = 0
        try:
            current_size = os.path.getsize(self.log_file_path)
            if current_size != self.file_size or current_size > self.last_position:
                self.file_size = current_size
                with open(self.log_file_path, 'r', errors='ignore') as f:
                    f.seek(self.last_position)
                    new_lines = f.readlines()
                    self.last_position = f.tell()
                    
                    for line in new_lines:
                        line_stripped = line.strip()
                        if line_stripped and line_stripped not in self.processed_lines:
                            self.processed_lines.add(line_stripped)
                            self.callback(line_stripped)
                            new_lines_count += 1
                            
                            # Limit processed_lines size
                            if len(self.processed_lines) > 10000:
                                self.processed_lines.clear()
        except Exception as e:
            print(f"Force reload error: {e}")
        
        return new_lines_count
    
    def _monitor_loop(self):
        """Main monitoring loop - exactly like original code"""
        while self.monitoring:
            try:
                with open(self.log_file_path, 'r', errors='ignore') as f:
                    # Move to last read position
                    f.seek(self.last_position)
                    
                    # Read new lines
                    new_lines = f.readlines()
                    
                    # Update position
                    self.last_position = f.tell()
                    
                    # Process new lines
                    for line in new_lines:
                        if line.strip():
                            self.callback(line.strip())
                
                # Sleep - check every second like original code
                time.sleep(1)
                
            except Exception as e:
                print(f"Monitor error: {e}")
                time.sleep(2)


class SIEMApplication:
    """Main SIEM Application with GUI"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("SIEM - Security Information and Event Management")
        self.root.geometry("1200x900")
        self.root.configure(bg='#1e1e1e')
        
        self.analyzer = LogAnalyzer()
        self.alert_manager = AlertManager()
        self.file_monitor = FileMonitor(self.process_log_line)
        
        self.monitoring_active = False
        self.auto_fc_active = False
        self.fc_thread = None
        self.default_syslog_path = "/var/log/installer/syslog"
        
        self.setup_ui()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_ui(self):
        """Setup user interface"""
        # Title
        title_frame = tk.Frame(self.root, bg='#2d2d2d', pady=10)
        title_frame.pack(fill=tk.X)
        
        title_label = tk.Label(
            title_frame,
            text="🛡️ SIEM - Security Log Monitor",
            font=('Arial', 20, 'bold'),
            bg='#2d2d2d',
            fg='#00ff00'
        )
        title_label.pack()
        
        # Monitoring Control Panel
        monitor_frame = tk.Frame(self.root, bg='#2d2d2d', pady=10)
        monitor_frame.pack(fill=tk.X, padx=10)
        
        tk.Label(
            monitor_frame,
            text="File Path:",
            font=('Arial', 10),
            bg='#2d2d2d',
            fg='white'
        ).pack(side=tk.LEFT, padx=5)
        
        self.syslog_path_entry = tk.Entry(
            monitor_frame,
            font=('Arial', 10),
            bg='#1e1e1e',
            fg='white',
            insertbackground='white',
            width=40
        )
        self.syslog_path_entry.insert(0, self.default_syslog_path)
        self.syslog_path_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            monitor_frame,
            text="Browse",
            command=self.browse_syslog,
            bg='#607D8B',
            fg='white',
            font=('Arial', 10),
            padx=10,
            pady=5
        ).pack(side=tk.LEFT, padx=5)
        
        self.monitor_btn = tk.Button(
            monitor_frame,
            text="▶ Start Monitoring",
            command=self.toggle_monitoring,
            bg='#4CAF50',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=20,
            pady=5
        )
        self.monitor_btn.pack(side=tk.LEFT, padx=5)
        
        self.status_label = tk.Label(
            monitor_frame,
            text="● Stopped",
            font=('Arial', 10, 'bold'),
            bg='#2d2d2d',
            fg='#ff0000'
        )
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # FC-W Control Frame (for shell history)
        fc_frame = tk.Frame(self.root, bg='#2d2d2d', pady=5)
        fc_frame.pack(fill=tk.X, padx=10)
        
        self.fc_enable_var = tk.BooleanVar(value=False)
        self.fc_checkbox = tk.Checkbutton(
            fc_frame,
            text="Enable auto fc -W for shell history (every 10 seconds)",
            variable=self.fc_enable_var,
            command=self.toggle_fc_mode,
            font=('Arial', 10),
            bg='#2d2d2d',
            fg='#ffaa00',
            selectcolor='#1e1e1e',
            activebackground='#2d2d2d',
            activeforeground='#ffaa00'
        )
        self.fc_checkbox.pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            fc_frame,
            text="Run fc -W Now",
            command=self.manual_fc,
            bg='#9C27B0',
            fg='white',
            font=('Arial', 9),
            padx=15,
            pady=3
        ).pack(side=tk.LEFT, padx=5)
        
        self.fc_status_label = tk.Label(
            fc_frame,
            text="",
            font=('Arial', 9),
            bg='#2d2d2d',
            fg='#00ff00'
        )
        self.fc_status_label.pack(side=tk.LEFT, padx=10)
        
        # Quick file selection buttons
        quick_frame = tk.Frame(self.root, bg='#2d2d2d', pady=5)
        quick_frame.pack(fill=tk.X, padx=10)
        
        tk.Label(
            quick_frame,
            text="Quick Select:",
            font=('Arial', 9),
            bg='#2d2d2d',
            fg='#aaaaaa'
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            quick_frame,
            text="Syslog",
            command=lambda: self.set_file_path("/var/log/installer/syslog"),
            bg='#455A64',
            fg='white',
            font=('Arial', 9),
            padx=10,
            pady=3
        ).pack(side=tk.LEFT, padx=2)
        
        tk.Button(
            quick_frame,
            text="Zsh History",
            command=lambda: self.set_file_path("~/.zsh_history"),
            bg='#455A64',
            fg='white',
            font=('Arial', 9),
            padx=10,
            pady=3
        ).pack(side=tk.LEFT, padx=2)
        
        tk.Button(
            quick_frame,
            text="Bash History",
            command=lambda: self.set_file_path("~/.bash_history"),
            bg='#455A64',
            fg='white',
            font=('Arial', 9),
            padx=10,
            pady=3
        ).pack(side=tk.LEFT, padx=2)
        
        tk.Button(
            quick_frame,
            text="Auth Log",
            command=lambda: self.set_file_path("/var/log/auth.log"),
            bg='#455A64',
            fg='white',
            font=('Arial', 9),
            padx=10,
            pady=3
        ).pack(side=tk.LEFT, padx=2)
        
        # Control Panel
        control_frame = tk.Frame(self.root, bg='#2d2d2d', pady=10)
        control_frame.pack(fill=tk.X, padx=10)
        
        tk.Button(
            control_frame,
            text="Load & Analyze File",
            command=self.load_log_file,
            bg='#2196F3',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=20,
            pady=5
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            control_frame,
            text="Analyze Entry",
            command=self.analyze_manual_entry,
            bg='#2196F3',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=20,
            pady=5
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            control_frame,
            text="Clear Alerts",
            command=self.clear_alerts,
            bg='#f44336',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=20,
            pady=5
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            control_frame,
            text="Export Alerts",
            command=self.export_alerts,
            bg='#FF9800',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=20,
            pady=5
        ).pack(side=tk.LEFT, padx=5)
        
        # Main content area
        content_frame = tk.Frame(self.root, bg='#1e1e1e')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel - Log input
        left_frame = tk.Frame(content_frame, bg='#2d2d2d')
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        tk.Label(
            left_frame,
            text="Log Entry Input / Live Monitor",
            font=('Arial', 12, 'bold'),
            bg='#2d2d2d',
            fg='white'
        ).pack(pady=5)
        
        self.log_input = scrolledtext.ScrolledText(
            left_frame,
            wrap=tk.WORD,
            font=('Courier', 9),
            bg='#1e1e1e',
            fg='#00ff00',
            insertbackground='white',
            height=15
        )
        self.log_input.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Right panel - Statistics
        right_frame = tk.Frame(content_frame, bg='#2d2d2d', width=300)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        right_frame.pack_propagate(False)
        
        tk.Label(
            right_frame,
            text="Alert Statistics",
            font=('Arial', 12, 'bold'),
            bg='#2d2d2d',
            fg='white'
        ).pack(pady=5)
        
        self.stats_frame = tk.Frame(right_frame, bg='#2d2d2d')
        self.stats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bottom panel - Alerts display
        bottom_frame = tk.Frame(self.root, bg='#2d2d2d')
        bottom_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        alert_header = tk.Frame(bottom_frame, bg='#2d2d2d')
        alert_header.pack(fill=tk.X, pady=5)
        
        tk.Label(
            alert_header,
            text="Security Alerts",
            font=('Arial', 12, 'bold'),
            bg='#2d2d2d',
            fg='white'
        ).pack(side=tk.LEFT, padx=5)
        
        self.alert_count_label = tk.Label(
            alert_header,
            text="(0 alerts)",
            font=('Arial', 10),
            bg='#2d2d2d',
            fg='#ffaa00'
        )
        self.alert_count_label.pack(side=tk.LEFT)
        
        self.alerts_display = scrolledtext.ScrolledText(
            bottom_frame,
            wrap=tk.WORD,
            font=('Courier', 9),
            bg='#1e1e1e',
            fg='white',
            height=15
        )
        self.alerts_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.setup_alert_tags()
        self.update_statistics()
    
    def setup_alert_tags(self):
        """Setup text tags for different severity levels"""
        for severity, color in self.analyzer.severity_levels.items():
            self.alerts_display.tag_config(severity, foreground=color, font=('Courier', 9, 'bold'))
            self.log_input.tag_config(severity, foreground=color, font=('Courier', 9, 'bold'))
    
    def set_file_path(self, path):
        """Set file path in entry field"""
        self.syslog_path_entry.delete(0, tk.END)
        self.syslog_path_entry.insert(0, path)
    
    def browse_syslog(self):
        """Browse for syslog file"""
        filename = filedialog.askopenfilename(
            title="Select Log/History File",
            initialdir="/var/log",
            filetypes=[("Log files", "*.log"), ("History files", "*history"), ("All files", "*.*")]
        )
        
        if filename:
            self.syslog_path_entry.delete(0, tk.END)
            self.syslog_path_entry.insert(0, filename)
    
    def toggle_monitoring(self):
        """Toggle file monitoring"""
        if not self.monitoring_active:
            # Start monitoring
            file_path = self.syslog_path_entry.get().strip()
            success, message = self.file_monitor.start_monitoring(file_path)
            
            if success:
                self.monitoring_active = True
                self.monitor_btn.config(text="⏸ Stop Monitoring", bg='#f44336')
                self.status_label.config(text="● Monitoring", fg='#00ff00')
                self.log_input.insert(tk.END, f"\n{'='*60}\n")
                self.log_input.insert(tk.END, f"[SYSTEM] {message}\n", 'INFO')
                self.log_input.insert(tk.END, f"[SYSTEM] File: {os.path.expanduser(file_path)}\n", 'INFO')
                
                # Show hint for shell history
                if self.file_monitor.is_shell_history:
                    self.log_input.insert(tk.END, f"[SYSTEM] TIP: Enable 'auto fc -W' for automatic updates\n", 'INFO')
                
                self.log_input.insert(tk.END, f"{'='*60}\n\n")
                self.log_input.see(tk.END)
            else:
                messagebox.showerror("Monitoring Error", message)
        else:
            # Stop monitoring
            self.file_monitor.stop_monitoring()
            self.monitoring_active = False
            self.monitor_btn.config(text="▶ Start Monitoring", bg='#4CAF50')
            self.status_label.config(text="● Stopped", fg='#ff0000')
            self.log_input.insert(tk.END, f"\n[SYSTEM] Monitoring stopped\n\n", 'INFO')
            self.log_input.see(tk.END)
    
    def toggle_fc_mode(self):
        """Toggle automatic fc -W execution"""
        if self.fc_enable_var.get():
            # Start auto fc -W
            self.auto_fc_active = True
            self.fc_thread = threading.Thread(target=self._fc_loop, daemon=True)
            self.fc_thread.start()
            self.fc_status_label.config(text="✓ Auto fc -W enabled")
            self.log_input.insert(tk.END, f"[SYSTEM] Auto fc -W enabled (every 10 seconds)\n", 'INFO')
            self.log_input.see(tk.END)
        else:
            # Stop auto fc -W
            self.auto_fc_active = False
            self.fc_status_label.config(text="")
            self.log_input.insert(tk.END, f"[SYSTEM] Auto fc -W disabled\n", 'INFO')
            self.log_input.see(tk.END)
    
    def _fc_loop(self):
        """Background loop to run fc -W periodically"""
        while self.auto_fc_active:
            try:
                # Run fc -W command
                result = subprocess.run(
                    ['zsh', '-c', 'fc -W'],
                    capture_output=True,
                    timeout=3
                )
                
                # Force reload monitored file
                if self.monitoring_active:
                    count = self.file_monitor.force_reload()
                    if count > 0:
                        self.root.after(0, self._update_fc_status, f"✓ Loaded {count} new entries")
                
                time.sleep(10)  # Wait 10 seconds
            except Exception as e:
                print(f"fc -W error: {e}")
                time.sleep(10)
    
    def _update_fc_status(self, message):
        """Update fc status label"""
        self.fc_status_label.config(text=message)
        self.root.after(3000, lambda: self.fc_status_label.config(text="✓ Auto fc -W enabled"))
    
    def manual_fc(self):
        """Manually run fc -W and reload"""
        try:
            # Run fc -W
            subprocess.run(['zsh', '-c', 'fc -W'], capture_output=True, timeout=3)
            
            # Force reload
            if self.monitoring_active:
                count = self.file_monitor.force_reload()
                messagebox.showinfo("Success", f"fc -W executed\nLoaded {count} new entries")
            else:
                messagebox.showinfo("Success", "fc -W executed\nStart monitoring to see results")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run fc -W: {str(e)}")
    
    def process_log_line(self, log_line):
        """Process a log line from real-time monitoring"""
        # Thread-safe GUI update
        self.root.after(0, self._process_log_line_gui, log_line)
    
    def _process_log_line_gui(self, log_line):
        """GUI update for processing log line"""
        result = self.analyzer.analyze_log_entry(log_line)
        
        # Display in log monitor
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_input.insert(tk.END, f"[{timestamp}] {log_line}\n")
        
        # If threats detected, create alert
        if result['threats']:
            self.alert_manager.add_alert(result)
            self.display_alert(result)
            self.update_statistics()
            
            # Visual/audio notification for critical alerts
            if result['severity'] in ['CRITICAL', 'HIGH']:
                self.root.bell()  # System beep
        
        # Auto-scroll and limit log display size
        self.log_input.see(tk.END)
        
        # Keep only last 1000 lines in log monitor
        line_count = int(self.log_input.index('end-1c').split('.')[0])
        if line_count > 1000:
            self.log_input.delete(1.0, f"{line_count-1000}.0")
    
    def load_log_file(self):
        """Load and analyze log file"""
        filename = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("Log files", "*.log"), ("History files", "*history"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r', errors='ignore') as f:
                    logs = f.readlines()
                
                self.log_input.delete(1.0, tk.END)
                threat_count = 0
                
                for log in logs:
                    if log.strip():
                        result = self.analyzer.analyze_log_entry(log)
                        if result['threats']:
                            threat_count += 1
                            self.alert_manager.add_alert(result)
                            self.display_alert(result)
                
                self.update_statistics()
                messagebox.showinfo("Analysis Complete", 
                    f"Analyzed {len(logs)} log entries\nThreats detected: {threat_count}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def analyze_manual_entry(self):
        """Analyze manually entered log"""
        log_entry = self.log_input.get(1.0, tk.END).strip()
        
        if not log_entry:
            messagebox.showwarning("Warning", "Please enter a log entry to analyze")
            return
        
        result = self.analyzer.analyze_log_entry(log_entry)
        
        if result['threats']:
            self.alert_manager.add_alert(result)
            self.display_alert(result)
            self.update_statistics()
        else:
            self.alerts_display.insert(tk.END, f"\n[{result['timestamp']}] ", 'INFO')
            self.alerts_display.insert(tk.END, "No threats detected\n", 'INFO')
            self.alerts_display.see(tk.END)
    
    def display_alert(self, alert_data):
        """Display alert in the alerts panel"""
        timestamp = alert_data['timestamp']
        severity = alert_data['severity']
        
        self.alerts_display.insert(tk.END, f"\n{'='*80}\n")
        self.alerts_display.insert(tk.END, f"[{timestamp}] ", severity)
        self.alerts_display.insert(tk.END, f"🚨 SEVERITY: {severity}\n", severity)
        self.alerts_display.insert(tk.END, f"Log: {alert_data['log'][:100]}...\n")
        self.alerts_display.insert(tk.END, "Threats Detected:\n", severity)
        
        for threat in alert_data['threats']:
            self.alerts_display.insert(tk.END, f"  ⚠️  {threat}\n", severity)
        
        self.alerts_display.see(tk.END)
        
        # Update alert count
        total_alerts = sum(self.alert_manager.get_statistics().values())
        self.alert_count_label.config(text=f"({total_alerts} alerts)")
    
    def update_statistics(self):
        """Update statistics display"""
        for widget in self.stats_frame.winfo_children():
            widget.destroy()
        
        stats = self.alert_manager.get_statistics()
        
        for severity, count in stats.items():
            frame = tk.Frame(self.stats_frame, bg='#2d2d2d')
            frame.pack(fill=tk.X, pady=5)
            
            color = self.analyzer.severity_levels[severity]
            
            tk.Label(
                frame,
                text=f"{severity}:",
                font=('Arial', 11, 'bold'),
                bg='#2d2d2d',
                fg=color,
                width=10,
                anchor='w'
            ).pack(side=tk.LEFT, padx=5)
            
            tk.Label(
                frame,
                text=str(count),
                font=('Arial', 11, 'bold'),
                bg='#2d2d2d',
                fg=color
            ).pack(side=tk.LEFT)
        
        # Total
        total_frame = tk.Frame(self.stats_frame, bg='#2d2d2d')
        total_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(
            total_frame,
            text="TOTAL:",
            font=('Arial', 12, 'bold'),
            bg='#2d2d2d',
            fg='white',
            width=10,
            anchor='w'
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Label(
            total_frame,
            text=str(sum(stats.values())),
            font=('Arial', 12, 'bold'),
            bg='#2d2d2d',
            fg='white'
        ).pack(side=tk.LEFT)
    
    def clear_alerts(self):
        """Clear all alerts"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all alerts?"):
            self.alerts_display.delete(1.0, tk.END)
            self.alert_manager = AlertManager()
            self.update_statistics()
            self.alert_count_label.config(text="(0 alerts)")
    
    def export_alerts(self):
        """Export alerts to file"""
        filename = filedialog.asksaveasfilename(
            title="Export Alerts",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            if self.alert_manager.export_alerts(filename):
                messagebox.showinfo("Success", f"Alerts exported to {filename}")
            else:
                messagebox.showerror("Error", "Failed to export alerts")
    
    def on_closing(self):
        """Handle window close event"""
        if self.monitoring_active:
            self.file_monitor.stop_monitoring()
        self.auto_fc_active = False
        self.root.destroy()


def main():
    root = tk.Tk()
    app = SIEMApplication(root)
    root.mainloop()


if __name__ == "__main__":
    main()