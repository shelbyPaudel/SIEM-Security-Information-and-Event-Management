SIEM Security Log Monitor
A lightweight, real-time Security Information and Event Management (SIEM) tool built with Python and Tkinter. It monitors system logs and shell history files to detect suspicious activities such as privilege escalation, critical file access, and failed authentication attempts.

Features
1. Real-time monitoring of log files (system logs, .zsh_history, .bash_history)
2. Multi-threaded architecture for non-blocking GUI
3. Threat detection using pattern matching
4. Severity classification: INFO, LOW, MEDIUM, HIGH, CRITICAL
5. Color-coded alerts and live statistics dashboard
6. Export alerts to JSON
7. Auto-refresh for Zsh history (fc -W integration)

Technology
Python 3.8+, Tkinter, threading, regex, JSON

Installation
Clone the repository:
  git clone https://github.com/yourusername/siem-log-monitor.git
  cd siem-log-monitor

(Linux) Ensure Tkinter is installed:
  sudo apt-get install python3-tk   # Debian/Ubuntu

Run the application:
  python3 siem_monitor.py

Usage
  1. Select a log file (use quick-select buttons or browse)
  2. Click Start Monitoring
  3. View real-time logs and alerts in the GUI
  4. Enable auto fc -W for Zsh history updates
  5. Export alerts via the Export button

