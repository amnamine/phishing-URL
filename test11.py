import tkinter as tk
from tkinter import ttk, scrolledtext
import requests
import socket
import ssl
import websockets
import asyncio
import re
import whois
from urllib.parse import urlparse
import threading
import json

class PhishingDetector:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Advanced Phishing URL Detector")
        self.root.geometry("800x600")
        
        self.setup_gui()
        self.websocket = None
        self.blacklist_cache = set()
        
    def setup_gui(self):
        # URL Input
        input_frame = ttk.LabelFrame(self.root, text="URL Analysis", padding=10)
        input_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(input_frame, text="Enter URL:").pack()
        self.url_entry = ttk.Entry(input_frame, width=60)
        self.url_entry.pack(pady=5)
        
        # Analysis buttons
        btn_frame = ttk.Frame(input_frame)
        btn_frame.pack(pady=5)
        
        ttk.Button(btn_frame, text="Quick Scan", 
                  command=self.quick_scan).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Deep Analysis", 
                  command=self.deep_analysis).pack(side="left", padx=5)
        
        # Results area
        results_frame = ttk.LabelFrame(self.root, text="Analysis Results", padding=10)
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=20)
        self.results_text.pack(fill="both", expand=True)
        
    async def check_websocket_security(self, url):
        try:
            async with websockets.connect(f"wss://{urlparse(url).netloc}") as websocket:
                return True
        except:
            return False
            
    def analyze_ip(self, hostname):
        try:
            ip = socket.gethostbyname(hostname)
            # Check if IP is private
            ip_parts = ip.split('.')
            if ip_parts[0] == "10" or \
               (ip_parts[0] == "172" and 16 <= int(ip_parts[1]) <= 31) or \
               (ip_parts[0] == "192" and ip_parts[1] == "168"):
                return False, f"Warning: Private IP detected ({ip})"
                
            # Check IP reputation
            response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
                                 headers={"Key": "YOUR_API_KEY"})
            if response.status_code == 200:
                data = response.json()
                if data.get("data", {}).get("abuseConfidenceScore", 0) > 50:
                    return False, f"Warning: IP has bad reputation score"
                    
            return True, f"IP check passed: {ip}"
        except Exception as e:
            return False, f"IP analysis error: {str(e)}"
            
    def check_ssl(self, url):
        try:
            hostname = urlparse(url).netloc
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
                sock.connect((hostname, 443))
                cert = sock.getpeercert()
                
                # Check certificate validity
                if not cert:
                    return False, "Invalid SSL certificate"
                    
                # Check certificate age
                import datetime
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if not_after < datetime.datetime.now():
                    return False, "Expired SSL certificate"
                    
                return True, "Valid SSL certificate"
        except Exception as e:
            return False, f"SSL verification failed: {str(e)}"
            
    def quick_scan(self):
        url = self.url_entry.get()
        self.results_text.delete(1.0, tk.END)
        
        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            self.results_text.insert(tk.END, "Error: Invalid URL format\n")
            return
            
        # Start analysis in thread to prevent GUI freezing
        threading.Thread(target=self.run_quick_analysis, args=(url,)).start()
        
    def run_quick_analysis(self, url):
        self.append_result("Starting quick analysis...\n")
        
        # Check domain age
        try:
            domain = whois.whois(urlparse(url).netloc)
            if domain.creation_date:
                creation_date = domain.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                age = (datetime.datetime.now() - creation_date).days
                if age < 30:
                    self.append_result(f"Warning: Domain is only {age} days old\n")
        except:
            self.append_result("Warning: Could not verify domain age\n")
            
        # Check URL characteristics
        suspicious_patterns = [
            r'paypal.*\.com',
            r'bank.*\.tk',
            r'.*\.php\?id=.*',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                self.append_result(f"Warning: Suspicious URL pattern detected\n")
                break
                
        # Run IP analysis
        success, message = self.analyze_ip(urlparse(url).netloc)
        self.append_result(f"IP Analysis: {message}\n")
        
    def deep_analysis(self):
        url = self.url_entry.get()
        self.results_text.delete(1.0, tk.END)
        
        # Start analysis in thread
        threading.Thread(target=self.run_deep_analysis, args=(url,)).start()
        
    def run_deep_analysis(self, url):
        self.append_result("Starting deep analysis...\n")
        
        # Run all checks
        self.quick_scan()
        
        # Additional SSL verification
        success, message = self.check_ssl(url)
        self.append_result(f"SSL Check: {message}\n")
        
        # Check for websocket security
        asyncio.run(self.check_websocket_security(url))
        
        # Content analysis
        try:
            response = requests.get(url, timeout=5)
            content = response.text.lower()
            
            # Check for suspicious forms
            if 'password' in content and 'credit card' in content:
                self.append_result("Warning: Page contains sensitive input forms\n")
                
            # Check response headers
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options'
            ]
            
            missing_headers = [header for header in security_headers 
                             if header not in response.headers]
            if missing_headers:
                self.append_result(f"Warning: Missing security headers: {', '.join(missing_headers)}\n")
                
        except Exception as e:
            self.append_result(f"Error during content analysis: {str(e)}\n")
            
    def append_result(self, message):
        self.results_text.insert(tk.END, message)
        self.results_text.see(tk.END)
        
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    detector = PhishingDetector()
    detector.run()
