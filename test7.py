import tkinter as tk
from tkinter import ttk
from urllib.parse import urlparse
import re
import requests
from tld import get_tld
import ssl
import socket
import whois
from datetime import datetime

class PhishingDetector:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Advanced Phishing URL Detector")
        self.root.geometry("800x600")
        self.root.configure(bg='#2c3e50')

        # URL Input
        self.url_frame = ttk.LabelFrame(self.root, text="URL Analysis", padding=10)
        self.url_frame.pack(fill="x", padx=20, pady=10)

        self.url_entry = ttk.Entry(self.url_frame, width=50)
        self.url_entry.pack(side=tk.LEFT, padx=5)

        self.scan_btn = ttk.Button(self.url_frame, text="Scan URL", command=self.analyze_url)
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        # Results Area
        self.result_text = tk.Text(self.root, height=20, width=70, bg='#ecf0f1')
        self.result_text.pack(pady=10)

    def check_suspicious_elements(self, url):
        suspicious_patterns = [
            r'@',
            r'//.*@',
            r'\.{2,}',
            r'-{2,}',
            r'payload',
            r'admin',
            r'login',
            r'banking',
            r'account',
            r'secure',
            r'update'
        ]
        return any(re.search(pattern, url.lower()) for pattern in suspicious_patterns)

    def check_ssl_cert(self, domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return True, cert['notAfter']
        except:
            return False, None

    def analyze_url(self):
        self.result_text.delete(1.0, tk.END)
        url = self.url_entry.get()
        
        try:
            # Basic URL parsing
            parsed = urlparse(url)
            domain = parsed.netloc

            # Domain age check
            try:
                w = whois.whois(domain)
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                domain_age = (datetime.now() - creation_date).days
            except:
                domain_age = None

            # SSL Check
            has_ssl, ssl_expiry = self.check_ssl_cert(domain)

            # Analyze and display results
            self.result_text.insert(tk.END, "=== URL Analysis Results ===\n\n")
            
            risk_score = 0
            
            # Check URL length
            if len(url) > 75:
                self.result_text.insert(tk.END, "⚠️ Long URL detected (Suspicious)\n")
                risk_score += 20

            # Check suspicious elements
            if self.check_suspicious_elements(url):
                self.result_text.insert(tk.END, "⚠️ Suspicious elements found in URL\n")
                risk_score += 25

            # Check SSL
            if not has_ssl:
                self.result_text.insert(tk.END, "❌ No SSL Certificate\n")
                risk_score += 30
            else:
                self.result_text.insert(tk.END, "✅ Valid SSL Certificate\n")

            # Check domain age
            if domain_age:
                if domain_age < 365:
                    self.result_text.insert(tk.END, f"⚠️ Domain age: {domain_age} days (New domain)\n")
                    risk_score += 25
                else:
                    self.result_text.insert(tk.END, f"✅ Domain age: {domain_age} days\n")

            # Final risk assessment
            self.result_text.insert(tk.END, f"\nRisk Score: {risk_score}%\n")
            if risk_score > 70:
                self.result_text.insert(tk.END, "🔴 High risk - Likely a phishing URL!")
            elif risk_score > 40:
                self.result_text.insert(tk.END, "🟡 Medium risk - Exercise caution!")
            else:
                self.result_text.insert(tk.END, "🟢 Low risk - Probably safe")

        except Exception as e:
            self.result_text.insert(tk.END, f"Error analyzing URL: {str(e)}")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = PhishingDetector()
    app.run()
