import tkinter as tk
from tkinter import ttk
import re
import ssl
import socket
import requests
from urllib.parse import urlparse
import tldextract
from datetime import datetime

class PhishingDetector:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Advanced Phishing URL Detector")
        self.window.geometry("800x600")
        self.window.configure(bg="#2c3e50")
        
        self.setup_ui()
        
    def setup_ui(self):
        # Header
        header = tk.Frame(self.window, bg="#34495e")
        header.pack(fill=tk.X, padx=20, pady=20)
        
        title = tk.Label(header, text="URL Phishing Detection System", 
                        font=("Helvetica", 24, "bold"), fg="white", bg="#34495e")
        title.pack(pady=10)
        
        # URL Input Section
        input_frame = tk.Frame(self.window, bg="#2c3e50")
        input_frame.pack(fill=tk.X, padx=20)
        
        self.url_entry = tk.Entry(input_frame, width=50, font=("Helvetica", 12))
        self.url_entry.pack(side=tk.LEFT, padx=5, pady=20)
        
        analyze_btn = tk.Button(input_frame, text="Analyze URL", command=self.analyze_url,
                              bg="#27ae60", fg="white", font=("Helvetica", 10, "bold"))
        analyze_btn.pack(side=tk.LEFT, padx=5)
        
        # Results Section
        self.result_frame = tk.Frame(self.window, bg="#2c3e50")
        self.result_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Analysis Results
        self.result_text = tk.Text(self.result_frame, height=20, width=70, 
                                 font=("Courier", 10), bg="#34495e", fg="white")
        self.result_text.pack(pady=10)

    def analyze_url(self):
        url = self.url_entry.get()
        self.result_text.delete(1.0, tk.END)
        
        # Basic URL validation
        if not self.is_valid_url(url):
            self.show_result("Invalid URL format!", "high")
            return
        
        risk_score = 0
        analysis_results = []
        
        # Domain analysis
        domain = urlparse(url).netloc
        ext = tldextract.extract(url)
        
        # Check for suspicious TLD
        suspicious_tlds = ['.xyz', '.top', '.work', '.live', '.tk', '.ml']
        if any(tld in ext.suffix for tld in suspicious_tlds):
            risk_score += 25
            analysis_results.append(("Suspicious TLD detected", "high"))
        
        # Length analysis
        if len(url) > 75:
            risk_score += 10
            analysis_results.append(("Unusually long URL", "medium"))
        
        # Special character analysis
        if url.count('@') > 0:
            risk_score += 20
            analysis_results.append(("Contains @ symbol", "high"))
        
        if url.count('//') > 1:
            risk_score += 20
            analysis_results.append(("Multiple redirects detected", "high"))
        
        # SSL Check
        try:
            response = requests.get(url, verify=True, timeout=5)
            if response.status_code == 200:
                analysis_results.append(("SSL Certificate valid", "low"))
            else:
                risk_score += 15
                analysis_results.append(("SSL verification failed", "medium"))
        except:
            risk_score += 25
            analysis_results.append(("Connection failed/Invalid SSL", "high"))
        
        # Display Results
        self.result_text.insert(tk.END, f"=== URL Analysis Results ===\n\n")
        self.result_text.insert(tk.END, f"URL: {url}\n")
        self.result_text.insert(tk.END, f"Domain: {domain}\n")
        self.result_text.insert(tk.END, f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        self.result_text.insert(tk.END, "--- Detailed Analysis ---\n\n")
        for result, risk in analysis_results:
            self.result_text.insert(tk.END, f"• {result} (Risk: {risk})\n")
        
        self.result_text.insert(tk.END, f"\nOverall Risk Score: {risk_score}/100\n")
        self.result_text.insert(tk.END, f"Risk Level: {self.get_risk_level(risk_score)}")
        
    def is_valid_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def get_risk_level(self, score):
        if score >= 70:
            return "HIGH RISK - Likely Phishing"
        elif score >= 40:
            return "MEDIUM RISK - Suspicious"
        else:
            return "LOW RISK - Probably Safe"
    
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = PhishingDetector()
    app.run()
