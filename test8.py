import tkinter as tk
from tkinter import ttk, messagebox
import re
from urllib.parse import urlparse
import tldextract
import requests
from datetime import datetime

class PhishingDetector:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Advanced Phishing URL Detector")
        self.window.geometry("800x600")
        self.window.configure(bg='#f0f0f0')
        
        # Styling
        style = ttk.Style()
        style.configure('TLabel', font=('Helvetica', 11))
        style.configure('TButton', font=('Helvetica', 11))
        style.configure('TEntry', font=('Helvetica', 11))
        
        # Main frame
        self.main_frame = ttk.Frame(self.window, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # URL Input
        ttk.Label(self.main_frame, text="Enter URL to check:").pack(pady=5)
        self.url_entry = ttk.Entry(self.main_frame, width=60)
        self.url_entry.pack(pady=5)
        
        # Check button
        check_button = ttk.Button(self.main_frame, text="Check URL", 
                                command=self.analyze_url)
        check_button.pack(pady=10)
        
        # Results area
        self.result_frame = ttk.LabelFrame(self.main_frame, text="Analysis Results", 
                                         padding="10")
        self.result_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create result labels
        self.create_result_labels()
        
    def create_result_labels(self):
        self.score_label = ttk.Label(self.result_frame, 
                                   text="Overall Risk Score: N/A")
        self.score_label.pack(anchor='w', pady=5)
        
        self.details_text = tk.Text(self.result_frame, height=20, width=70)
        self.details_text.pack(pady=5)
        
    def analyze_url(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
            
        risk_factors = []
        total_score = 0
        
        # Check URL length
        length_score = self.check_url_length(url)
        total_score += length_score
        risk_factors.append(f"URL Length Score: {length_score}%")
        
        # Check for special characters
        special_char_score = self.check_special_characters(url)
        total_score += special_char_score
        risk_factors.append(f"Special Characters Score: {special_char_score}%")
        
        # Check for suspicious words
        suspicious_score = self.check_suspicious_words(url)
        total_score += suspicious_score
        risk_factors.append(f"Suspicious Words Score: {suspicious_score}%")
        
        # Check for IP address
        ip_score = self.check_ip_address(url)
        total_score += ip_score
        risk_factors.append(f"IP Address Check Score: {ip_score}%")
        
        # Check SSL/HTTPS
        ssl_score = self.check_ssl(url)
        total_score += ssl_score
        risk_factors.append(f"SSL/HTTPS Score: {ssl_score}%")
        
        # Calculate final score
        final_score = total_score / 5  # Average of all scores
        
        # Update UI
        self.update_results(final_score, risk_factors)
        
    def check_url_length(self, url):
        length = len(url)
        if length < 30:
            return 100
        elif length < 50:
            return 80
        elif length < 75:
            return 60
        else:
            return 30
            
    def check_special_characters(self, url):
        special_chars = re.findall(r'[^a-zA-Z0-9-.]', url)
        char_count = len(special_chars)
        
        if char_count == 0:
            return 100
        elif char_count <= 2:
            return 80
        elif char_count <= 4:
            return 60
        else:
            return 30
            
    def check_suspicious_words(self, url):
        suspicious_words = ['secure', 'account', 'banking', 'login', 'signin', 
                          'verify', 'support', 'update', 'confirm']
        url_lower = url.lower()
        
        found_words = sum(1 for word in suspicious_words if word in url_lower)
        
        if found_words == 0:
            return 100
        elif found_words == 1:
            return 70
        elif found_words == 2:
            return 40
        else:
            return 20
            
    def check_ip_address(self, url):
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, url):
            return 20
        return 100
        
    def check_ssl(self, url):
        if url.startswith('https://'):
            try:
                requests.get(url, verify=True, timeout=5)
                return 100
            except:
                return 50
        return 30
        
    def update_results(self, final_score, risk_factors):
        risk_level = self.get_risk_level(final_score)
        
        self.score_label.config(
            text=f"Overall Risk Score: {final_score:.2f}% - {risk_level}")
        
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, "Detailed Analysis:\n\n")
        
        for factor in risk_factors:
            self.details_text.insert(tk.END, f"• {factor}\n")
            
        self.details_text.insert(tk.END, f"\nRisk Level: {risk_level}")
        
    def get_risk_level(self, score):
        if score >= 80:
            return "Safe"
        elif score >= 60:
            return "Moderate Risk"
        elif score >= 40:
            return "High Risk"
        else:
            return "Very High Risk"
        
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = PhishingDetector()
    app.run()
