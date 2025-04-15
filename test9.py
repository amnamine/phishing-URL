import tkinter as tk
from tkinter import ttk, messagebox
import re
import tldextract
from urllib.parse import urlparse

class PhishingDetector:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Phishing URL Detector")
        self.window.geometry("600x400")
        
        # Known patterns
        self.suspicious_terms = ['login', 'signin', 'verify', 'secure', 'account', 'banking',
                               'confirm', 'password', 'security', 'update', 'authentication']
        self.legitimate_domains = ['google.com', 'facebook.com', 'amazon.com', 'apple.com',
                                 'microsoft.com', 'paypal.com', 'netflix.com', 'instagram.com']
        
        self.create_widgets()

    def create_widgets(self):
        # URL Entry
        url_frame = ttk.LabelFrame(self.window, text="Enter URL", padding=10)
        url_frame.pack(fill="x", padx=10, pady=5)
        
        self.url_entry = ttk.Entry(url_frame, width=50)
        self.url_entry.pack(fill="x", padx=5)
        
        # Check Button
        check_button = ttk.Button(self.window, text="Check URL", command=self.analyze_url)
        check_button.pack(pady=10)
        
        # Results Area
        results_frame = ttk.LabelFrame(self.window, text="Analysis Results", padding=10)
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.result_text = tk.Text(results_frame, height=15, width=50)
        self.result_text.pack(fill="both", expand=True, padx=5)

    def check_ip_url(self, url):
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(ip_pattern, url))

    def check_url_length(self, url):
        return len(url) > 75

    def check_suspicious_words(self, url):
        return any(term in url.lower() for term in self.suspicious_terms)

    def check_multiple_subdomains(self, url):
        ext = tldextract.extract(url)
        return len(ext.subdomain.split('.')) > 2

    def check_special_chars(self, url):
        special_chars = ['@', '!', '#', '$', '%', '^', '&', '*', '(', ')', '+', '=']
        return any(char in url for char in special_chars)

    def check_legitimate_domain_mimic(self, url):
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        
        for legit_domain in self.legitimate_domains:
            if domain != legit_domain and any(
                legit_domain.replace('.', '') in part 
                for part in domain.split('.')
            ):
                return True
        return False

    def analyze_url(self):
        url = self.url_entry.get().strip()
        self.result_text.delete(1.0, tk.END)
        
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
            
        risk_score = 0
        findings = []
        
        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        try:
            parsed = urlparse(url)
        except:
            messagebox.showerror("Error", "Invalid URL format")
            return
            
        # Perform checks
        if self.check_ip_url(url):
            risk_score += 25
            findings.append("⚠️ IP address used in URL (High Risk)")
            
        if self.check_url_length(url):
            risk_score += 15
            findings.append("⚠️ Unusually long URL")
            
        if self.check_suspicious_words(url):
            risk_score += 20
            findings.append("⚠️ Contains suspicious keywords")
            
        if self.check_multiple_subdomains(url):
            risk_score += 15
            findings.append("⚠️ Multiple subdomains detected")
            
        if self.check_special_chars(url):
            risk_score += 20
            findings.append("⚠️ Contains special characters")
            
        if self.check_legitimate_domain_mimic(url):
            risk_score += 25
            findings.append("⚠️ Possible legitimate domain mimicking")
            
        # Display results
        self.result_text.insert(tk.END, f"URL: {url}\n\n")
        self.result_text.insert(tk.END, "Findings:\n")
        for finding in findings:
            self.result_text.insert(tk.END, f"• {finding}\n")
            
        self.result_text.insert(tk.END, f"\nRisk Score: {risk_score}/100\n")
        
        if risk_score >= 70:
            self.result_text.insert(tk.END, "\n🔴 HIGH RISK - Likely Phishing")
        elif risk_score >= 40:
            self.result_text.insert(tk.END, "\n🟡 MEDIUM RISK - Suspicious")
        else:
            self.result_text.insert(tk.END, "\n🟢 LOW RISK - Probably Safe")

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = PhishingDetector()
    app.run()
