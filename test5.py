import tkinter as tk
from tkinter import ttk
import re
from urllib.parse import urlparse
import tldextract

class PhishingDetector:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Phishing URL Detector")
        self.window.geometry("600x400")
        self.window.configure(bg="#f0f0f0")

        # Main frame
        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # URL input
        ttk.Label(main_frame, text="Enter URL to check:", font=("Helvetica", 12)).pack(pady=10)
        self.url_entry = ttk.Entry(main_frame, width=50)
        self.url_entry.pack(pady=10)

        # Check button
        check_button = ttk.Button(main_frame, text="Check URL", command=self.check_url)
        check_button.pack(pady=10)

        # Result frame
        self.result_frame = ttk.Frame(main_frame)
        self.result_frame.pack(fill=tk.BOTH, expand=True, pady=20)

        # Result labels
        self.result_label = ttk.Label(self.result_frame, text="", font=("Helvetica", 14))
        self.result_label.pack()

        self.score_label = ttk.Label(self.result_frame, text="", font=("Helvetica", 12))
        self.score_label.pack()

    def check_phishing_rules(self, url):
        score = 0
        total_rules = 6
        
        # Rule 1: Check for IP address in URL
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            score += 1

        # Rule 2: Check URL length
        if len(url) > 75:
            score += 1

        # Rule 3: Check for @ symbol
        if '@' in url:
            score += 1

        # Rule 4: Check for multiple subdomains
        extracted = tldextract.extract(url)
        if len(extracted.subdomain.split('.')) > 2:
            score += 1

        # Rule 5: Check for suspicious words
        suspicious_words = ['login', 'signin', 'verify', 'secure', 'account', 'update']
        if any(word in url.lower() for word in suspicious_words):
            score += 1

        # Rule 6: Check for HTTPS
        if not url.startswith('https'):
            score += 1

        return (score / total_rules) * 100

    def check_url(self):
        url = self.url_entry.get()
        if not url:
            self.result_label.config(text="Please enter a URL")
            return

        try:
            phishing_score = self.check_phishing_rules(url)
            
            if phishing_score >= 70:
                result_text = "High Risk - Likely Phishing!"
                color = "#ff4d4d"
            elif phishing_score >= 40:
                result_text = "Medium Risk - Be Careful!"
                color = "#ffa500"
            else:
                result_text = "Low Risk - Probably Safe"
                color = "#4CAF50"

            self.result_label.config(text=result_text, foreground=color)
            self.score_label.config(text=f"Phishing Score: {phishing_score:.1f}%")
        except Exception as e:
            self.result_label.config(text="Error analyzing URL")

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = PhishingDetector()
    app.run()
