import tkinter as tk
from tkinter import ttk
from urllib.parse import urlparse
import re

class PhishingDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing URL Detector")
        self.root.geometry("600x400")
        self.root.configure(bg="#f0f0f0")

        # Main frame
        main_frame = ttk.Frame(root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Title
        title_label = ttk.Label(
            main_frame,
            text="Phishing URL Detector",
            font=("Helvetica", 16, "bold")
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        # URL Input
        url_label = ttk.Label(
            main_frame,
            text="Enter URL:",
            font=("Helvetica", 10)
        )
        url_label.grid(row=1, column=0, sticky=tk.W, pady=(0, 5))

        self.url_entry = ttk.Entry(main_frame, width=50)
        self.url_entry.grid(row=2, column=0, columnspan=2, pady=(0, 20))

        # Check button
        check_button = ttk.Button(
            main_frame,
            text="Check URL",
            command=self.check_url
        )
        check_button.grid(row=3, column=0, columnspan=2, pady=(0, 20))

        # Result frame
        self.result_frame = ttk.Frame(main_frame, padding="10")
        self.result_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E))

        self.result_label = ttk.Label(
            self.result_frame,
            text="Enter a URL and click 'Check URL'",
            font=("Helvetica", 10),
            wraplength=400
        )
        self.result_label.grid(row=0, column=0)

    def check_url(self):
        url = self.url_entry.get().strip()
        if not url:
            self.show_result("Please enter a URL", "warning")
            return

        # Simple phishing detection logic (you can expand this)
        suspicious_patterns = [
            r"paypal.*\.(?!paypal\.com)",  # Fake PayPal domains
            r"google.*\.(?!google\.com)",   # Fake Google domains
            r"bank.*\.(?!known-banks\.com)", # Suspicious bank domains
            r"@",                           # URLs with @ symbol
            r"^https?://\d+\.\d+\.\d+\.\d+",  # IP addresses as URLs
            r"bit\.ly|tinyurl",             # URL shorteners
        ]

        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc

            # Check for suspicious patterns
            for pattern in suspicious_patterns:
                if re.search(pattern, domain, re.IGNORECASE):
                    self.show_result("⚠️ Warning: This URL might be a phishing attempt!", "danger")
                    return

            self.show_result("✅ This URL appears to be safe", "safe")

        except Exception as e:
            self.show_result("Invalid URL format", "warning")

    def show_result(self, message, status):
        self.result_label.configure(text=message)
        
        # Update colors based on status
        if status == "safe":
            color = "#4CAF50"  # Green
        elif status == "danger":
            color = "#f44336"  # Red
        else:
            color = "#ff9800"  # Orange

        self.result_label.configure(foreground=color)

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingDetectorApp(root)
    root.mainloop()
