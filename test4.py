import tkinter as tk
from tkinter import ttk, filedialog
import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, Dense, GlobalMaxPooling1D, Embedding, Dropout
from tensorflow.keras.preprocessing.sequence import pad_sequences
import re
from urllib.parse import urlparse
import json
from datetime import datetime
import tldextract
from collections import Counter

# Constants
MAX_LENGTH = 100
VOCAB_SIZE = 128
EMBED_DIM = 32

class CNNPhishingDetector:
    def __init__(self):
        self.model = self._create_model()
        self._train_model()
        
    def _create_model(self):
        model = Sequential([
            Embedding(VOCAB_SIZE, EMBED_DIM, input_length=MAX_LENGTH),
            Conv1D(64, 3, activation='relu'),
            Conv1D(64, 3, activation='relu'),
            GlobalMaxPooling1D(),
            Dense(64, activation='relu'),
            Dropout(0.3),
            Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model
    
    def _train_model(self):
        X, y = self._create_sample_data()
        self.model.fit(X, y, epochs=5, batch_size=32, verbose=0)
    
    def _create_sample_data(self):
        legitimate = [
            "https://www.google.com/search",
            "https://github.com/login",
            "https://www.amazon.com/products",
            "https://www.microsoft.com/windows"
        ]
        phishing = [
            "http://googgle-secure.com/login",
            "http://verify-account-service.net",
            "http://security-check-required.com",
            "http://banking-verify-now.com"
        ]
        
        X = []
        y = []
        
        for url in legitimate + phishing:
            X.append([ord(c) % VOCAB_SIZE for c in url])
            y.append(0 if url in legitimate else 1)
        
        return pad_sequences(X, maxlen=MAX_LENGTH), np.array(y)
    
    def analyze_url(self, url):
        features = self._extract_features(url)
        sequence = pad_sequences([[ord(c) % VOCAB_SIZE for c in url]], maxlen=MAX_LENGTH)
        prediction = self.model.predict(sequence)[0][0]
        return prediction, features
    
    def _extract_features(self, url):
        features = {}
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        features['length'] = len(url)
        features['domain_length'] = len(extracted.domain)
        features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        features['path_length'] = len(parsed.path)
        features['special_chars'] = len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', url))
        features['digits'] = sum(c.isdigit() for c in url)
        features['https'] = url.startswith('https')
        
        return features

class PhishingDetectorUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CNN-Based Phishing URL Detector")
        self.root.geometry("900x700")
        self.root.configure(bg='#1e1e1e')
        
        self.detector = CNNPhishingDetector()
        self.setup_ui()
    
    def setup_ui(self):
        style = ttk.Style()
        style.configure('Modern.TFrame', background='#1e1e1e')
        style.configure('Modern.TLabel', background='#1e1e1e', foreground='#ffffff')
        style.configure('Modern.TButton', padding=5)
        
        main_frame = ttk.Frame(self.root, style='Modern.TFrame', padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header = ttk.Label(main_frame, text="Deep Learning URL Analysis", 
                          font=('Arial', 20), style='Modern.TLabel')
        header.pack(pady=10)
        
        # URL Input
        input_frame = ttk.Frame(main_frame, style='Modern.TFrame')
        input_frame.pack(fill=tk.X, pady=10)
        
        self.url_entry = ttk.Entry(input_frame, width=70)
        self.url_entry.pack(side=tk.LEFT, padx=5)
        
        analyze_btn = ttk.Button(input_frame, text="Analyze", 
                               command=self.analyze_url)
        analyze_btn.pack(side=tk.LEFT, padx=5)
        
        export_btn = ttk.Button(input_frame, text="Export Report", 
                              command=self.export_report)
        export_btn.pack(side=tk.LEFT, padx=5)
        
        # Results Area
        self.result_text = tk.Text(main_frame, height=20, bg='#2d2d2d', 
                                 fg='#ffffff', font=('Consolas', 10))
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Configure tags for colored output
        self.result_text.tag_configure('safe', foreground='#4caf50')
        self.result_text.tag_configure('danger', foreground='#f44336')
        self.result_text.tag_configure('header', foreground='#2196f3')
    
    def analyze_url(self):
        url = self.url_entry.get()
        if not url:
            return
        
        prediction, features = self.detector.analyze_url(url)
        self.display_results(url, prediction, features)
    
    def display_results(self, url, prediction, features):
        self.result_text.delete(1.0, tk.END)
        
        # Header
        self.result_text.insert(tk.END, "URL ANALYSIS REPORT\n", 'header')
        self.result_text.insert(tk.END, "=" * 50 + "\n\n")
        
        # Risk Score
        risk_level = "LOW RISK" if prediction < 0.5 else "HIGH RISK"
        tag = 'safe' if prediction < 0.5 else 'danger'
        self.result_text.insert(tk.END, f"Risk Assessment: {risk_level}\n", tag)
        self.result_text.insert(tk.END, f"Confidence Score: {prediction:.2%}\n\n")
        
        # Feature Analysis
        self.result_text.insert(tk.END, "FEATURE ANALYSIS\n", 'header')
        self.result_text.insert(tk.END, "-" * 30 + "\n")
        for key, value in features.items():
            self.result_text.insert(tk.END, f"{key.replace('_', ' ').title()}: {value}\n")
    
    def export_report(self):
        if not self.url_entry.get():
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        if filename:
            url = self.url_entry.get()
            prediction, features = self.detector.analyze_url(url)
            
            report = {
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "risk_score": float(prediction),
                "features": features
            }
            
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = PhishingDetectorUI()
    app.run()
