import tkinter as tk
from tkinter import ttk
import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Embedding
from tensorflow.keras.preprocessing.sequence import pad_sequences
import re
from urllib.parse import urlparse
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Constants
MAX_URL_LENGTH = 100
VOCAB_SIZE = 128  # ASCII characters

def create_model():
    model = Sequential([
        Embedding(VOCAB_SIZE, 32, input_length=MAX_URL_LENGTH),
        LSTM(64, return_sequences=True),
        LSTM(32),
        Dense(16, activation='relu'),
        Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

def url_to_sequence(url):
    # Convert URL to ASCII sequence
    return pad_sequences([[ord(c) % VOCAB_SIZE for c in url]], maxlen=MAX_URL_LENGTH)

def extract_safety_features(url):
    features = {}
    features['length'] = len(url)
    features['special_chars'] = len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', url))
    features['numbers'] = len(re.findall(r'\d', url))
    features['dots'] = url.count('.')
    features['hyphens'] = url.count('-')
    features['subdomains'] = len(urlparse(url).netloc.split('.')) - 1
    return features

def create_sample_data():
    # Sample URLs (replace with real dataset)
    legitimate_urls = [
        "https://www.google.com",
        "https://github.com/login",
        "https://www.microsoft.com/en-us",
    ]
    phishing_urls = [
        "http://g00gle.com-secure.net",
        "http://banking.secure-verify.com",
        "http://login.account-verify.net",
    ]
    
    X = []
    y = []
    
    for url in legitimate_urls:
        X.append([ord(c) % VOCAB_SIZE for c in url])
        y.append(0)
    
    for url in phishing_urls:
        X.append([ord(c) % VOCAB_SIZE for c in url])
        y.append(1)
    
    X = pad_sequences(X, maxlen=MAX_URL_LENGTH)
    return np.array(X), np.array(y)

class PhishingDetectorUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Deep Learning Phishing Detector")
        self.root.geometry("800x600")
        self.root.configure(bg='#2b2b2b')
        
        # Load and train model
        X, y = create_sample_data()
        self.model = create_model()
        self.model.fit(X, y, epochs=10, batch_size=2, verbose=0)
        
        self.setup_ui()
    
    def setup_ui(self):
        # Style configuration
        style = ttk.Style()
        style.configure('Dark.TFrame', background='#2b2b2b')
        style.configure('Dark.TLabel', background='#2b2b2b', foreground='#ffffff')
        style.configure('Dark.TButton', background='#404040', foreground='#ffffff')

        # Main container
        main_frame = ttk.Frame(self.root, style='Dark.TFrame', padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # URL input section
        url_frame = ttk.Frame(main_frame, style='Dark.TFrame')
        url_frame.pack(fill=tk.X, pady=10)

        url_label = ttk.Label(url_frame, text="Enter URL:", style='Dark.TLabel')
        url_label.pack(side=tk.LEFT, padx=5)

        self.url_entry = ttk.Entry(url_frame, width=60)
        self.url_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        analyze_btn = ttk.Button(url_frame, text="Analyze", command=self.analyze_url)
        analyze_btn.pack(side=tk.LEFT, padx=5)

        # Results section
        self.result_frame = ttk.Frame(main_frame, style='Dark.TFrame')
        self.result_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Create matplotlib figure for visualization
        self.fig, (self.ax1, self.ax2) = plt.subplots(1, 2, figsize=(10, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, self.result_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Text results
        self.result_text = tk.Text(main_frame, height=8, bg='#363636', fg='#ffffff',
                                 font=('Consolas', 10))
        self.result_text.pack(fill=tk.X, pady=10)

    def analyze_url(self):
        url = self.url_entry.get()
        if not url:
            return

        # Get model prediction
        seq = url_to_sequence(url)
        prediction = self.model.predict(seq)[0][0]
        features = extract_safety_features(url)

        # Update text results
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"URL Analysis Results:\n")
        self.result_text.insert(tk.END, f"Risk Score: {prediction:.2%}\n")
        self.result_text.insert(tk.END, f"Classification: ")
        
        if prediction < 0.5:
            self.result_text.insert(tk.END, "LEGITIMATE\n", "safe")
        else:
            self.result_text.insert(tk.END, "POTENTIALLY MALICIOUS\n", "danger")

        # Update visualizations
        self.update_visualizations(features, prediction)

    def update_visualizations(self, features, prediction):
        # Clear previous plots
        self.ax1.clear()
        self.ax2.clear()

        # Feature visualization
        feature_names = list(features.keys())
        feature_values = list(features.values())
        
        self.ax1.bar(feature_names, feature_values)
        self.ax1.set_title('URL Features')
        self.ax1.tick_params(axis='x', rotation=45)

        # Risk gauge
        self.ax2.clear()
        self.ax2.pie([prediction, 1-prediction], colors=['#ff6b6b', '#4ecdc4'],
                    labels=['Risk', 'Safe'])
        self.ax2.set_title('Risk Assessment')

        self.canvas.draw()

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingDetectorUI(root)
    root.mainloop()
