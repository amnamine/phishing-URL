import tkinter as tk
from tkinter import ttk
import re
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from urllib.parse import urlparse

def extract_features(url):
    # Basic feature extraction
    features = []
    
    # Length of URL
    features.append(len(url))
    
    # Count special characters
    features.append(len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', url)))
    
    # Count numbers
    features.append(len(re.findall(r'\d', url)))
    
    # Domain length
    domain = urlparse(url).netloc
    features.append(len(domain))
    
    # Number of dots
    features.append(url.count('.'))
    
    return np.array(features).reshape(1, -1)

def train_model():
    # Sample data (you should replace this with real phishing dataset)
    # Format: [length, special_chars, numbers, domain_length, dots]
    X = np.array([
        [20, 2, 1, 10, 1],  # legitimate
        [50, 8, 5, 15, 3],  # phishing
        [30, 3, 2, 12, 1],  # legitimate
        [60, 10, 6, 20, 4], # phishing
    ])
    y = np.array([0, 1, 0, 1])  # 0: legitimate, 1: phishing
    
    model = RandomForestClassifier(n_estimators=100)
    model.fit(X, y)
    return model

def check_url():
    url = url_entry.get()
    if not url:
        result_label.config(text="Please enter a URL")
        return
    
    try:
        features = extract_features(url)
        prediction = model.predict(features)[0]
        probability = model.predict_proba(features)[0]
        
        if prediction == 0:
            result = f"Legitimate URL\nConfidence: {probability[0]:.2%}"
            result_label.config(text=result, foreground="green")
        else:
            result = f"Phishing URL\nConfidence: {probability[1]:.2%}"
            result_label.config(text=result, foreground="red")
    except:
        result_label.config(text="Error processing URL", foreground="black")

# Create and train the model
model = train_model()

# Create the main window
root = tk.Tk()
root.title("Phishing URL Detector")
root.geometry("400x200")

# Create and pack widgets
frame = ttk.Frame(root, padding="10")
frame.pack(fill=tk.BOTH, expand=True)

url_label = ttk.Label(frame, text="Enter URL:")
url_label.pack(pady=5)

url_entry = ttk.Entry(frame, width=50)
url_entry.pack(pady=5)

check_button = ttk.Button(frame, text="Check URL", command=check_url)
check_button.pack(pady=10)

result_label = tk.Label(frame, text="", font=('Arial', 12))
result_label.pack(pady=10)

# Start the application
root.mainloop()
