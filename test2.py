import tkinter as tk
from tkinter import ttk
import re
import numpy as np
from xgboost import XGBClassifier
from urllib.parse import urlparse
import tld

def extract_advanced_features(url):
    features = []
    try:
        # Basic URL properties
        features.append(len(url))  # URL length
        
        # Domain specific features
        domain = urlparse(url).netloc
        features.append(len(domain))  # Domain length
        features.append(domain.count('-'))  # Count of hyphens
        features.append(domain.count('.'))  # Count of dots
        
        # Suspicious patterns
        suspicious_words = ['secure', 'account', 'banking', 'login', 'verify']
        features.append(sum(1 for word in suspicious_words if word in url.lower()))
        
        # Special character features
        features.append(len(re.findall(r'[!@#$%^&*()]', url)))  # Special chars
        features.append(len(re.findall(r'\d', url)))  # Number count
        
        # Path features
        path = urlparse(url).path
        features.append(len(path.split('/')))  # Directory depth
        
        # Protocol feature
        features.append(1 if url.startswith('https') else 0)  # HTTPS present
        
    except:
        return np.zeros(10)
    
    return np.array(features)

def create_sample_data():
    # Extended sample dataset (you should replace with real data)
    X = np.array([
        [20, 10, 0, 1, 0, 2, 1, 2, 1, 1],  # legitimate
        [45, 15, 2, 3, 2, 8, 5, 4, 0, 0],  # phishing
        [30, 12, 0, 1, 0, 3, 2, 2, 1, 1],  # legitimate
        [55, 20, 3, 4, 3, 10, 6, 5, 0, 0], # phishing
        [25, 8, 0, 1, 0, 1, 0, 2, 1, 1],   # legitimate
        [50, 18, 2, 3, 2, 7, 4, 4, 0, 0],  # phishing
    ])
    y = np.array([0, 1, 0, 1, 0, 1])
    return X, y

def check_url():
    url = url_entry.get()
    if not url:
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, "Please enter a URL")
        return
    
    try:
        features = extract_advanced_features(url)
        features = features.reshape(1, -1)
        prediction = model.predict(features)[0]
        probability = model.predict_proba(features)[0]
        
        result_text.delete(1.0, tk.END)
        
        if prediction == 0:
            result_text.insert(tk.END, "RESULT: LEGITIMATE URL\n\n", "safe")
        else:
            result_text.insert(tk.END, "RESULT: POTENTIAL PHISHING URL\n\n", "danger")
            
        result_text.insert(tk.END, f"Confidence: {max(probability):.2%}\n\n")
        result_text.insert(tk.END, "Feature Analysis:\n")
        result_text.insert(tk.END, f"- URL Length: {len(url)}\n")
        result_text.insert(tk.END, f"- Special Characters: {features[0][6]}\n")
        result_text.insert(tk.END, f"- Suspicious Keywords: {features[0][4]}\n")
        result_text.insert(tk.END, f"- Uses HTTPS: {'Yes' if features[0][9] else 'No'}\n")
        
    except Exception as e:
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Error processing URL: {str(e)}")

# Create and train model
X, y = create_sample_data()
model = XGBClassifier(n_estimators=100, learning_rate=0.1)
model.fit(X, y)

# Create main window
root = tk.Tk()
root.title("Advanced Phishing URL Detector")
root.geometry("500x400")

# Configure style
style = ttk.Style()
style.configure('TFrame', background='#f0f0f0')
style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
style.configure('TButton', font=('Arial', 10))

# Main frame
main_frame = ttk.Frame(root, padding="20", style='TFrame')
main_frame.pack(fill=tk.BOTH, expand=True)

# URL entry
url_label = ttk.Label(main_frame, text="Enter URL to check:", style='TLabel')
url_label.pack(pady=(0, 5))

url_entry = ttk.Entry(main_frame, width=50)
url_entry.pack(pady=(0, 10))

# Check button
check_button = ttk.Button(main_frame, text="Analyze URL", command=check_url)
check_button.pack(pady=(0, 10))

# Result text
result_text = tk.Text(main_frame, height=12, width=50, font=('Arial', 10))
result_text.pack(pady=(0, 10))
result_text.tag_configure("safe", foreground="green", font=('Arial', 12, 'bold'))
result_text.tag_configure("danger", foreground="red", font=('Arial', 12, 'bold'))

# Start application
root.mainloop()
