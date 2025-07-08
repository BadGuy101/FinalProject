# 🛡️ AdvoShield – Advanced Adware Detection & Prevention

**AdvoShield** (UltraAdware Engine) is a comprehensive adware detection and prevention system that combines machine learning, heuristic analysis, threat intelligence feeds, and real-time system monitoring to defend against modern adware threats.

Developed as part of a Final Year Project by **Zahid Ullah**  
**Supervisor**: Dr. Ibrar Ahmad  
University of Peshawar, Department of Computer Science

---

## 🚀 Features

- 🧠 **Machine Learning Engine**  
  - Multiple ML models: Random Forest, SVM, Neural Networks, etc.  
  - Optional deep learning with TensorFlow  

- 🕵️ **Heuristic & Signature-based Detection**  
  - File signatures, PE analysis, entropy analysis, anti-debug checks  

- 🔍 **Real-Time System Monitoring**  
  - CPU, memory, process behavior, file integrity, registry changes  

- 🌐 **Network Analyzer**  
  - Detects ad networks, DGA domains, suspicious traffic patterns  

- 🧠 **Threat Intelligence Integration**  
  - Pulls data from OpenPhish, Abuse.ch, AlienVault, etc.  

- 🗂️ **File Quarantine & Recovery**  
  - Encrypted quarantine with restoration support  

- 🖥️ **User Interface**  
  - GUI built with Tkinter (or PyQt/Tkinter depending on version)  

---

## 📦 Installation

> Python 3.8+ recommended

1. **Clone the repository:**

```bash
git clone https://github.com/yourusername/AdvoShield.git
cd AdvoShield


AdvoShield/
├── main.py                  # Main entry point
├── config/                  # Configuration & logging
├── core/                    # Core detection logic & monitoring
├── engines/                 # ML and file scanning engines
├── gui/                     # GUI frontend
├── utils/                   # Helpers, crypto, audit logging
├── tests/                   # Unit tests
├── assets/                 # Icons, logos, etc.
├── requirements.txt
└── README.md
