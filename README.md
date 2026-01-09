# 🔐 Network Traffic Monitoring and Attack Detection System

A core cybersecurity project implementing a basic Network Intrusion Detection System (NIDS) using Python on Kali Linux.  
The system monitors live network traffic and detects malicious activities using rule-based analysis.

---

## 📌 Project Overview
This project captures real-time network packets and analyzes TCP/IP behavior to detect suspicious activities such as port scanning and denial-of-service attacks.  
Attacks are generated and detected live, providing hands-on cybersecurity experience.

---

## 🚀 Features
- Live network packet monitoring
- Detection of Port Scanning attacks
- Detection of SYN Flood (DoS) attacks
- Real-time alert generation
- Attack simulation using real security tools
- Pure core cybersecurity (no AI, no datasets)

---

## 🧰 Tools & Technologies
- Kali Linux (Virtual Machine)
- Python 3
- Scapy
- Nmap
- Hping3
- Wireshark
- Git & GitHub

---

## 📥 Input
- Live network traffic packets
- TCP/IP header information:
  - Source IP
  - Destination port
  - TCP flags (SYN, ACK)

---

## 📤 Output
Real-time alerts displayed in the terminal when an attack is detected.

Example output:
ALERT: Port Scan Detected from 192.168.1.10
ALERT: SYN Flood Detected from 192.168.1.10


---

## ⚙️ How the System Works
1. Captures live network packets using Scapy
2. Tracks packet behavior for each source IP
3. Applies rule-based detection logic:
   - Multiple ports accessed in a short time → Port Scan
   - Excessive SYN packets without ACK → SYN Flood
4. Generates alerts when malicious behavior is detected

---

## ▶️ How to Run the Project

### Step 1: Install Required Tools
sudo apt update
sudo apt install python3-scapy nmap hping3 wireshark -y


### Step 2: Run the Program

sudo python3 monitor.py
The system will start monitoring live network traffic.

---

## 🧪 Testing the Detection

### Port Scan Test

nmap -p 1-1000 <your_kali_ip>

### SYN Flood Test

sudo hping3 -S --flood <your_kali_ip>


---

## ⚠️ Limitations
- Detects only basic network attacks
- May generate false positives in high-traffic environments
- Detection only (does not block traffic)

---

## 🔮 Future Improvements
- Save alerts to log files
- Detect SSH brute-force attacks
- Add dashboard visualization
- Extend detection rules

---
---

## 🧠 Key Learning Outcomes
- Understanding TCP/IP and packet structure
- Hands-on experience with real network attacks
- Core intrusion detection concepts
- Practical cybersecurity monitoring

