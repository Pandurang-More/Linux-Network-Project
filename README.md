# Network Traffic Monitoring and Attack Detection System

## Project Overview
This project is a basic Network Intrusion Detection System (NIDS) developed using Python on Kali Linux.  
It monitors live network traffic and detects common network-based attacks using rule-based analysis.

The system detects:
- Port Scanning attacks
- SYN Flood (Denial of Service) attacks

---

## Objectives
- Monitor live network packets
- Analyze TCP/IP behavior
- Detect malicious network activities
- Generate real-time security alerts

---

## Tools and Technologies
- Kali Linux (Virtual Machine)
- Python 3
- Scapy
- Nmap
- Hping3
- Wireshark
- Git & GitHub

---

## Input
- Live network traffic packets
- TCP/IP header information:
  - Source IP
  - Destination port
  - TCP flags (SYN, ACK)

---

## Output
- Real-time alerts printed on the terminal

Example:
ALERT: Port Scan Detected from 192.168.1.10  
ALERT: SYN Flood Detected from 192.168.1.10  

---

## How It Works
1. Captures live network packets using Scapy
2. Tracks behavior of source IP addresses
3. Applies detection rules:
   - Multiple ports accessed in a short time → Port Scan
   - Excessive SYN packets without ACK → SYN Flood
4. Generates alerts when suspicious activity is detected

---

## How to Run the Project

### Install Required Tools
sudo apt update  
sudo apt install python3-scapy nmap hping3 wireshark -y  

### Run the Program
sudo python3 monitor.py  

---

## Testing the System

### Port Scan Test
nmap -p 1-1000 <your_kali_ip>

### SYN Flood Test
sudo hping3 -S --flood <your_kali_ip>

---

## Screenshots
Screenshots of alerts, attack simulation, and packet capture using Wireshark can be added to demonstrate proof of execution.

---

## Limitations
- Detects only basic network attacks
- May generate false positives in high-traffic environments
- Detection only (does not block traffic)

---

## Future Improvements
- Save alerts to log files
- Detect SSH brute-force attacks
- Add dashboard visualization
- Extend detection rules

---

## Author
Pandurang More
