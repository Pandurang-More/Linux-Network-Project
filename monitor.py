from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

# store ports contacted by each IP
port_tracker = defaultdict(set)

# store SYN packet count
syn_counter = defaultdict(int)

# time window (seconds)
TIME_WINDOW = 10
start_time = time.time()

def analyze_packet(packet):
    global start_time

    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

        # track ports (for port scan)
        port_tracker[src_ip].add(dst_port)

        # track SYN packets (for SYN flood)
        if flags == "S":
            syn_counter[src_ip] += 1

    # check every TIME_WINDOW seconds
    if time.time() - start_time > TIME_WINDOW:
        for ip in port_tracker:
            if len(port_tracker[ip]) > 20:
                print(f"ALERT: Port Scan Detected from {ip}")

        for ip in syn_counter:
            if syn_counter[ip] > 100:
                print(f"ALERT: SYN Flood Detected from {ip}")

        # reset counters
        port_tracker.clear()
        syn_counter.clear()
        start_time = time.time()

print("Monitoring network traffic...")
sniff(prn=analyze_packet, store=False)
