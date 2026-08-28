#!/usr/bin/env python3
"""
Quick self-scan to test the IDS detection.
Scans your own IP on common ports to trigger port scan detection.
"""
import socket
import time

TARGET = "10.84.35.234"
PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
         993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443]

print(f"Scanning {TARGET} on {len(PORTS)} ports...")
print("-" * 40)

for port in PORTS:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((TARGET, port))
        print(f"  Port {port}: OPEN")
        s.close()
    except (socket.timeout, ConnectionRefusedError):
        print(f"  Port {port}: closed")
    except OSError:
        print(f"  Port {port}: filtered")
    time.sleep(0.1)

print("-" * 40)
print("Scan complete! Check Terminal 1 for detection alerts.")
print("Also check dashboard at http://localhost:5001")
