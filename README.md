# WiFi Deauth Attack Shield 🛡️

A real-time Wi-Fi deauthentication attack detection tool
built for Kali Linux using Python and Scapy.

---

## 🔍 What is a Deauth Attack?

A deauthentication attack forces devices off a WiFi network
by flooding fake disconnect signals. WiFi management frames
have no authentication by design — making this attack
possible on any WPA2 network.

---

## ⚡ What This Tool Does

- Captures live WiFi packets in monitor mode
- Analyzes deauth frame patterns in real time
- Fires instant alerts when an attack is detected
- Saves all alerts to deauth_alerts.log with timestamps

---

## 🎯 10 Attack Patterns Detected

| # | Pattern |
|---|---------|
| 1 | Flood attacks |
| 2 | Broadcast deauth (FF:FF:FF:FF:FF:FF) |
| 3 | Spoofed MAC addresses |
| 4 | Evil Twin / Rogue AP |
| 5 | Scripted interval attacks |
| 6 | MAC rotation |
| 7 | Deauth + Disassoc combos |
| 8 | Targeted client attacks |
| 9 | Suspicious reason codes |
| 10 | Rogue unknown sources |

---

## 🛠️ Requirements

- Kali Linux
- Monitor mode compatible WiFi adapter
- Python 3
- Scapy

Install Scapy:

    pip install scapy

---

## ▶️ How to Run

Step 1 — Run the tool:

    sudo python3 wifi_deauth_shield.py

Step 2 — Check saved alerts:

    cat deauth_alerts.log

---

## ⚠️ Disclaimer

This tool is for **educational and defensive use only.**
Do not use it on networks you do not own or have
explicit permission to monitor.

---

## 👤 Author

GopiVallabha — github.com/GopiVallbha
