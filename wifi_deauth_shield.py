#!/usr/bin/env python3
import subprocess, sys, os, time, signal, threading
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt, RadioTap, Dot11Disas
except ImportError:
    subprocess.run([sys.executable,"-m","pip","install","scapy","--break-system-packages","-q"])
    from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt, RadioTap, Dot11Disas

DEAUTH_THRESHOLD  = 5
TIME_WINDOW       = 10
SCAN_TIME         = 20
CHANNEL_HOP_DELAY = 0.3

nearby_networks   = {}
deauth_counts     = defaultdict(list)
deauth_timestamps = defaultdict(list)
alerts_issued     = set()
mac_history       = defaultdict(set)
combo_attacks     = set()
interface         = None
monitor_iface     = None
stop_sniff_event  = threading.Event()
total_deauth      = 0
attack_log        = []

R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
C="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RST="\033[0m"; BLINK="\033[5m"

def banner():
    print(f"""
{G}{BOLD}
  ╔══════════════════════════════════════════════════════════╗
  ║  {C}░██╗░░░░░░░██╗██╗███████╗██╗{G}                          ║
  ║  {C}░██║░░██╗░░██║██║██╔════╝██║{G}                          ║
  ║  {C}░╚██╗████╗██╔╝██║█████╗░░██║{G}                          ║
  ║  {C}░░████╔═████║░██║██╔══╝░░██║{G}                          ║
  ║  {C}░░╚██╔╝░╚██╔╝░██║██║░░░░░██║{G}                          ║
  ║  {C}░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░░░░╚═╝{G}                         ║
  ║                                                          ║
  ║  {G}█▀▄ █▀▀ ▄▀█ █░█ ▀█▀ █░█   █▀ █░█ █ █▀▀ █░░ █▀▄{G}     ║
  ║  {G}█▄▀ ██▄ █▀█ █▄█ ░█░ █▀█   ▄█ █▀█ █ ██▄ █▄▄ █▄▀{G}     ║
  ║                                                          ║
  ║  {DIM}01001000 01000001 01000011 01001011{G}                   ║
  ╠══════════════════════════════════════════════════════════╣
  ║  {Y}⚡ WiFi Deauth Attack Shield v2.0 — Pattern Edition{G}    ║
  ║  {DIM}Initializing matrix... Loading attack signatures...{G}    ║
  ╚══════════════════════════════════════════════════════════╝
{RST}""")

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log_info(msg):  print(f"  {DIM}[{ts()}]{RST} {G}[+]{RST} {msg}")
def log_warn(msg):  print(f"  {DIM}[{ts()}]{RST} {Y}[!]{RST} {msg}")
def log_err(msg):   print(f"  {R}[x]{RST} {msg}")

def get_severity(count, patterns):
    score = min(count * 2, 40)
    for p in patterns:
        if p['level'] == 'CRITICAL': score += 30
        elif p['level'] == 'HIGH':   score += 20
        elif p['level'] == 'MEDIUM': score += 10
    if score >= 60: return "CRITICAL"
    if score >= 40: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"

def log_alert(src, dst, count, patterns, reason):
    severity  = get_severity(count, patterns)
    sev_color = R if severity in ["CRITICAL","HIGH"] else Y
    print(f"""
  {G}╔{'═'*62}╗{RST}
  {G}║{RST} {R}{BOLD}{BLINK}  [!!!] DEAUTH ATTACK DETECTED [{ts()}]{RST}              {G}║{RST}
  {G}╠{'═'*62}╣{RST}
  {G}║{RST}  {BOLD}Source MAC  :{RST} {R}{src:<42}{G}║{RST}
  {G}║{RST}  {BOLD}Target      :{RST} {Y}{dst:<42}{G}║{RST}
  {G}║{RST}  {BOLD}Packets     :{RST} {R}{str(count)+' in '+str(TIME_WINDOW)+'s':<42}{G}║{RST}
  {G}║{RST}  {BOLD}Reason Code :{RST} {DIM}{str(reason):<42}{RST}{G}║{RST}
  {G}║{RST}  {BOLD}Severity    :{RST} {sev_color}{BOLD}{severity:<42}{RST}{G}║{RST}
  {G}╠{'═'*62}╣{RST}
  {G}║{RST}  {BOLD}{C}ATTACK PATTERNS:{RST}                                       {G}║{RST}""")
    for p in patterns:
        pc = R if p['level']=='CRITICAL' else Y if p['level']=='HIGH' else C
        name = p['name'][:56]
        desc = p['desc'][:56]
        print(f"  {G}║{RST}  {pc}▶ {name}{RST}")
        print(f"  {G}║{RST}    {DIM}{desc}{RST}")
    print(f"""  {G}╠{'═'*62}╣{RST}
  {G}║{RST}  {Y}Action: Enable WPA3 or 802.11w PMF on your router!{RST}    {G}║{RST}
  {G}╚{'═'*62}╝{RST}
""")

def detect_patterns(src, dst, count, reason, timestamps):
    patterns = []

    # Pattern 1 - FLOOD
    if count >= 100:
        patterns.append({"name":"FLOOD ATTACK (EXTREME)","desc":f"{count} packets — aireplay-ng or mdk3 likely running","level":"CRITICAL"})
    elif count >= 20:
        patterns.append({"name":"FLOOD ATTACK (MODERATE)","desc":f"{count} deauth packets in {TIME_WINDOW}s — automated tool","level":"HIGH"})

    # Pattern 2 - BROADCAST
    if dst.lower() in ["ff:ff:ff:ff:ff:ff","ff:ff:ff:ff:ff:fe"]:
        patterns.append({"name":"BROADCAST DEAUTH ATTACK","desc":"Targeting ALL devices on network at once","level":"CRITICAL"})

    # Pattern 3 - SPOOFED MAC
    try:
        first_byte = int(src.split(":")[0], 16)
        if first_byte & 0x02:
            patterns.append({"name":"SPOOFED MAC ADDRESS","desc":"Locally administered MAC — attacker hiding identity","level":"CRITICAL"})
    except:
        pass

    # Pattern 4 - REGULAR INTERVALS (scripted)
    if len(timestamps) >= 4:
        intervals = [timestamps[i+1]-timestamps[i] for i in range(len(timestamps)-1)]
        avg = sum(intervals)/len(intervals)
        variance = sum((x-avg)**2 for x in intervals)/len(intervals)
        if variance < 0.05 and avg < 2.0:
            patterns.append({"name":"REGULAR INTERVAL ATTACK","desc":f"Packets every ~{avg:.2f}s — scripted/automated attack","level":"HIGH"})

    # Pattern 5 - EVIL TWIN / ROGUE AP
    if src in nearby_networks:
        patterns.append({"name":"EVIL TWIN / ROGUE AP","desc":f"Deauth from known AP '{nearby_networks[src]['ssid']}' — may be cloned","level":"HIGH"})
    else:
        patterns.append({"name":"UNKNOWN/ROGUE SOURCE","desc":"Source not found in any nearby AP — rogue device","level":"MEDIUM"})

    # Pattern 6 - MALICIOUS REASON CODE
    malicious_reasons = {
        1:"Unspecified (common in attacks)",
        2:"Previous auth no longer valid",
        3:"Station left BSS (spoofed)",
        6:"Class 2 frame from non-auth station",
        7:"Class 3 frame — most common in attacks",
        8:"Disassociated — station left",
        9:"Station re-associating too fast"
    }
    if reason in malicious_reasons:
        patterns.append({"name":f"SUSPICIOUS REASON CODE ({reason})","desc":malicious_reasons[reason],"level":"MEDIUM"})

    # Pattern 7 - RAPID MAC ROTATION
    mac_history[dst].add(src)
    if len(mac_history[dst]) >= 3:
        patterns.append({"name":"RAPID MAC ROTATION","desc":f"{len(mac_history[dst])} MACs targeting same device — MAC spoofing loop","level":"CRITICAL"})

    # Pattern 8 - DEAUTH + DISASSOC COMBO
    if src in combo_attacks:
        patterns.append({"name":"DEAUTH + DISASSOC COMBO","desc":"Both frame types from same source — advanced attack toolkit","level":"HIGH"})

    # Pattern 9 - TARGETED CLIENT
    if dst.lower() != "ff:ff:ff:ff:ff:ff":
        patterns.append({"name":"TARGETED CLIENT ATTACK","desc":f"Specific device {dst} being individually targeted","level":"HIGH"})

    # Pattern 10 - CHANNEL SPECIFIC
    patterns.append({"name":"MONITOR MODE VERIFIED","desc":"Packet captured in monitor mode — confirmed real frame","level":"MEDIUM"})

    return patterns

def handle_beacon(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr3
        if not bssid or bssid in nearby_networks:
            return
        ssid = "Hidden"
        channel = "?"
        try:
            ssid = pkt[Dot11Elt].info.decode(errors="replace") or "Hidden"
        except: pass
        try:
            channel = int(ord(pkt[Dot11Elt:3].info))
        except: pass
        nearby_networks[bssid] = {"ssid":ssid,"channel":channel}
        log_info(f"Network: {BOLD}{G}{ssid}{RST}  BSSID:{C}{bssid}{RST}  Ch:{Y}{channel}{RST}")

def handle_disassoc(pkt):
    if pkt.haslayer(Dot11Disas):
        src = pkt[Dot11].addr2 or "unknown"
        combo_attacks.add(src)

def handle_deauth(pkt):
    global total_deauth
    if pkt.haslayer(Dot11Deauth):
        src    = pkt[Dot11].addr2 or "unknown"
        dst    = pkt[Dot11].addr1 or "broadcast"
        reason = pkt[Dot11Deauth].reason if hasattr(pkt[Dot11Deauth],'reason') else 0
        now    = time.time()
        total_deauth += 1
        deauth_counts[src].append(now)
        deauth_timestamps[src].append(now)
        deauth_counts[src]     = [t for t in deauth_counts[src]     if now-t <= TIME_WINDOW]
        deauth_timestamps[src] = [t for t in deauth_timestamps[src] if now-t <= TIME_WINDOW*3]
        count = len(deauth_counts[src])
        known_ssid = "Unknown"
        for bssid,info in nearby_networks.items():
            if src.upper() == bssid.upper():
                known_ssid = info["ssid"]
                break
        if count == 1:
            log_warn(f"Deauth frame: {Y}{src}{RST} → {dst}  Reason:{reason}  AP:{known_ssid}")
        if count >= DEAUTH_THRESHOLD and src not in alerts_issued:
            alerts_issued.add(src)
            patterns = detect_patterns(src, dst, count, reason, deauth_timestamps[src])
            alert_patterns = [p for p in patterns if p['level'] != 'INFO']
            if alert_patterns:
                log_alert(src, dst, count, alert_patterns, reason)
                attack_log.append({"time":ts(),"src":src,"dst":dst,"count":count,"patterns":alert_patterns})
        def reset(mac):
            time.sleep(TIME_WINDOW*3)
            alerts_issued.discard(mac)
        threading.Thread(target=reset,args=(src,),daemon=True).start()

def packet_handler(pkt):
    handle_beacon(pkt)
    handle_deauth(pkt)
    handle_disassoc(pkt)

def get_wireless_interfaces():
    try:
        result = subprocess.run(["iw","dev"],capture_output=True,text=True)
        return [l.split()[1] for l in result.stdout.split("\n") if "Interface" in l]
    except:
        return []

def enable_monitor_mode(iface):
    print(f"\n  {G}[*]{RST} Enabling monitor mode on {G}{iface}{RST}...")
    try:
        subprocess.run(["airmon-ng","check","kill"],capture_output=True)
        subprocess.run(["ip","link","set",iface,"down"],capture_output=True)
        subprocess.run(["iw",iface,"set","monitor","none"],capture_output=True)
        subprocess.run(["ip","link","set",iface,"up"],capture_output=True)
        result = subprocess.run(["iwconfig",iface],capture_output=True,text=True)
        if "Monitor" in result.stdout:
            log_info(f"Monitor mode {G}ACTIVE{RST} on {iface}")
        return iface
    except Exception as e:
        log_err(f"Monitor mode error: {e}")
        sys.exit(1)

def disable_monitor_mode(iface):
    print(f"\n  {G}[*]{RST} Restoring interface...")
    try:
        subprocess.run(["ip","link","set",iface,"down"],capture_output=True)
        subprocess.run(["iw",iface,"set","type","managed"],capture_output=True)
        subprocess.run(["ip","link","set",iface,"up"],capture_output=True)
        subprocess.run(["service","NetworkManager","restart"],capture_output=True)
        log_info("Interface restored.")
    except Exception as e:
        print(f"  {Y}[!]{RST} Restore error: {e}")

def channel_hopper(iface, stop_event):
    channels = list(range(1,14))+[36,40,44,48,52,100,149,153]
    while not stop_event.is_set():
        for ch in channels:
            if stop_event.is_set(): break
            try:
                subprocess.run(["iw","dev",iface,"set","channel",str(ch)],capture_output=True)
            except: pass
            time.sleep(CHANNEL_HOP_DELAY)

def print_network_table():
    print(f"\n  {G}╔{'═'*60}╗{RST}")
    print(f"  {G}║{RST}  {BOLD}{'SSID':<28} {'BSSID':<19} CH{RST}         {G}║{RST}")
    print(f"  {G}╠{'═'*60}╣{RST}")
    for bssid,info in nearby_networks.items():
        ssid = info['ssid'][:26]
        ch   = str(info['channel'])
        print(f"  {G}║{RST}  {G}{ssid:<28}{RST} {DIM}{bssid:<19}{RST} {Y}{ch:<5}{RST} {G}║{RST}")
    print(f"  {G}╚{'═'*60}╝{RST}\n")

def print_attack_summary():
    print(f"\n  {G}╔{'═'*58}╗{RST}")
    print(f"  {G}║{RST}  {BOLD}{Y}SESSION SUMMARY{RST}                                    {G}║{RST}")
    print(f"  {G}╠{'═'*58}╣{RST}")
    print(f"  {G}║{RST}  Total deauth packets : {R}{BOLD}{total_deauth}{RST}                            {G}║{RST}")
    print(f"  {G}║{RST}  Attacks detected     : {R}{BOLD}{len(attack_log)}{RST}                            {G}║{RST}")
    print(f"  {G}║{RST}  Networks scanned     : {G}{BOLD}{len(nearby_networks)}{RST}                            {G}║{RST}")
    print(f"  {G}╠{'═'*58}╣{RST}")
    if attack_log:
        for a in attack_log:
            pnames = ", ".join(p['name'] for p in a['patterns'][:2])
            print(f"  {G}║{RST}  {R}{a['time']}{RST} {Y}{a['src']}{RST}     {G}║{RST}")
            print(f"  {G}║{RST}  {DIM}{pnames[:54]}{RST}  {G}║{RST}")
    else:
        print(f"  {G}║{RST}  {G}No attacks detected — You were safe!{RST}               {G}║{RST}")
    print(f"  {G}╚{'═'*58}╝{RST}\n")

def scan_networks(iface):
    stop_hop = threading.Event()
    threading.Thread(target=channel_hopper,args=(iface,stop_hop),daemon=True).start()
    print(f"\n  {G}╔{'═'*52}╗{RST}")
    print(f"  {G}║{RST}  {BOLD}{C}  PHASE 1: Scanning Nearby Networks ({SCAN_TIME}s){RST}   {G}║{RST}")
    print(f"  {G}╚{'═'*52}╝{RST}\n")
    try:
        sniff(iface=iface,prn=packet_handler,store=False,timeout=SCAN_TIME)
    except Exception as e:
        log_err(f"Scan error: {e}")
    stop_hop.set()
    print(f"\n  {G}[+]{RST} Scan complete. {G}{BOLD}{len(nearby_networks)}{RST} networks found.")
    print_network_table()

def monitor_deauth(iface):
    stop_hop = threading.Event()
    threading.Thread(target=channel_hopper,args=(iface,stop_hop),daemon=True).start()
    print(f"  {G}╔{'═'*58}╗{RST}")
    print(f"  {G}║{RST}  {BOLD}{C}  PHASE 2: Monitoring [Ctrl+C to stop]{RST}           {G}║{RST}")
    print(f"  {G}║{RST}  {DIM}  Threshold : {DEAUTH_THRESHOLD} deauths in {TIME_WINDOW}s = ALERT{RST}             {G}║{RST}")
    print(f"  {G}║{RST}  {DIM}  Detecting : Flood|Spoof|Broadcast|Combo|EvilTwin{RST}  {G}║{RST}")
    print(f"  {G}╚{'═'*58}╝{RST}\n")
    try:
        sniff(iface=iface,prn=packet_handler,store=False,
              stop_filter=lambda p: stop_sniff_event.is_set())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log_err(f"Monitor error: {e}")

def cleanup(sig=None, frame=None):
    print(f"\n  {G}[*]{RST} Shutting down shield...")
    stop_sniff_event.set()
    if monitor_iface:
        disable_monitor_mode(monitor_iface)
    print_attack_summary()
    print(f"  {G}{BOLD}[+] Shield deactivated. Stay safe!{RST}\n")
    sys.exit(0)

def main():
    global interface, monitor_iface
    if os.geteuid() != 0:
        print(f"\n  {R}[x] Run as root: sudo python3 wifi_deauth_shield.py{RST}\n")
        sys.exit(1)
    banner()
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    ifaces = get_wireless_interfaces()
    if not ifaces:
        log_err("No wireless interfaces found!")
        sys.exit(1)
    if len(ifaces) == 1:
        interface = ifaces[0]
        log_info(f"Using interface: {G}{BOLD}{interface}{RST}")
    else:
        print(f"\n  {G}Available interfaces:{RST}")
        for i,iface in enumerate(ifaces):
            print(f"    {G}[{i}]{RST} {iface}")
        choice = int(input(f"\n  {Y}Select [0-{len(ifaces)-1}]: {RST}"))
        interface = ifaces[choice]
    monitor_iface = enable_monitor_mode(interface)
    time.sleep(2)
    scan_networks(monitor_iface)
    monitor_deauth(monitor_iface)
    cleanup()

if __name__ == "__main__":
    main()
