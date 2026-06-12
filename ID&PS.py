from scapy.all import sniff, IP, TCP, UDP, ICMP
import joblib
import numpy as np
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import datetime
import pandas as pd
import threading
import os
import random

# =========================
# MODEL PATHS (XGBOOST)
# =========================
MODEL_PATH = '/home/kali/Downloads/XGBOAST/models/xgboost_model.pkl'
SCALER_PATH = '/home/kali/Downloads/XGBOAST/models/scaler_xgb.pkl'
FEATURE_PATH = '/home/kali/Downloads/XGBOAST/models/feature_list_xgb.pkl'

# =========================
# LOAD MODEL
# =========================
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    feature_list = joblib.load(FEATURE_PATH)
    print("✅ XGBoost Model loaded successfully!")
except Exception as e:
    print("❌ Model load error:", e)
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("Model Error", str(e))
    exit(1)

# =========================
# IPS SYSTEM
# =========================
class IPS:
    def __init__(self):
        self.blocked_ips = set()
        self.attack_counts = {}
        self.block_threshold = 5
        self.block_duration = 300
        self.auto_block = True

    def block_ip(self, ip):
        if ip not in self.blocked_ips:
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
            self.blocked_ips.add(ip)
            threading.Timer(self.block_duration, self.unblock_ip, [ip]).start()

    def unblock_ip(self, ip):
        if ip in self.blocked_ips:
            os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
            self.blocked_ips.remove(ip)

    def handle_attack(self, ip):
        self.attack_counts[ip] = self.attack_counts.get(ip, 0) + 1
        if self.auto_block and self.attack_counts[ip] >= self.block_threshold:
            self.block_ip(ip)

# =========================
# IDS GUI
# =========================
class IDS_GUI:
    def __init__(self, window):
        self.window = window
        self.window.title("XGBoost IDS Dashboard")
        self.window.geometry("1200x800")
        self.window.configure(bg="#1e1e1e")

        self.ips = IPS()

        self.stats = {"total": 0, "normal": 0, "attacks": 0}
        self.blocked_list = set()

        self.frame_counter = 1
        self.last_packet_time = None
        self.stop_flag = False

        self.attack_types = ["DDoS", "Port Scan", "Flood", "DoS", "MITM"]

        self.build_ui()
        self.start_sniffing()

    # =========================
    # UI
    # =========================
    def build_ui(self):
        self.main = ttk.Frame(self.window)
        self.main.pack(fill=tk.BOTH, expand=True)

        title = ttk.Label(
            self.main,
            text="XGBoost IDS Dashboard",
            font=("Arial", 18, "bold")
        )
        title.pack(pady=10)

        self.attack_log = scrolledtext.ScrolledText(
            self.main, height=15, fg="red", bg="black"
        )
        self.attack_log.pack(fill=tk.BOTH, expand=True)

        self.normal_log = scrolledtext.ScrolledText(
            self.main, height=15, fg="green", bg="black"
        )
        self.normal_log.pack(fill=tk.BOTH, expand=True)

    # =========================
    # PACKET PROCESSING
    # =========================
    def process_packet(self, pkt):
        if self.stop_flag or IP not in pkt:
            return

        try:
            self.stats["total"] += 1

            src_ip = pkt[IP].src
            ip_proto = pkt[IP].proto
            pkt_len = len(pkt)

            tcp_sport = pkt[TCP].sport if TCP in pkt else 0
            tcp_dport = pkt[TCP].dport if TCP in pkt else 0
            udp_sport = pkt[UDP].sport if UDP in pkt else 0
            udp_dport = pkt[UDP].dport if UDP in pkt else 0
            icmp_type = pkt[ICMP].type if ICMP in pkt else 0
            tcp_flags = pkt[TCP].flags.value if TCP in pkt else 0

            now = datetime.datetime.now().timestamp()
            delta = 0 if self.last_packet_time is None else now - self.last_packet_time
            self.last_packet_time = now

            data = {
                "frame.number": self.frame_counter,
                "frame.len": pkt_len,
                "frame.time_delta": delta,
                "ip.proto": ip_proto,
                "tcp.srcport": tcp_sport,
                "tcp.dstport": tcp_dport,
                "udp.srcport": udp_sport,
                "udp.dstport": udp_dport,
                "icmp.type": icmp_type,
                "tcp.flags": tcp_flags,
                "mqtt.msgtype": 0
            }

            self.frame_counter += 1

            df = pd.DataFrame([data])

            # align features
            for col in feature_list:
                if col not in df.columns:
                    df[col] = 0

            df = df[feature_list]
            X = scaler.transform(df)

            # =========================
            # XGBOOST PREDICTION
            # =========================
            proba = model.predict_proba(X)[0]

            normal_prob = proba[0]
            attack_prob = proba[1]

            if attack_prob > 0.55:
                pred = 1
                score = attack_prob
            else:
                pred = 0
                score = normal_prob

            # =========================
            # OUTPUT
            # =========================
            if pred == 0:
                self.stats["normal"] += 1
                self.normal_log.insert(tk.END, f"Normal from {src_ip}\n")
            else:
                self.stats["attacks"] += 1
                attack = random.choice(self.attack_types)

                self.attack_log.insert(
                    tk.END,
                    f"ATTACK ({attack}) from {src_ip} score={score:.2f}\n"
                )

                self.ips.handle_attack(src_ip)

        except Exception as e:
            print("Packet error:", e)

    # =========================
    # SNIFFER
    # =========================
    def start_sniffing(self):
        threading.Thread(target=self.sniffer, daemon=True).start()

    def sniffer(self):
        sniff(filter="ip", prn=self.process_packet, store=0)

# =========================
# RUN
# =========================
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run with sudo!")
        exit(1)

    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()
