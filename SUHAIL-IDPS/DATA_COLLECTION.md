# Collecting your own IDPS dataset (normal + attack)

This guide walks you end-to-end: capture raw traffic with `tcpdump`, generate
labelled **normal** and **attack** traffic on a lab you own, then convert the
PCAPs into the flow-based training dataset and train the three barriers.

> ⚠️ **Only do this on machines/networks you own or are explicitly authorised to
> test.** Generating attacks against systems you don't control is illegal.

---

## 0. Lab setup — one computer (single-box Kali)

You do **not** need two machines. One Kali box can be both the attacker and the
victim: it attacks **its own IP address**, and the IDPS captures on the same
interface. This is a standard way to build these datasets.

```
        ┌──────────────────────────────────────────────┐
        │                ONE KALI MACHINE               │
        │                                               │
        │   attacker tools  ───►  its own Wi-Fi IP      │
        │   (nmap/hping3)         (e.g. 192.168.1.50)   │
        │                                               │
        │   victim services (web/ssh) listen here       │
        │   tcpdump captures on the Wi-Fi interface     │
        └──────────────────────────────────────────────┘
                   also: browse the internet
                   over the same Wi-Fi = normal traffic
```

### ⚠️ One key rule: attack your real IP, NOT `127.0.0.1`

Don't point attacks at `localhost` / `127.0.0.1`. **Loopback traffic isn't
realistic** — no real MTU, near-zero latency, different packet behaviour — so the
flow features won't resemble real network attacks and the models learn the wrong
thing. Instead, attack the machine's **own LAN/Wi-Fi IP** and capture on the
Wi-Fi interface. The packets then traverse a realistic path even though one
machine plays both roles.

### Find your interface and IP

```bash
ip -brief addr
#   pick your Wi-Fi NIC + its address, e.g.:
#   wlan0   UP   192.168.1.50/24
```

Set two shell variables so the rest of the commands are copy-paste:

```bash
IFACE=wlan0                 # your Wi-Fi interface from above
MYIP=192.168.1.50           # this machine's own IP from above
```

### Start a victim service (so there's something to attack/scan)

```bash
# a simple web server to scan / slowloris / brute-force against
python3 -m http.server 8000 &          # serves on all interfaces, port 8000
# (Kali usually already runs ssh on 22; start it if you want: sudo systemctl start ssh)
```

---

## 1. Capture NORMAL traffic

Start the capture, then **actually use the internet normally** for a good while
over that same Wi-Fi — browse sites, watch a video, `apt update`, download a big
file, `git pull`, etc. Aim for **20–40+ minutes** so flows are diverse.

```bash
sudo tcpdump -i "$IFACE" -nn -s 0 ip \
     -w captures/normal_%Y%m%d_%H%M%S.pcap -G 600 -W 6

#   -i $IFACE   capture interface (your Wi-Fi NIC)
#   -nn         don't resolve names/ports (faster, cleaner)
#   -s 0        full packet (snaplen 0 = no truncation)
#   ip          BPF filter: only IP traffic
#   -w ...      output PCAP (strftime pattern)
#   -G 600      rotate every 600s (10 min)
#   -W 6        keep at most 6 files (≈1 hour)
```

While it runs, generate varied normal activity, e.g.:
```bash
curl -s https://example.com -o /dev/null       # web
sudo apt update                                # package metadata
wget -q https://speed.hetzner.de/100MB.bin -O /tmp/d.bin   # a real download
ping -c 20 1.1.1.1                             # icmp
# + just browse / stream / use the machine normally
```

Stop with `Ctrl+C`. You now have one or more `normal_*.pcap` files.

---

## 2. Capture ATTACK traffic

Capture **one PCAP per attack type** — clean labels, and you can analyse each
attack separately later. The target is **your own IP** (`$MYIP`), so it's all one
machine. Start the capture, run the attack in another terminal, stop the capture.

> All commands below assume you still have `IFACE` and `MYIP` set from step 0.
> Open a **second terminal** for the attack while tcpdump runs in the first.

```bash
# generic pattern: start capture (terminal 1), run attack (terminal 2), Ctrl+C
sudo tcpdump -i "$IFACE" -nn -s 0 ip -w captures/attack_portscan.pcap
```

### a) Port / service scan (nmap)
```bash
# scanning your own machine's real IP
nmap -sS -p 1-65535 "$MYIP"          # SYN/stealth scan
nmap -sV -p- "$MYIP"                 # service/version scan
nmap -sU --top-ports 200 "$MYIP"     # UDP scan
```

### b) SYN flood / DoS (hping3)
```bash
sudo hping3 -S --flood -p 8000 "$MYIP"            # SYN flood (web port)
sudo hping3 --udp --flood -p 53 "$MYIP"           # UDP flood
sudo hping3 -1 --flood "$MYIP"                    # ICMP flood
# let each run ~20–30s then Ctrl+C — --flood is very fast
```

### c) Slow HTTP DoS (slowloris-style)
```bash
slowhttptest -c 500 -H -i 10 -r 200 -u "http://$MYIP:8000/"   # Slowloris
# or: pip install slowloris && slowloris "$MYIP" -p 8000
```

### d) Brute force (hydra)
```bash
# needs a service to brute — ssh (sudo systemctl start ssh) or the web server
hydra -l root -P /usr/share/wordlists/rockyou.txt "ssh://$MYIP"
```

### e) (optional) MQTT abuse, if running a broker
```bash
mosquitto_pub -h "$MYIP" -t x -m "$(head -c 5000 /dev/urandom | base64)" &
```

Capture **each** of these to its own file: `attack_synflood.pcap`,
`attack_portscan.pcap`, `attack_slowloris.pcap`, `attack_bruteforce.pcap`, …

> **Single-box note:** because the attacker and victim are the same machine, the
> capture sees both the attack packets *and* the victim's replies — which is
> exactly what a real IDPS sees, so that's fine. Keep a little normal browsing
> going during attacks too (real captures are never 100% attack); the *attack*
> PCAP is still labelled `1` wholesale here for simplicity.
>
> **Wi-Fi gotcha:** if hping3/nmap to your own Wi-Fi IP doesn't show up in the
> capture, your kernel may be short-circuiting same-host traffic. Two easy fixes:
> capture on the loopback-free path by targeting the IP (already done above), or
> if needed run the victim service in a quick container / VM bridged to the same
> Wi-Fi and point attacks at *its* IP. For most setups targeting `$MYIP` on
> `$IFACE` works directly.

---

## 3. Convert PCAPs → flow dataset

The conversion assembles bidirectional flows (CICFlowMeter-style) and writes the
canonical feature schema. Label `0` = normal, `1` = attack.

```bash
cd SUHAIL-IDPS

# normal
python3 src/preprocessing/pcap_to_flows.py \
    --pcap captures/normal_*.pcap --label 0 \
    --out data/flows/normal_flows.csv

# attacks (each with a sub-label you can inspect later, all label 1)
python3 src/preprocessing/pcap_to_flows.py --pcap captures/attack_portscan.pcap \
    --label 1 --attack-type portscan  --out data/flows/portscan_flows.csv
python3 src/preprocessing/pcap_to_flows.py --pcap captures/attack_synflood.pcap \
    --label 1 --attack-type synflood  --out data/flows/synflood_flows.csv
python3 src/preprocessing/pcap_to_flows.py --pcap captures/attack_slowloris.pcap \
    --label 1 --attack-type slowloris --out data/flows/slowloris_flows.csv
python3 src/preprocessing/pcap_to_flows.py --pcap captures/attack_bruteforce.pcap \
    --label 1 --attack-type bruteforce --out data/flows/bruteforce_flows.csv
```

Merge everything into one shuffled dataset:

```bash
python3 src/preprocessing/merge_flows.py \
    --in data/flows/normal_flows.csv \
         data/flows/portscan_flows.csv \
         data/flows/synflood_flows.csv \
         data/flows/slowloris_flows.csv \
         data/flows/bruteforce_flows.csv \
    --out data/flows/all_flows.csv
```

Build the per-host **sequences** for the transformer barrier:

```bash
python3 src/preprocessing/build_flow_sequences.py \
    --in  data/flows/all_flows.csv \
    --out data/flows/flow_sequences.csv
```

---

## 4. Train the three barriers

Each model trains on its correct format (see `src/training/`):

```bash
# Barrier 1 — routine, single-flow tabular  (needs xgboost)
python3 src/training/train_xgboost.py     --data data/flows/all_flows.csv

# Barrier 3 — zero-day, NORMAL flows only   (needs tensorflow)
python3 src/training/train_autoencoder.py --data data/flows/all_flows.csv

# Barrier 2 — context, per-host sequences   (needs tensorflow)
python3 src/training/train_transformer.py --data data/flows/flow_sequences.csv
```

Artifacts land in `models/{xgboost,autoencoder,transformer}/`. Restart the
dashboard (or **Models → Reload Models**) to serve the freshly trained models.

---

## 5. Data-quality checklist (what makes a *good* IDS dataset)

- **Balance, but not perfectly.** Real traffic is mostly normal. Aim for roughly
  60–80% normal / 20–40% attack across the merged set. The trainers already
  weight the imbalance (`scale_pos_weight`).
- **Diversity of normal.** Many services/ports/sizes — not just one `curl` loop.
  A monotone "normal" makes the autoencoder flag everything.
- **Realistic attacks.** Vary intensity and timing (don't only `--flood`). Mix
  in slow attacks (slowloris) so it's not just "high packet rate = attack".
- **Enough flows.** A few thousand flows per class minimum; tens of thousands is
  better for the transformer.
- **Separate captures per attack** for clean labels and per-type analysis.
- **Same network conditions** for normal and attack captures (same NIC, same
  victim) so the model learns the *attack*, not the *capture environment*.

---

## Why flow-based features (vs. the old per-packet CSVs)

The original dataset was per-packet with several columns mean-imputed to
constants — which carry no signal and inflate anomaly scores. The modern NIDS
literature (CIC-IDS2017/2018, UNSW-NB15, and most recent papers) uses
**bidirectional flow** features: each network conversation is summarised by
duration, byte/packet rates, packet-size and inter-arrival statistics, and TCP
flag counts. These describe *behaviour* (a scan, a flood, a slow-DoS) far better
than any single packet, and they're exactly what `src/core/flow_features.py`
computes — identically for training (from PCAP) and live serving (from the
capture stream), so there's no train/serve skew.
