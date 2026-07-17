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

## 2. Capture ATTACK traffic (single box, Docker victim)

On one machine you should **not** attack your own IP directly: the kernel routes
traffic to your own address over **loopback** (MTU 65536, zero latency), which is
unrealistic and would clash with your Wi-Fi-captured normal data. The clean
single-box method is to attack a **local Docker container** as the victim — the
traffic then crosses a real bridge interface (MTU 1500), just like real traffic.

`collect_attack.sh` automates all of this: it auto-detects the victim container
and bridge, captures **one filtered PCAP per attack type**, and writes a
**metadata JSON** next to each PCAP so the converter can label *only* the true
attack flows (any background traffic in the same capture stays benign — the way
CIC-IDS2017 / UNSW-NB15 are labelled).

### Prereqs
```bash
sudo apt install -y nmap hping3 slowhttptest      # attack tools (Kali has them; Ubuntu doesn't)
# a victim web app on the docker bridge — e.g. a WordPress/Apache container.
docker ps            # note the victim container name + that it's on a 172.x bridge
```

### Run it
```bash
cd SUHAIL-IDPS
sudo ./collect_attack.sh                 # all attacks: portscan synflood udpflood icmpflood slowloris httpflood
# or one at a time:
sudo ./collect_attack.sh synflood
# override auto-detection if needed:
sudo VICTIM=172.18.0.4 IFACE=br-1fbaeb82b180 WP_CONTAINER=pen_af_wp ./collect_attack.sh
```

It produces, in `../dataset/attack/`:
```
attack_portscan.pcap   attack_portscan.meta.json
attack_synflood.pcap   attack_synflood.meta.json
attack_udpflood.pcap   ...
attack_icmpflood.pcap
attack_slowloris.pcap
attack_httpflood.pcap
```
Each `.meta.json` records the victim/attacker IPs, attacked port(s) and the
attack time window.

> **Why a container victim, not `127.0.0.1`?** Loopback traffic has a 65536-byte
> MTU and near-zero latency, so its flow features don't resemble real network
> traffic (and wouldn't match your normal Wi-Fi data). A Docker container sits on
> a real L2 bridge (MTU 1500), so attack flows are realistic. No second machine
> needed.
>
> **Not 100% attack — and that's correct.** Real IDS datasets keep a little
> background traffic in attack captures and label at the *flow* level, not the
> file level. The metadata JSON + `--meta` flag below do exactly that.

---

## 3. Convert PCAPs → flow dataset

The conversion assembles bidirectional flows (CICFlowMeter-style) and writes the
canonical feature schema. Label `0` = normal, `1` = attack.

```bash
cd SUHAIL-IDPS

# normal — whole capture is benign, wholesale label 0
python3 src/preprocessing/pcap_to_flows.py \
    --pcap ../dataset/normal/*.pcap --label 0 \
    --out data/flows/normal_flows.csv

# attacks — windowed labelling via each capture's .meta.json:
#   only attacker<->victim flows on the attacked port(s), inside the attack
#   window, get label 1; background flows stay 0.
for p in ../dataset/attack/attack_*.pcap; do
  python3 src/preprocessing/pcap_to_flows.py \
      --pcap "$p" --label 1 --meta "${p%.pcap}.meta.json" \
      --out "data/flows/$(basename "${p%.pcap}").csv"
done
```

> Without a Docker victim you *can* still label wholesale (`--label 1` with no
> `--meta`), or pass the signature by hand:
> `--victim-ip <ip> --attacker-ip <ip> --victim-ports 80 443`.

Merge everything into one shuffled dataset (normal + every attack CSV).

> ⚠️ **Balance the flood attacks.** A SYN/UDP flood uses a new source port per
> packet, so it explodes into *tens of thousands* of 1-packet flows that would
> swamp the normal class and the other attacks (a real run here gave ~65k SYN
> flows vs ~960 slowloris vs 1 ICMP). Use `--cap-per-attack` to subsample each
> attack type to a sane size — standard practice for flow-based DoS data.

```bash
python3 src/preprocessing/merge_flows.py \
    --in data/flows/normal_flows.csv data/flows/attack_*.csv \
    --out data/flows/all_flows.csv \
    --cap-per-attack 2500        # each attack_type -> <= 2500 flows
    # optional: --cap-normal 8000   to also cap the benign side
```

The merge prints the before/after attack breakdown and the final attack:normal
ratio so you can see the balance. (Note: an ICMP flood is inherently a *single*
flow — no ports to separate it — so that class stays tiny; that's expected.)

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
