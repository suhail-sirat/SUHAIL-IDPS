#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# collect_normal_topup.sh — capture a DIVERSE "normal" traffic top-up.
#
# Fixes the HTTPS-monoculture in the existing normal dataset by generating a
# rich mix of everyday client protocols (DNS, ICMP, HTTP, HTTPS, FTP, SSH,
# mail-TLS, NTP, WHOIS) while tcpdump records them — then you fold the PCAP
# into dataset/normal/ and re-run the analyzer.
#
# Run:   sudo ./collect_normal_topup.sh
#        sudo DURATION=1200 IFACE=wlp2s0 ./collect_normal_topup.sh
#
# Needs root (for tcpdump). Traffic generators run as normal tools.
# ---------------------------------------------------------------------------
set -uo pipefail

IFACE="${IFACE:-wlp2s0}"
DURATION="${DURATION:-1000}"          # seconds of capture (~16 min default)
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTDIR="${OUTDIR:-$HERE/../dataset/normal}"
STAMP="$(date +%Y%m%d_%H%M%S)"
PCAP="$OUTDIR/normal_topup_${STAMP}.pcap"

if [[ $EUID -ne 0 ]]; then
  echo "!! Please run with sudo (tcpdump needs root):  sudo ./collect_normal_topup.sh"
  exit 1
fi
mkdir -p "$OUTDIR"

# --- VPN / route sanity check --------------------------------------------
DEFROUTE="$(ip route get 1.1.1.1 2>/dev/null || true)"
if grep -qE 'proton0|tun0|wg0' <<<"$DEFROUTE"; then
  echo "!! WARNING: default route looks like a VPN tunnel:"
  echo "   $DEFROUTE"
  echo "   Disconnect ProtonVPN so we capture DIVERSE real endpoints on $IFACE."
  read -r -p "   Continue anyway? [y/N] " ans
  [[ "${ans:-N}" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }
fi
if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "!! Interface $IFACE not found. Set IFACE=... (see: ip -brief addr)"; exit 1
fi

echo "=============================================================="
echo "  Normal top-up capture"
echo "  iface=$IFACE  duration=${DURATION}s  out=$(basename "$PCAP")"
echo "=============================================================="

# --- start capture --------------------------------------------------------
tcpdump -i "$IFACE" -nn -s 0 ip -w "$PCAP" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 2
if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
  echo "!! tcpdump failed to start (bad interface/permissions)."; exit 1
fi
echo "capture running (pid $TCPDUMP_PID) ..."

cleanup() {
  echo; echo "stopping capture ..."
  kill -INT "$TCPDUMP_PID" 2>/dev/null || true
  wait "$TCPDUMP_PID" 2>/dev/null || true
  if [[ -f "$PCAP" ]]; then
    echo "saved: $PCAP  ($(du -h "$PCAP" | cut -f1))"
    echo "next:  python3 src/preprocessing/analyze_captures.py --dir ../dataset/normal"
  fi
}
trap cleanup EXIT INT TERM

have() { command -v "$1" >/dev/null 2>&1; }

# --- target pools ---------------------------------------------------------
DOMAINS=(google.com cloudflare.com wikipedia.org github.com amazon.com
  microsoft.com apple.com mozilla.org reddit.com stackoverflow.com bbc.com
  nytimes.com netflix.com spotify.com dropbox.com gitlab.com debian.org
  archlinux.org ubuntu.com python.org kernel.org cdnjs.com jsdelivr.net
  fastly.com akamai.com wordpress.org medium.com twitch.tv)
HTTP_SITES=(http://neverssl.com http://example.com http://cp.cloudflare.com/
  http://httpforever.com http://info.cern.ch http://ftp.gnu.org/)
HTTPS_SITES=(https://www.google.com https://en.wikipedia.org https://www.debian.org
  https://www.python.org https://github.com https://www.cloudflare.com
  https://www.mozilla.org https://news.ycombinator.com https://www.bbc.com)
PING_HOSTS=(1.1.1.1 8.8.8.8 9.9.9.9 google.com github.com wikipedia.org)
DL_FILES=(http://speedtest.tele2.net/10MB.zip
  https://speed.hetzner.de/10MB.bin
  http://ftp.gnu.org/gnu/wget/wget-1.21.tar.gz)
FTP_URLS=(ftp://ftp.gnu.org/gnu/bash/ ftp://ftp.debian.org/debian/)
SSH_HOSTS=(git@github.com git@gitlab.com)
MAIL_TLS=(imap.gmail.com:993 pop.gmail.com:995 smtp.gmail.com:465)

ntp_query() {  # small NTP request over UDP/123 (no ntpdate dependency)
  have python3 || return 0
  for srv in time.google.com pool.ntp.org time.cloudflare.com; do
    timeout 3 python3 - "$srv" <<'PY' 2>/dev/null || true
import socket,sys,struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
try:
    s.sendto(b'\x1b'+47*b'\0',(sys.argv[1],123)); s.recvfrom(48)
except Exception: pass
finally: s.close()
PY
  done
}

# --- generator loop -------------------------------------------------------
end=$((SECONDS + DURATION))
round=0
while [ $SECONDS -lt $end ]; do
  round=$((round+1))
  remain=$((end - SECONDS))
  echo "  round $round  (${remain}s left) — dns/icmp/http/https/ftp/ssh/mail/ntp"

  # DNS: many small UDP/53 flows, varied record types
  if have dig; then
    for d in "${DOMAINS[@]}"; do
      dig +short +time=2 +tries=1 "$d" A     >/dev/null 2>&1 &
      dig +short +time=2 +tries=1 "$d" AAAA  >/dev/null 2>&1 &
      dig +short +time=2 +tries=1 "$d" MX    >/dev/null 2>&1 &
    done
  elif have nslookup; then
    for d in "${DOMAINS[@]}"; do nslookup "$d" >/dev/null 2>&1 & done
  fi

  # ICMP baseline
  for h in "${PING_HOSTS[@]}"; do ping -c 3 -W 2 "$h" >/dev/null 2>&1 & done
  have traceroute && traceroute -q1 -w2 -m12 1.1.1.1 >/dev/null 2>&1 &

  # HTTP (plain :80) + HTTPS browsing (parallel, browser-like)
  if have curl; then
    for u in "${HTTP_SITES[@]}";  do curl -s -m 15 -A "Mozilla/5.0" -o /dev/null "$u" & done
    for u in "${HTTPS_SITES[@]}"; do curl -s -m 15 -A "Mozilla/5.0" -o /dev/null "$u" & done
    # FTP listings/fetches (:21 + data)
    for u in "${FTP_URLS[@]}"; do curl -s -m 20 -l "$u" -o /dev/null & done
  fi

  # a couple of real bulk downloads for volume + long flows
  if have curl; then
    for u in "${DL_FILES[@]}"; do curl -s -m 45 -o /dev/null "$u" & done
  elif have wget; then
    for u in "${DL_FILES[@]}"; do wget -q -T 45 -O /dev/null "$u" & done
  fi

  # SSH handshakes (real port-22 sessions, no account needed)
  if have ssh; then
    for h in "${SSH_HOSTS[@]}"; do
      timeout 12 ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 \
        -o BatchMode=yes -T "$h" >/dev/null 2>&1 &
    done
  fi

  # Mail-protocol TLS handshakes (IMAPS/POP3S/SMTPS) — no login
  if have openssl; then
    for hp in "${MAIL_TLS[@]}"; do
      timeout 8 bash -c "echo QUIT | openssl s_client -connect $hp -crlf" \
        >/dev/null 2>&1 &
    done
  fi

  # WHOIS (:43) + NTP (:123)
  have whois && { whois google.com >/dev/null 2>&1 & whois -h whois.iana.org . >/dev/null 2>&1 & }
  ntp_query &

  # let this round's parallel work run, then wait for THIS ROUND's generator
  # jobs to finish — but NOT tcpdump (it runs until we kill it; waiting on it
  # would hang the loop forever).
  sleep 20
  for p in $(jobs -p); do
    [ "$p" = "$TCPDUMP_PID" ] && continue
    wait "$p" 2>/dev/null || true
  done
done

echo "generator finished ($round rounds)."
# cleanup() runs on EXIT
