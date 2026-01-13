#!/bin/bash
# Zabbix Agent Enumeration Script (10050)
# Runs Nmap + key enumeration using netcat and saves per-host output.

IPS_FILE="${1:-zabbix_ips.txt}"
OUTDIR="ZABBIX_10050_ENUM_$(date +%F_%H%M)"
mkdir -p "$OUTDIR"

if [[ ! -f "$IPS_FILE" ]]; then
  echo "[-] File not found: $IPS_FILE"
  echo "Usage: $0 zabbix_ips.txt"
  exit 1
fi

KEYS=(
  "agent.ping"
  "agent.version"
  "system.hostname"
  "system.uname"
  "system.uptime"
  "net.tcp.listen[3389]"
)

echo "[+] Zabbix 10050 Enumeration Started"
echo "[+] Targets: $IPS_FILE"
echo "[+] Output: $OUTDIR"
echo ""

while read -r IP; do
  [[ -z "$IP" || "$IP" =~ ^# ]] && continue

  HOSTDIR="$OUTDIR/$IP"
  mkdir -p "$HOSTDIR"

  echo "==============================================="
  echo "[*] Target: $IP:10050"
  echo "==============================================="

  # 1) Nmap fingerprint
  nmap -p10050 -sV -Pn "$IP" -oN "$HOSTDIR/01_nmap_service.txt" 2>/dev/null
  nmap -p10050 -Pn --script banner "$IP" -oN "$HOSTDIR/02_nmap_banner.txt" 2>/dev/null

  # 2) Connectivity test
  timeout 3 nc -zv "$IP" 10050 > "$HOSTDIR/03_nc_connectivity.txt" 2>&1

  # 3) Enumerate common keys
  OUTKEY="$HOSTDIR/04_key_enum.txt"
  {
    echo "[+] Key Enumeration Output"
    echo "[+] Note: timeout used to ensure response is captured."
    echo ""
  } > "$OUTKEY"

  for key in "${KEYS[@]}"; do
    echo "===== $key =====" >> "$OUTKEY"
    echo -ne "${key}\n" | timeout 3 nc -nv "$IP" 10050 >> "$OUTKEY" 2>&1
    echo "" >> "$OUTKEY"
  done

  # 4) Check system.run[] (DO NOT exploit; only check)
  echo "===== system.run[id] (check-only) =====" >> "$OUTKEY"
  echo -ne "system.run[id]\n" | timeout 3 nc -nv "$IP" 10050 >> "$OUTKEY" 2>&1
  echo "" >> "$OUTKEY"

  echo "[+] Completed $IP"
  echo ""

done < "$IPS_FILE"

echo "[✅] Completed. Results saved in: $OUTDIR"
