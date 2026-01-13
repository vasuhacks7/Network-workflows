#!/bin/bash
# WinRM HTTPS (5986) Enumeration Script - Updated
# Runs:
#  - nmap service detection
#  - nmap http scripts
#  - TLS certificate & cipher checks
#  - curl HEAD/GET/POST /wsman
#  - extract WWW-Authenticate headers + detect Basic auth
#
# Usage:
#   chmod +x winrm_5986_enum_all.sh
#   ./winrm_5986_enum_all.sh winrm_5986_ips.txt

IPS_FILE="${1:-winrm_5986_ips.txt}"
OUTDIR="WINRM_5986_ENUM_$(date +%F_%H%M)"
mkdir -p "$OUTDIR"

if [[ ! -f "$IPS_FILE" ]]; then
  echo "[-] File not found: $IPS_FILE"
  echo "Usage: $0 winrm_5986_ips.txt"
  exit 1
fi

# Disable proxy for clean internal scanning
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY

echo "[+] WinRM 5986 Enumeration Started"
echo "[+] Targets: $IPS_FILE"
echo "[+] Output: $OUTDIR"
echo ""

while read -r IP; do
  [[ -z "$IP" || "$IP" =~ ^# ]] && continue

  HOSTDIR="$OUTDIR/$IP"
  mkdir -p "$HOSTDIR"

  echo "==============================================="
  echo "[*] Target: $IP:5986 (WinRM HTTPS)"
  echo "==============================================="

  # 1) Service detection
  nmap -p5986 -sV -Pn "$IP" -oN "$HOSTDIR/01_nmap_service.txt" 2>/dev/null

  # 2) HTTP scripts
  nmap -p5986 -Pn --script "http-title,http-methods,http-headers,http-auth-finder" "$IP" \
    -oN "$HOSTDIR/02_nmap_http_scripts.txt" 2>/dev/null

  # 3) TLS certificate & ciphers
  nmap -p5986 -Pn --script "ssl-cert,ssl-enum-ciphers" "$IP" \
    -oN "$HOSTDIR/03_nmap_tls.txt" 2>/dev/null

  # 4) OpenSSL cert extraction (proof)
  openssl s_client -connect "$IP:5986" </dev/null 2>/dev/null | \
    openssl x509 -noout -subject -issuer -dates -ext subjectAltName \
    > "$HOSTDIR/04_openssl_cert_details.txt" 2>&1

  # 5) Curl tests for /wsman (HEAD + GET + POST)
  echo "[+] Curl /wsman checks..."

  curl -skvI "https://$IP:5986/wsman" > "$HOSTDIR/05_curl_HEAD_wsman.txt" 2>&1
  curl -skv  "https://$IP:5986/wsman" > "$HOSTDIR/06_curl_GET_wsman.txt" 2>&1

  # POST is important to trigger WWW-Authenticate
  curl -skv -X POST "https://$IP:5986/wsman" > "$HOSTDIR/07_curl_POST_wsman.txt" 2>&1

  # POST with body (more realistic)
  curl -skv -X POST "https://$IP:5986/wsman" -d "<s></s>" > "$HOSTDIR/08_curl_POST_body_wsman.txt" 2>&1

  # 6) Extract authentication headers
  AUTH_FILE="$HOSTDIR/09_auth_headers.txt"
  {
    echo "=== Auth header extraction for $IP:5986 ==="
    echo ""
    echo "[HEAD]"
    grep -iE "HTTP/|WWW-Authenticate:|server:|allow:" "$HOSTDIR/05_curl_HEAD_wsman.txt" || true
    echo ""
    echo "[GET]"
    grep -iE "HTTP/|WWW-Authenticate:|server:|allow:" "$HOSTDIR/06_curl_GET_wsman.txt" || true
    echo ""
    echo "[POST]"
    grep -iE "HTTP/|WWW-Authenticate:|server:|allow:" "$HOSTDIR/07_curl_POST_wsman.txt" || true
    echo ""
    echo "[POST BODY]"
    grep -iE "HTTP/|WWW-Authenticate:|server:|allow:" "$HOSTDIR/08_curl_POST_body_wsman.txt" || true
  } > "$AUTH_FILE"

  # 7) Detect if Basic authentication is enabled
  if grep -qi "WWW-Authenticate:.*Basic" "$AUTH_FILE"; then
    echo "[!!!] BASIC AUTH ENABLED on WinRM (Potential finding)" | tee "$HOSTDIR/10_basic_auth_flag.txt"
  else
    echo "[OK] Basic auth not observed in responses" | tee "$HOSTDIR/10_basic_auth_flag.txt"
  fi

  echo "[+] Completed $IP"
  echo ""

done < "$IPS_FILE"

echo "[✅] All WinRM 5986 enumeration completed."
echo "[✅] Results saved in: $OUTDIR"
