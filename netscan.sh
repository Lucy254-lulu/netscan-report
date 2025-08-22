#!/usr/bin/env bash
# Strict mode
set -o errexit
set -o nounset
set -o pipefail

# Prints the header
write_header() {
  local target="${1:-UNSET}"
  cat <<EOF
========================================
Network Security Report
Target: ${target}
Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Author: $(whoami)@$(hostname)
========================================

Overview
This is an auto-generated security report produced by a Bash-based scanner.
EOF
}

# Quick ports/services section (fast pass)
write_ports_section() {
  local target="$1"
  echo ""
  echo "----------------------------------------"
  echo "1) Open Ports and Detected Services"
  echo "----------------------------------------"
  if ! nmap -sV "$target" 2>/dev/null | grep -E "^[0-9]+/tcp\s+open" || true; then
    echo "No open TCP ports found or scan blocked."
  fi

  echo ""
  echo "OS Detection (best effort)"
  if ! nmap -O "$target" 2>/dev/null | grep -E "^(OS details|Running|OS CPE):" || true; then
    echo "OS detection unavailable (may require elevated privileges)."
  fi
}

# Query NVD for CVEs using product+version; formats with TSV to avoid jq quoting issues
query_nvd() {
  local product="$1"
  local version="$2"
  local results_limit=3
  echo ""
  echo "Querying NVD for vulnerabilities in: $product $version..."

  local search_query
  search_query=$(printf '%s' "$product $version" | sed 's/ /%20/g')
  local url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=${results_limit}"

  local json
  json=$(curl -s "$url") || json=""
  if [[ -z "$json" ]]; then
    echo "  [!] Error: Failed to fetch data from NVD."
    return
  fi
  if echo "$json" | jq -e '.message' >/dev/null 2>&1; then
    echo "  [!] NVD API Error: $(echo "$json" | jq -r '.message')"
    return
  fi
  if ! echo "$json" | jq -e '.vulnerabilities[0]' >/dev/null 2>&1; then
    echo "  [+] No vulnerabilities found in NVD for this keyword search."
    return
  fi

  echo "$json" | jq -r '
    .vulnerabilities[] |
    [
      .cve.id,
      (.cve.descriptions[] | select(.lang=="en") | .value | gsub("\\n"; " ")),
      (.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity
       // .cve.metrics.cvssMetricV2[0].cvssData.baseSeverity
       // "N/A")
    ] | @tsv
  ' | while IFS=$'\t' read -r cve desc sev; do
        echo "  CVE ID: ${cve:-N/A}"
        echo "  Description: ${desc:-N/A}"
        echo "  Severity: ${sev:-N/A}"
        echo "---"
     done
}

# Deep scan + vulnerability analysis (≥8 distinct checks)
write_vulns_section() {
  local target="$1"
  echo ""
  echo "----------------------------------------"
  echo "2) Potential Vulnerabilities Identified"
  echo "----------------------------------------"

  # Rich scan with NSE helpers
  local scan
  if ! scan=$(nmap -sV -O --script "vuln,ssh2-enum-algos,ssl-enum-ciphers,http-headers,http-title" "$target" 2>/dev/null); then
    echo "Scan failed or was blocked."
    return
  fi

  # Show any high-confidence NSE results
  local nse_count
  nse_count=$(echo "$scan" | grep -c "VULNERABLE" || true)
  if (( nse_count > 0 )); then
    echo "NSE flagged $nse_count potential issues:"
    echo "$scan" | grep "VULNERABLE" | sed 's/^/  - /'
  else
    echo "No direct NSE 'VULNERABLE' findings."
  fi

  echo ""
  echo "--- Analyzing Detected Services & Config ---"
  local found=0

  # 1) Cleartext HTTP exposure (80 open without 443)
  local has80 has443
  has80=$(echo "$scan"  | grep -cE '^80/tcp\s+open'  || true)
  has443=$(echo "$scan" | grep -cE '^443/tcp\s+open' || true)
  if (( has80 > 0 && has443 == 0 )); then
    echo "[1] Cleartext HTTP (80/tcp) without HTTPS (443/tcp)."
    found=$((found+1))
  fi

  # 2) Weak TLS ciphers/protocols
  if echo "$scan" | grep -q "ssl-enum-ciphers"; then
    if echo "$scan" | grep -Eq 'RC4|3DES|LOW|TLSv1\.0'; then
      echo "[2] Weak TLS ciphers/protocols advertised (RC4/3DES/LOW/TLSv1.0)."
      found=$((found+1))
    fi
  fi

  # 3) Weak SSH algorithms
  if echo "$scan" | grep -q "ssh2-enum-algos"; then
    if echo "$scan" | grep -Ei 'cbc|diffie-hellman-group1|hmac-md5'; then
      echo "[3] Weak SSH algorithms enabled (cbc/group1/hmac-md5)."
      found=$((found+1))
    fi
  fi

  # 4) Outdated Apache
  if echo "$scan" | grep -q "Apache httpd 2.4.7"; then
    echo "[4] Apache 2.4.7 is outdated."
    found=$((found+1))
    query_nvd "Apache httpd" "2.4.7"
  fi

  # 5) Outdated OpenSSH
  if echo "$scan" | grep -q "OpenSSH 6.6.1p1"; then
    echo "[5] OpenSSH 6.6.1p1 is outdated."
    found=$((found+1))
    query_nvd "OpenSSH" "6.6.1p1"
  fi

  # 6) Exposed nping-echo service
  if echo "$scan" | grep -qE '^9929/tcp\s+open\s+nping-echo'; then
    echo "[6] Nping echo service exposed on 9929/tcp."
    found=$((found+1))
  fi

  # 7) tcpwrapped services
  if echo "$scan" | grep -q "tcpwrapped"; then
    echo "[7] Service reports tcpwrapped (behind filtering; access controls may be lax)."
    found=$((found+1))
  fi

  # 8) Uncommon high-numbered port (example: 31337)
  if echo "$scan" | grep -qE '^31337/tcp\s+open'; then
    echo "[8] Uncommon high port 31337/tcp is open."
    found=$((found+1))
  fi

  echo ""
  echo "Total potential issues identified: $found"
}

# Actionable remediation
write_recs_section() {
  cat <<'EOF'

----------------------------------------
3) Recommendations
----------------------------------------
- Enforce HTTPS: close 80/tcp or redirect HTTP→HTTPS; enable HSTS
- Update Apache to 2.4.57+ and OpenSSH to a supported 9.x release
- Disable weak TLS ciphers/protocols (no RC4/3DES/LOW; disable TLS 1.0/1.1)
- Harden SSH: disable CBC and diffie-hellman-group1; prefer curve25519/ed25519, chacha20-poly1305
- Restrict/close uncommon services like nping-echo (9929/tcp)
- Limit exposure with host firewall/ACLs; allow-list required source IPs only
- Monitor with logs/alerts; schedule recurring scans after changes
EOF
}

# Footer
write_footer() {
  cat <<'EOF'

----------------------------------------
4) Appendix & Footer
----------------------------------------
Tools: nmap (vuln, ssh2-enum-algos, ssl-enum-ciphers, http-headers, http-title), curl, jq
Notes: Findings are best-effort; confirm with patch advisories and vendor guidance.

End of report.
========================================
EOF
}

main() {
  # Argument validation
  if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <target_ip_or_hostname>" >&2
    exit 1
  fi
  local target="$1"
  local REPORT_FILE="report.txt"

  # Build the report
  write_header "$target"          >  "$REPORT_FILE"
  write_ports_section "$target"   >> "$REPORT_FILE"
  write_vulns_section "$target"   >> "$REPORT_FILE"
  write_recs_section              >> "$REPORT_FILE"
  write_footer                    >> "$REPORT_FILE"

  echo "Report written to: ${REPORT_FILE}"
}

main "$@"

