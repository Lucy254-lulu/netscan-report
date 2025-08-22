#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

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
This is an auto-generated security report.
EOF
}

write_ports_section() {
  local target="$1"
  echo ""
  echo "----------------------------------------"
  echo "1) Open Ports and Detected Services"
  echo "----------------------------------------"
  nmap -sV "$target" | grep "open" || echo "No open ports found."
}

query_nvd() {
  local product="$1"
  local version="$2"
  local results_limit=2
  echo ""
  echo "Querying NVD for vulnerabilities in: $product $version..."
  local search_query
  search_query=$(printf '%s' "$product $version" | sed 's/ /%20/g')
  local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=${results_limit}"
  local json
  json=$(curl -s "$nvd_api_url")
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

write_vulns_section() {
  local target="$1"
  echo ""
  echo "----------------------------------------"
  echo "2) Potential Vulnerabilities Identified"
  echo "----------------------------------------"
  SCAN_RESULTS=$(nmap -sV --script vuln "$target")
  echo "$SCAN_RESULTS" | grep "VULNERABLE" || echo "No direct NSE vulnerability matches found."
  echo ""
  echo "--- Analyzing Service Versions ---"
  echo "$SCAN_RESULTS" | while read -r line; do
    case "$line" in
      *"Apache httpd 2.4.7"*)
        echo "[!!] Apache 2.4.7 is outdated"
        query_nvd "Apache httpd" "2.4.7"
        ;;
      *"OpenSSH 6.6.1p1"*)
        echo "[!!] OpenSSH 6.6.1p1 is old"
        query_nvd "OpenSSH" "6.6.1p1"
        ;;
    esac
  done
}

write_recs_section() {
  cat <<'EOF'

----------------------------------------
3) Recommendations
----------------------------------------
- Patch and upgrade vulnerable services immediately
- Apply vendor security updates
- Restrict network access to critical services
- Enable monitoring and alerting
EOF
}

write_footer() {
  cat <<'EOF'

----------------------------------------
4) Appendix & Footer
----------------------------------------
- Tools used: nmap, curl, jq
- API results limited for testing

End of report.
========================================
EOF
}

main() {
  if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <target_ip_or_hostname>" >&2
    exit 1
  fi
  local target="$1"
  local REPORT_FILE="report.txt"
  write_header "$target" > "$REPORT_FILE"
  write_ports_section "$target" >> "$REPORT_FILE"
  write_vulns_section "$target" >> "$REPORT_FILE"
  write_recs_section            >> "$REPORT_FILE"
  write_footer                  >> "$REPORT_FILE"
  echo "Report written to: ${REPORT_FILE}"
}
main "$@"

