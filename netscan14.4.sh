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
        printf '  CVE ID: %s\n' "$cve"
        printf '  Description: %s\n' "$desc"
        printf '  Severity: %s\n' "$sev"
        printf '---\n'
     done
}

