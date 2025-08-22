# Final Project — Shell Script Security Scanner

## Usage

## What it does
- Runs `nmap -sV -O --script "vuln,ssh2-enum-algos,ssl-enum-ciphers,http-headers,http-title"`
- Parses open ports, OS hints, and NSE output
- Identifies ≥8 potential vulnerabilities (version checks, weak crypto, exposed services)
- Calls NVD (curl + jq) for CVEs by product/version
- Writes a detailed report to `report.txt`

## Vulnerability identification (examples)
- Cleartext HTTP without HTTPS
- Weak TLS ciphers/protocols (RC4/3DES/LOW/TLS1.0)
- Weak SSH algorithms (CBC, diffie-hellman-group1, hmac-md5)
- Outdated Apache (2.4.7)
- Outdated OpenSSH (6.6.1p1)
- Exposed nping-echo (9929/tcp)
- tcpwrapped/filtered services
- Uncommon high ports (e.g., 31337)

## Recommendations (examples)
- Enforce HTTPS and HSTS; close 80/tcp or redirect
- Upgrade Apache to 2.4.57+; OpenSSH to a supported 9.x
- Disable weak TLS/SSH algorithms; prefer modern suites
- Close or restrict uncommon services; apply firewall ACLs
- Monitor logs and schedule rescans after changes

## Ethical considerations
Only scan assets you own or have explicit authorization to test. Some NSE scripts are intrusive. Respect scope and law; obtain consent and minimize potential impact.
