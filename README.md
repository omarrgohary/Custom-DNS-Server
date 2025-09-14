Python Custom DNS Server with Blacklisting, Caching, Logging, Rate Limiting, and Advanced Record Support
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
Overview:

This project implements a custom DNS server in Python that supports real DNS resolution, caching, blacklisting, query logging, and rate limiting. It goes beyond basic DNS features by supporting additional record types (e.g., PTR, SOA, TXT, CAA) and even attempts zone transfers (AXFR) for testing.
The project also includes a CLI tool to directly query domains and manage server functionality.

-------------------------------------------------------------------------------------------------------------------------------------------------------------------

Key Features:
  Real-Time Domain Resolution:
    Supports multiple record types: A, AAAA, NS, CNAME, MX, TXT, SOA, PTR, CAA.
    Uses multiple upstream resolvers (Google 8.8.8.8, Cloudflare 1.1.1.1, Quad9 9.9.9.9) for redundancy.
    Gracefully handles failed lookups with fallback values.

-------------------------------------------------------------------------------------------------------------------------------------------------------------------

Domain Blacklisting:
  Maintains a persistent blacklist file (blacklist_domains.txt).
  Any blacklisted domain resolves to safe dummy values (0.0.0.0, ns.blacklisted.local, etc.).

-------------------------------------------------------------------------------------------------------------------------------------------------------------------

CLI options allow:
  Add a domain to blacklist
  Remove a domain from blacklist
  
-------------------------------------------------------------------------------------------------------------------------------------------------------------------


DNS Caching with TTL:
  Queries are cached in memory for performance.
  Entries expire automatically after a configurable TTL (default 60s).
  
-------------------------------------------------------------------------------------------------------------------------------------------------------------------

CLI option to show the current cache with TTL usage.

Rate Limiting (Anti-DoS/DDoS)
  Per-client IP rate limiting with a sliding time window.
  Default: 20 requests per 30 seconds.
  Exceeded clients receive dummy responses.

Query Logging:
  Every query is logged to dns_log.txt with:
  Domain name
  Record type
  Result(s)
  Status (cached, blacklisted, failed, rate-limited)
  TXT records and verification strings (e.g., Google site verification) are logged in detail.
  
-------------------------------------------------------------------------------------------------------------------------------------------------------------------

CLI option to view logs.

  Admin Command-Line Interface (CLI):
    Supports multiple management commands:
      --start → Start DNS server
      --show-cache → View current cache
      --add-blacklist DOMAIN → Add domain to blacklist
      --remove-blacklist DOMAIN → Remove domain from blacklist
      --view-logs → Display query logs
      --query DOMAIN --type TYPE → Resolve directly without running the server

    Advanced Record Types
      PTR → Reverse DNS lookups (IP → hostname).
      SOA → Shows domain’s Start of Authority.
      CAA → Displays which Certificate Authorities are allowed to issue SSL/TLS certificates for a domain.
      AXFR (Zone Transfer) → Attempts a full zone transfer (useful only on misconfigured test servers).
      ⚠️ Most real-world domains will block AXFR (return REFUSED or SERVFAIL), but this feature is implemented for educational/testing purposes.

-------------------------------------------------------------------------------------------------------------------------------------------------------------------

Example Usage:
  # Start DNS server
  python dns_server.py --start
  # Query A record
  python dns_server.py --query youtube.com --type A
  # Reverse lookup (PTR)
  python dns_server.py --query 142.251.37.238 --type PTR
  # View Certificate Authority Authorization (CAA)
  python dns_server.py --query facebook.com --type CAA
  # Attempt AXFR (zone transfer) – usually blocked
  python dns_server.py --query zonetransfer.me --type AXFR
  # Add domain to blacklist
  python dns_server.py --add-blacklist malware.com
  # Remove domain from blacklist
  python dns_server.py --remove-blacklist malware.com
  # Show cached entries
  python dns_server.py --show-cache
  # View logs
  python dns_server.py --view-logs

-------------------------------------------------------------------------------------------------------------------------------------------------------------------

Technologies Used
  Python 3.11+
  dnslib
   → DNS packet creation/parsing
  dnspython
   → Query upstream DNS servers
  UDP sockets (socket)
  
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
This project is open-source and available under the MIT License.
