Python Custom DNS Server with Blacklisting, Caching, Logging, and Rate Limiting
___________________________________________________________________________________________________________________________________________________________________

This project implements a fully functional DNS server built using Python that supports domain name resolution, blacklist enforcement, in-memory caching, logging of all queries, and rate limiting to mitigate abuse.
It includes an admin command-line interface for managing blacklist entries and viewing cache or logs, along with a testing client to simulate DNS queries over UDP.

___________________________________________________________________________________________________________________________________________________________________

Key Features

Real-Time Domain Resolution
- Resolves queried domain names to their respective IP addresses using real DNS resolvers (`dnspython`).
- Provides fallback response (`0.0.0.0`) for blocked or failed lookups.

Domain Blacklisting
- Blocks DNS queries for known malicious or suspicious domains.
- Maintains a persistent blacklist in `blacklist_domains.txt`.
- Allows real-time addition or removal of entries via admin interface.

DNS Caching with TTL
- Stores resolved domains and their IPs in memory for fast lookup.
- TTL (Time-to-Live) support ensures cache entries expire after a defined period.

Rate Limiting (DoS/DDoS Protection)
- Limits the number of DNS queries per IP address within a time window.
- Helps prevent abuse and reduce risk of Denial of Service (DoS) or Distributed DoS (DDoS) attacks.

Query Logging
- Logs every DNS query with its resolution result and status (cached, blacklisted, etc.).
- Stores logs in `dns_log.txt`.

Admin Command-Line Interface
- Interactive menu to:
  - View current DNS cache
  - Add/remove domains from the blacklist
  - Review query logs
  - Start the DNS server

Testing Client
- A separate test client (`dns_client.py`) to simulate and verify DNS queries.

___________________________________________________________________________________________________________________________________________________________________

Technologies Used

- Python 3.11
- `dnslib` for DNS packet creation and parsing
- `dnspython` for domain resolution
- UDP sockets (`socket`)
- File handling, multi-threading, and time-based logic

___________________________________________________________________________________________________________________________________________________________________

License
This project is open-source and available under the MIT License.

___________________________________________________________________________________________________________________________________________________________________
