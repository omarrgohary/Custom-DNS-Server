import socket
import time
import argparse
import ipaddress

from dnslib import DNSRecord, QTYPE, RR
import dns.resolver
import dns.reversename
import dns.query
import dns.zone
import dns.rdatatype


class DNSserver:
    def __init__(
        self,
        host="127.0.0.1",
        port=5354,
        ttl_duration=60,
        max_requests=20,
        window_seconds=30,
        blacklist_file=r"C:\Users\omarr\OneDrive\Desktop\projects\DNS Server\blacklist_domains.txt",
    ):
        self.host = host
        self.port = port
        self.cache = {}  
        self.ttl_duration = ttl_duration
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.rate_limit = {}
        self.blacklist_file = blacklist_file
        self.load_blacklist(self.blacklist_file)

    # ---------------- Blacklist ----------------
    def load_blacklist(self, blacklist_file):
        self.blacklist = set()
        try:
            with open(blacklist_file, "r") as file:
                for line in file:
                    domain = line.strip()
                    if domain:
                        self.blacklist.add(domain.lower())
            print(f"Blacklisted domains loaded from {blacklist_file}")
        except Exception as e:
            print(f"Error loading blacklist: {e}")

    def add_to_blacklist(self, domain):
        domain = domain.lower()
        if domain not in self.blacklist:
            self.blacklist.add(domain)
            with open(self.blacklist_file, "a") as file:
                file.write(domain + "\n")
            print(f"{domain} added to blacklist.")
        else:
            print(f"{domain} is already in blacklist.")

    def remove_from_blacklist(self, domain):
        domain = domain.lower()
        if domain in self.blacklist:
            self.blacklist.remove(domain)
            try:
                with open(self.blacklist_file, "r") as file:
                    lines = file.readlines()
                with open(self.blacklist_file, "w") as file:
                    for line in lines:
                        if line.strip().lower() != domain:
                            file.write(line)
                print(f"{domain} removed from blacklist.")
            except Exception as e:
                print(f"Error updating blacklist file: {e}")
        else:
            print(f"{domain} not found in blacklist.")

    def is_blacklisted(self, domain):
        return domain.rstrip(".").lower() in self.blacklist

    # ---------------- Cache ----------------
    def show_cache(self):
        print("Current Cache:")
        for (domain, qtype), data in self.cache.items():
            ttl_used = int(time.time() - data["timestamp"])
            print(f"{domain} ({qtype}) -> {data['answer']} (TTL used: {ttl_used}s)")
        print()

    def is_cache_valid(self, cache_key):
        current_time = time.time()
        cache_entry = self.cache.get(cache_key)
        if cache_entry:
            if current_time - cache_entry["timestamp"] <= self.ttl_duration:
                return True
        return False

    # ---------------- Logging ----------------
    def log_query(self, domain, answers):
        try:
            log_path = r"C:\Users\omarr\OneDrive\Desktop\projects\DNS Server\dns_log.txt"
            with open(log_path, "a", encoding="utf-8") as log_file:
                if isinstance(answers, list):
                    log_file.write(f"Queried: {domain}, Resolved: {', '.join(answers)}\n")
                else:
                    log_file.write(f"Queried: {domain}, Resolved: {answers}\n")
        except Exception as e:
            print(f"Logging failed: {e}")

    def view_logs(self):
        log_path = r"C:\Users\omarr\OneDrive\Desktop\projects\DNS Server\dns_log.txt"
        try:
            with open(log_path, "r", encoding="utf-8") as log_file:
                print("Logs:\n" + log_file.read())
        except Exception as e:
            print(f"Error reading logs: {e}")

    # ---------------- Rate Limit ----------------
    def is_rate_limited(self, ip):
        current_time = time.time()
        request_times = self.rate_limit.get(ip, [])
        request_times = [t for t in request_times if current_time - t <= self.window_seconds]
        self.rate_limit[ip] = request_times
        if len(request_times) >= self.max_requests:
            return True
        else:
            self.rate_limit[ip].append(current_time)
            return False

    # ---------------- Resolver ----------------
    def resolve_domain(self, domain, qtype):
        upstream_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

        if qtype == "PTR":
            try:
                ip_obj = ipaddress.ip_address(domain)
                domain = str(dns.reversename.from_address(str(ip_obj)))
            except Exception:
                pass

        if qtype == "AXFR":
            for upstream in upstream_servers:
                try:
                    xfr = dns.query.xfr(upstream, domain, timeout=5)
                    try:
                        zone_obj = dns.zone.from_xfr(xfr)
                    except Exception as ze:
                        print(f"AXFR failed to build zone from {upstream}: {ze}")
                        continue

                    results = []
                    for name, node in zone_obj.nodes.items():
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                name_text = name.to_text() if name else "@"
                                ttl = rdataset.ttl
                                rdtype = dns.rdatatype.to_text(rdataset.rdtype)
                                rdata_text = rdata.to_text()
                                line = f"{name_text} {ttl} IN {rdtype} {rdata_text}"
                                results.append(line)
                    return results if results else None
                except Exception as e:
                    print(f"AXFR upstream {upstream} failed for {domain}: {e}")
            return None

        for upstream in upstream_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [upstream]
                resolver.lifetime = 2
                answer = resolver.resolve(domain, qtype)
                results = []
                for rdata in answer:
                    if qtype in ["A", "AAAA"]:
                        results.append(rdata.address)
                    elif qtype == "NS":
                        results.append(str(rdata.target).rstrip("."))
                    elif qtype == "CNAME":
                        results.append(str(rdata.target).rstrip("."))
                    elif qtype == "MX":
                        results.append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
                    elif qtype == "TXT":
                        try:
                            txt_strings = [s.decode("utf-8") for s in rdata.strings]
                        except Exception:
                            txt_strings = [str(x) for x in rdata.strings]
                        results.append(" ".join(txt_strings))
                    elif qtype == "SOA":
                        results.append(
                            f"{rdata.mname} {rdata.rname} {rdata.serial} "
                            f"{rdata.refresh} {rdata.retry} {rdata.expire} {rdata.minimum}"
                        )
                    elif qtype == "PTR":
                        results.append(str(rdata.target).rstrip("."))
                    elif qtype == "CAA":
                        results.append(f"{rdata.flags} {rdata.tag} {rdata.value}")
                return results if results else None
            except Exception as e:
                print(f"Upstream {upstream} failed for {domain} ({qtype}): {e}")

        return None

    # ---------------- DNS Server (UDP only) ----------------
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((self.host, self.port))
        print(f"DNS Server started on {self.host}:{self.port} (UDP only)")
        while True:
            data, addr = server_socket.recvfrom(512)
            print(f"Received DNS query from {addr}")
            self.handle_query(data, addr, server_socket)

    def handle_query(self, data, addr, server_socket):
        client_ip = addr[0]
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]

        print(f"Query for {qname}, Type: {qtype}")

        cache_key = (qname, qtype)

        if self.is_rate_limited(client_ip):
            answers = ["rate-limited.local"]
            status_note = "rate-limited"
        elif self.is_blacklisted(qname):
            answers = ["blacklisted.local"]
            status_note = "blacklisted"
        elif cache_key in self.cache and self.is_cache_valid(cache_key):
            answers = self.cache[cache_key]["answer"]
            status_note = "cached"
        else:
            answers = self.resolve_domain(qname, qtype)
            if answers:
                self.cache[cache_key] = {"answer": answers, "timestamp": time.time()}
                status_note = "not cached"
            else:
                answers = ["failed.local"]
                status_note = "resolution failed"

        response = self.build_response(request, answers, qtype, status_note)
        server_socket.sendto(response, addr)
        self.log_query(f"{qname} ({qtype})", answers)

    def build_response(self, request, answers, qtype, status_note=""):
        reply = request.reply()

        if qtype == "A":
            for ip in answers:
                reply.add_answer(*RR.fromZone(f"{str(request.q.qname)} 60 A {ip}"))
        elif qtype == "AAAA":
            for ip in answers:
                reply.add_answer(*RR.fromZone(f"{str(request.q.qname)} 60 AAAA {ip}"))
        elif qtype == "NS":
            for ns in answers:
                reply.add_answer(*RR.fromZone(f"{str(request.q.qname)} 60 NS {ns}"))
        elif qtype == "CNAME":
            for cname in answers:
                reply.add_answer(*RR.fromZone(f"{str(request.q.qname)} 60 CNAME {cname}"))
        elif qtype == "MX":
            for mx in answers:
                preference, exchange = mx.split(" ", 1)
                reply.add_answer(*RR.fromZone(f"{str(request.q.qname)} 60 MX {preference} {exchange}"))
        elif qtype == "TXT":
            for txt in answers:
                reply.add_answer(*RR.fromZone(f"{str(request.q.qname)} 60 TXT \"{txt}\""))
        elif qtype == "SOA":
            for soa in answers:
                mname, rname, serial, refresh, retry, expire, minimum = soa.split(" ")
                reply.add_answer(*RR.fromZone(
                    f"{str(request.q.qname)} 60 SOA {mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
                ))
        elif qtype == "PTR":
            for ptr in answers:
                reply.add_answer(*RR.fromZone(f"{str(request.q.qname)} 60 PTR {ptr}"))
        elif qtype == "CAA":
            for caa in answers:
                reply.add_answer(*RR.fromZone(f"{str(request.q.qname)} 60 CAA {caa}"))
        elif qtype == "AXFR":
            for line in answers:
                reply.add_ar(*RR.fromZone(f"{str(request.q.qname)} 60 TXT \"{line}\""))

        if status_note:
            reply.add_ar(*RR.fromZone(f"{str(request.q.qname)} 60 TXT \"{status_note}\""))
        return reply.pack()


# ---------------- CLI ----------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Custom DNS Server CLI Tool (with AXFR and CAA support)")
    parser.add_argument("--start", action="store_true", help="Start the DNS server (UDP)")
    parser.add_argument("--show-cache", action="store_true", help="Show cached DNS entries")
    parser.add_argument("--add-blacklist", type=str, help="Add a domain to the blacklist")
    parser.add_argument("--remove-blacklist", type=str, help="Remove a domain from the blacklist")
    parser.add_argument("--view-logs", action="store_true", help="View DNS query logs")

    parser.add_argument("--query", type=str, help="Domain or IP to resolve directly")
    parser.add_argument(
        "--type",
        type=str,
        default="A",
        choices=["A", "AAAA", "NS", "CNAME", "MX", "TXT", "SOA", "PTR", "CAA", "AXFR"],
        help="Record type (default A)."
    )

    args = parser.parse_args()
    server = DNSserver()

    if args.start:
        server.start()
    elif args.show_cache:
        server.show_cache()
    elif args.add_blacklist:
        server.add_to_blacklist(args.add_blacklist)
    elif args.remove_blacklist:
        server.remove_from_blacklist(args.remove_blacklist)
    elif args.view_logs:
        server.view_logs()
    elif args.query:
        answers = server.resolve_domain(args.query, args.type)
        if answers:
            if args.type in ["TXT", "SOA", "CAA", "AXFR"]:
                print(f"{args.query} ({args.type}) ->")
                for ans in answers:
                    print(f"  {ans}")
            else:
                print(f"{args.query} ({args.type}) -> {', '.join(answers)}")
            server.log_query(args.query, answers)
        else:
            print(f"Failed to resolve {args.query} ({args.type})")
    else:
        parser.print_help()
