import socket
import os
import time
from dnslib import DNSRecord, QTYPE, RR
import dns.resolver  # Required for real DNS resolution

class DNSserver:

    def __init__(self, host="127.0.0.1", port=5354, ttl_duration=60, max_requests=5, window_seconds=30, blacklist_file="blacklist_domains.txt"):
        self.host = host
        self.port = port
        self.cache = {}
        self.ttl_duration = ttl_duration
        self.max_requests = max_requests  # Max queries allowed within the time window
        self.window_seconds = window_seconds  # Time window (in seconds) for rate limiting
        self.rate_limit = {}  # Tracks the timestamps of requests from each client IP
        self.load_blacklist(blacklist_file)  # Load the blacklist from the file

    def load_blacklist(self, blacklist_file): #Loads domains from the given blacklist file into the blacklist set
        
        self.blacklist = set()  # Initialize the blacklist to an empty set here
        try:
            with open(blacklist_file, "r") as file:
                for line in file:
                    domain = line.strip()  # Remove any extra spaces or newline characters
                    if domain:  # Only add non-empty lines
                        self.blacklist.add(domain.lower())  # Make it case-insensitive
            print(f"Blacklisted domains loaded from {blacklist_file}")
        except Exception as e:
            print(f"Error loading blacklist: {e}")

    def show_cache(self): #Display the current cache.
        print("Current Cache:")
        for domain, data in self.cache.items():
            print(f"{domain} -> {data['ip_address']} (TTL: {int(time.time() - data['timestamp'])}s)")
        print()

    def addition_to_blacklist(self):  # Add a domain to the blacklist and file
        domain = input("Enter domain to blacklist: ").strip()
        if domain in self.blacklist:
            print(f"{domain} is already in the blacklist.\n")
        else:
            self.blacklist.add(domain.lower())
            with open("blacklist_domains.txt", "a") as file:  # Append the domain to the file
                file.write(domain.lower() + "\n")
            print(f"{domain} is added to the blacklist.\n")


    def remove_from_blacklist(self):  # Remove a domain from the blacklist and file
        domain = input("Enter domain to remove from blacklist: ").strip()
        if domain in self.blacklist:
            self.blacklist.remove(domain.lower())
            # Rewrite the file without the removed domain
            with open("blacklist_domains.txt", "r") as file:
                lines = file.readlines()

            with open("blacklist_domains.txt", "w") as file:
                for line in lines:
                    if line.strip().lower() != domain.lower():
                        file.write(line)
        
            print(f"{domain} removed from the blacklist.\n")
        else:
            print(f"{domain} not found in the blacklist.\n")


    def view_logs(self): #Display the log file
        log_path = r"C:\\Users\\omarr\\OneDrive\\Desktop\\dns_log.txt"
        try:
            with open(log_path, "r") as log_file:
                print("Logs:")
                print(log_file.read())
        except Exception as e:
            print(f"Error reading logs: {e}")
        print()

    def display_menu(self): #Display the admin menu
        while True:
            print("\nAdmin Menu:")
            print("1. View Cache")
            print("2. Add to Blacklist")
            print("3. Remove from Blacklist")
            print("4. View Logs")
            print("5. Start DNS Server")
            print("6. Exit")
            choice = input("Enter your choice: ").strip()

            if choice == "1":
                self.show_cache()
            elif choice == "2":
                self.addition_to_blacklist()
            elif choice == "3":
                self.remove_from_blacklist()
            elif choice == "4":
                self.view_logs()
            elif choice == "5":
                print("Starting DNS server...")
                self.start()  # Start the DNS server after the menu selection
                break  # Exit the menu and start the server
            elif choice == "6":
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Creates a UDP socket using IPv4 and UDP protocol
        server_socket.bind((self.host, self.port))  # Binds the socket to the specified port and host

        print(f"DNS Server started on {self.host}:{self.port}")

        while True:  # Infinite loop
            data, addr = server_socket.recvfrom(512)  # Receiving data up to 512 bytes
            print(f"Received DNS query from {addr}")
            self.handle_query(data, addr, server_socket)

    def handle_query(self, data, addr, server_socket):
        client_ip = addr[0]  # Get the client IP address

        # Check if the client is rate-limited
        if self.is_rate_limited(client_ip):
            print(f"Rate limit exceeded for {client_ip}")
            ip_address = "0.0.0.0"
            status_note = "rate-limited"
            response = self.build_response(DNSRecord.parse(data), ip_address, status_note)
            server_socket.sendto(response, addr)
            self.log_query("rate-limited", ip_address)  # Log the rate-limited query
            return

        request = DNSRecord.parse(data)  # Parse the incoming DNS query data
        qname = str(request.q.qname)  # Extract the query domain name
        qtype = QTYPE[request.q.qtype]  # Extract the query type

        print(f"Query for {qname}, Type: {qtype}")

        if self.is_blacklisted(qname):  # Check if the domain name is blacklisted
            print(f"{qname} is blacklisted.")
            ip_address = "0.0.0.0"
            status_note = "blacklisted"
        elif qname in self.cache and self.is_cache_valid(qname):  # Check if the domain name is cached and TTL is valid
            ip_address = self.cache[qname]["ip_address"]
            print(f"{qname} is cached with IP {ip_address}.")
            status_note = "cached"
        else:
            ip_address = self.resolve_domain(qname)  # Resolve the domain if not cached
            if ip_address:
                print(f"{qname} resolved to {ip_address}.")
                status_note = "not cached"
                self.cache[qname] = {"ip_address": ip_address, "timestamp": time.time()}
            else:  # If resolution fails, use fallback IP.
                ip_address = "0.0.0.0"
                print(f"Failed to resolve {qname}, using fallback IP.")
                status_note = "resolution failed"

        response = self.build_response(request, ip_address, status_note)  # Build the response packet
        server_socket.sendto(response, addr)  # Send the response back to the client
        self.log_query(qname, ip_address)  # Log the query

    def build_response(self, request, ip_address, status_note=""):
        reply = request.reply()  # Starts building a reply from the original request.
        reply.add_answer(*RR.fromZone(f"{str(request.q.qname)} 60 A {ip_address}"))  # Adds an A record with a TTL of 60 seconds.
        if status_note:
            reply.add_ar(*RR.fromZone(f"{str(request.q.qname)} 60 TXT \"{status_note}\""))  # Adds a TXT record explaining the status.
        return reply.pack()  # Serializes the response into bytes to send over the network.

    def resolve_domain(self, domain):
        try:
            answer = dns.resolver.resolve(domain, 'A')  # Uses dnspython to resolve the domain to an IPv4 address.
            for rdata in answer:
                return rdata.address
        except Exception as e:
            print(f"Error resolving domain {domain}: {e}")  # Catches and logs any errors during DNS resolution.
            return None

    def is_blacklisted(self, domain):  # Checks if the domain is in the blacklist. Removes trailing dot from DNS name.
        return domain.rstrip(".").lower() in self.blacklist

    def add_to_blacklist(self, domain):  # Adds a domain to the blacklist.
        self.blacklist.add(domain.lower())

    def is_cache_valid(self, domain):  # Returns True if cache is still within TTL
        current_time = time.time()
        cache_entry = self.cache.get(domain)
        if cache_entry:
            cache_timestamp = cache_entry["timestamp"]
            if current_time - cache_timestamp <= self.ttl_duration:
                return True
        return False

    def log_query(self, domain, ip_address):  # Logs the query into the file
        try:
            log_path = r"C:\\Users\\omarr\\OneDrive\\Desktop\\dns_log.txt"
            with open(log_path, "a") as log_file:
                log_file.write(f"Queried domain: {domain}, Resolved to: {ip_address}\n")
                log_file.flush()
        except Exception as e:
            print(f"Logging failed: {e}")

    def is_rate_limited(self, ip):
        current_time = time.time()
        request_times = self.rate_limit.get(ip, [])

        # Keep only timestamps from the last window
        request_times = [t for t in request_times if current_time - t <= self.window_seconds]  
        self.rate_limit[ip] = request_times

        if len(request_times) >= self.max_requests:
            return True  # The client is rate-limited
        else:
            self.rate_limit[ip].append(current_time)  # Add the current time to the list
            return False  # The client is not rate-limited

# Initialize DNS server, display menu, and start the server after admin actions
server = DNSserver()
server.display_menu()  # Display menu first
