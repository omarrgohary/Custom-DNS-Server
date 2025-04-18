import socket
from dnslib import DNSRecord

# Send query to DNS server
def query_domain(domain):
    query = DNSRecord.question(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query.pack(), ("127.0.0.1", 5354))

    # Receive the response
    data, _ = sock.recvfrom(1024)
    reply = DNSRecord.parse(data)

    # Print the reply
    print(f"RECEIVED REPLY for {domain}:")
    print(reply)

# Test querying the same domain twice
query_domain("instagram.com") 
query_domain("virus-injection.com") 
query_domain("facebook.com") 
query_domain("snapchat.com") 
query_domain("openai.com") 
