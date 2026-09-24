from scapy.all import *
import datetime
import base64

# Data
name = "Dimitris Stathoulias"
am = "2018030109"
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
payload = f"{name}-{am} {now}"
pcap_file = "snort/lab/traffic.pcap"
packets = []

# Student Packet
print("Generating Student Packet...")
randomIP = str(RandIP())    # Generating random IPs inside IP() method causes incompatibility issues
                            # with python3 and scapy (current version) so we generate them outside
packet1 = IP(src = randomIP, dst = "192.168.1.1")/ TCP(dport = 54321) / payload
packets.append(packet1)

# Ports Packets
ports = {
    # All services besides DNS and RTSP use TCP only
    # For the purposes of this assignment we only generate traffic for the service's primary protocol
    "HTTP": (80, "TCP"),
    "HTTPS": (443, "TCP"),
    "SSH": (22, "TCP"),
    "TELNET": (23, "TCP"),
    "FTP": (21, "TCP"),
    "DNS": (53, "UDP"),  # Uses UDP primarily but TCP for large response data sizes or Zone transfers
    "RTSP": (554, "TCP"),    # Uses TCP for commands and UDP for transmission
    "SQL": (5432, "TCP"),    # 1433:Microsoft SQL, 3306:MySQL, 5432:PostgreSQL
    "RDP": (3389, "TCP"),    # Newer versions utilize UDP fas well for high quality graphics streaming
                             # For the purposes of this assignment we assume it uses only TCP 
    "MQTT": (1883, "TCP")
}
print("Generating Ports Packets...")
for service, (port, protocol) in ports.items():
    randomIP = str(RandIP())
    ip = IP(src = randomIP, dst = "192.168.1.2")

    if protocol == "TCP":
        transmission = TCP(dport = port)
    else:
        transmission = UDP(dport = port)

    packet = ip / transmission / payload
    packets.append(packet)
    
# Base64 Packet
print("Generating Base64 Packet...")
base64_am = base64.b64encode(am.encode()).decode()  # Convert AM to Base64 encoded string
randomIP = str(RandIP())
packet3 = IP(src = randomIP, dst = "192.168.1.3") / TCP(dport = 8080) / base64_am
packets.append(packet3)

# Suspicious DNS Packet
print("Generating Suspicious DNS Packet...")
dns = UDP(dport = 53) / DNS(rd = 1, qd = DNSQR(qname = "malicious.example.com"))
randomIP = str(RandIP())
packet4 = IP(src = randomIP, dst = "192.168.178.1") / dns
packets.append(packet4)

# Ping Test Packet
print("Generating Ping Packet...")
randomIP = str(RandIP())
packet5 = IP(src = randomIP, dst = "192.168.1.4") / ICMP() / "PingTest2025"
packets.append(packet5)

# Save packets to PCAP file
wrpcap(pcap_file, packets)
print("Packets saved to PCAP file.")