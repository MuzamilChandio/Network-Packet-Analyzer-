import scapy.all as scapy

def packet_callback(packet):
    # Extract relevant information from the packet
    source_ip = packet[scapy.IP].src
    destination_ip = packet[scapy.IP].dst
    protocol = packet[scapy.IP].proto
    payload_data = packet[scapy.Raw].load if scapy.Raw in packet else ""

    # Display the information
    print(f"Source IP: {source_ip}, Destination IP: {destination_ip}, Protocol: {protocol}, Payload: {payload_data}")

def start_sniffing(interface):
    print(f"[*] Sniffing started on interface {interface}")
    scapy.sniff(iface=interface, store=False, prn=packet_callback)

# Example usage
interface = "eth0"  # Specify the network interface to sniff on (e.g., "eth0" for Ethernet)
start_sniffing(interface)
