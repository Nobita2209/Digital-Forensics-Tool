from scapy.all import sniff

# Define a function to process and display captured packets
def packet_callback(packet):
    # Display basic packet information
    print(f"Packet: {packet.summary()}")
    
    # If the packet has IP layer, display source and destination IPs
    if packet.haslayer('IP'):
        print(f"Source IP: {packet['IP'].src}")
        print(f"Destination IP: {packet['IP'].dst}")
    
    # If the packet has TCP layer, display port information
    if packet.haslayer('TCP'):
        print(f"Source Port: {packet['TCP'].sport}")
        print(f"Destination Port: {packet['TCP'].dport}")
    
    # If the packet has UDP layer, display port information
    if packet.haslayer('UDP'):
        print(f"Source Port: {packet['UDP'].sport}")
        print(f"Destination Port: {packet['UDP'].dport}")
    
    print("-" * 50)

# Set the interface for sniffing network packets (use 'Ethernet', 'Wi-Fi', etc. as appropriate for your system)
interface = "Wi-Fi 2" # Adjust interface name based on your system (e.g., "Ethernet", "Wi-Fi")

# Start sniffing packets on the network interface
print(f"Sniffing network traffic on {interface}...")
sniff(iface=interface, prn=packet_callback, store=0)