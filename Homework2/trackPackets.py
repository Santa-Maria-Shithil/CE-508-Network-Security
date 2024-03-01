from scapy.all import sniff, wrpcap

# Function to capture packets
def capture_packets():
    print("Capturing 10 packets...")
    packets = sniff(count=1000)  # Adjust count as needed
    print("Capture complete. Saving to file...")
    wrpcap('trace.pcap', packets)
    print("Packets saved to 'captured_packets.pcap'.")

capture_packets()
