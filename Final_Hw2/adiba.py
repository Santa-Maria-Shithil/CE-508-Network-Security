from scapy.all import ARP, sniff
import netifaces as ni
import argparse
import sys



def get_arp_cache():
    """ Returns the current ARP cache as a dictionary mapping IP to MAC """
    arp_cache = {}
    try:
        # Read ARP cache
        with open('/proc/net/arp', 'r') as f:
            for line in f.readlines()[1:]:
                columns = line.split()
                ip = columns[0]
                mac = columns[3]
                arp_cache[ip] = mac
    except Exception as e:
        print(f"Error reading ARP cache: {e}")
        sys.exit(1)

    # Print the current ARP cache entries
    print("Current ARP cache entries (considered as ground truth):")
    for ip, mac in arp_cache.items():
        print(f"{ip} -> {mac}")

    return arp_cache

def monitor_callback(pkt, arp_cache):
    """ Callback for sniffing packets """
    if ARP in pkt and pkt[ARP].op in (1, 2):  # who-has or is-at
        source_ip = pkt[ARP].psrc
        source_mac = pkt[ARP].hwsrc
        if source_ip in arp_cache and arp_cache[source_ip] != source_mac:
            print(f"Warning: {source_ip} changed from {arp_cache[source_ip]} to {source_mac}")
            arp_cache[source_ip] = source_mac

def main():
    parser = argparse.ArgumentParser(description="Simple ARP poisoning attack detector")
    parser.add_argument("-i", "--interface", help="Specify the interface on which to listen", default=get_default_interface())
    args = parser.parse_args()

    arp_cache = get_arp_cache()
    print("Monitoring ARP packets. Press Ctrl+C to stop.")
    sniff(iface=args.interface, store=False, prn=lambda x: monitor_callback(x, arp_cache))

if __name__ == "_main_":
    main()