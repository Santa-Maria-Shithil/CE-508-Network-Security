import subprocess
import argparse
from scapy.all import *
from scapy.layers.tls.all import *
import re
load_layer("tls")
load_layer("http")


def captureOptions():   
    # Create the parser
    interface = conf.iface

    parser = argparse.ArgumentParser(description="Parsing argument from the command line.")

    interface_help_string = "Live capture from the network device <interface> (e.g., eth0). If not specified,  the program should automatically select a default interface to listen on. Capture should continue indefinitely until the user terminatesthe program."

    #Adding arguments
    parser.add_argument("-i","--interface", metavar="<interface>", help=interface_help_string, required=False)


    # Parse the arguments
    args = parser.parse_args()

    # Access and display the arguments

    if args.interface:
        interface = args.interfacen
        
    print(f"Interface: {interface}")

    return interface

def read_arp_cache():
        
    command = "arp -a"  # or "ip neigh" for Linux
    
    # Execute the command
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    # Decode the output from bytes to string
    arp_output = stdout.decode().strip()
    
    if stderr:
        print("Error:", stderr.decode())
    
    return arp_output



def handle_packet(packet):

    print(packet)  
    if packet[ARP].op == 2: # ARP response (op=2)
        #print(f"ARP Response: From IP {packet[ARP].psrc} is at {packet[ARP].hwsrc}")
        tracked_ip = packet[ARP].psrc
        tracked_mac = packet[ARP].hwsrc

        pattern = re.compile(r'\? \(([\d\.]+)\) at ([\da-f:]+) on (\w+) ifscope (\[.*?\])')
        # Search through ARP entries
        ipfound = False
        macfound = False
        for match in pattern.finditer(ARP_ENTRIES):
            ip, mac, _, _ = match.groups()
            if ip.strip() == tracked_ip.strip():
                #tracked_mac2 = mac
                ipfound = True
                print(f"mac:{mac.lower()} tracked_mac:{tracked_mac.lower()}")
                if mac.strip().lower() == tracked_mac.strip().lower():
                    print("inside 2nd condiiton")
                    macfound = True
                break
                

        if ipfound == True and macfound ==False:
            print("##########################Warning Warning Warning#################")
            print("There is an ARP poisoning")
            print(f"{tracked_ip} changed from {mac.lower()} to {tracked_mac.lower()}")

def arp_filter(packet):
    return "ARP" in packet

def trackingFromInterface(interfaceName):
    try:
        print("Packet capturing started. Press Ctrl+C to stop.")
        # Start sniffing packets. The store=0 ensures packets are not kept in memory for performance.
        #sniff(iface=interfaceName, prn=handle_packet, store=0)
        sniff( prn=handle_packet, store=0, iface = interfaceName, lfilter=arp_filter)
    except KeyboardInterrupt:
        print("\nCapturing stopped by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")

ARP_ENTRIES = read_arp_cache()

if __name__ == "__main__":
    interfaceName = captureOptions()
    
    print(ARP_ENTRIES)

    trackingFromInterface(interfaceName)

    