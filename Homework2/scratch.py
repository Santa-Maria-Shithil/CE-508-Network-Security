import argparse
from scapy.all import *
import logging
from datetime import datetime
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName
from scapy.layers.tls.record import TLS

def captureOptions():   
    # Create the parser
    parser = argparse.ArgumentParser(description="Parsing argument from the command line.")

    interface_help_string = "Live capture from the network device <interface> (e.g., eth0). If not specified,  the program should automatically select a default interface to listen on. Capture should continue indefinitely until the user terminatesthe program."
    read_help_string = "Read packets from <tracefile> (tcpdump format). Useful for analyzing network traces that have been captured previously."
    expression_help_string = "The optional <expression> argument is a BPF filter that specifies a subset of the traffic to be monitored (similar to tcpdump)."

    #Adding arguments
    parser.add_argument("-i","--interface", metavar="<interface>", help=interface_help_string, required=False, nargs='?',default='en0')
    parser.add_argument("-r", "--read", metavar ="<tracefile>",help=read_help_string, required=False)
    parser.add_argument("expression", help=expression_help_string, nargs='?', default="none")

    # Parse the arguments
    args = parser.parse_args()

    # Access and display the arguments

    if args.interface:
        print(f"Interface: {args.interface}")
    if args.read:
        print(f"Tracefile: {args.read}")
    if args.expression: 
        print(f"Expression: {args.expression}")

    return args.interface, args.read,args.expression

def handle_packet(packet):
    """
    This function will be called for each captured packet.
    You can add custom logic here to process or filter packets.
    """
    print(packet[Raw].load)
    


def main(interfaceName):
    try:
        print("Packet capturing started. Press Ctrl+C to stop.")
        # Start sniffing packets. The store=0 ensures packets are not kept in memory for performance.
        sniff(iface=interfaceName, prn=handle_packet, store=0)
    except KeyboardInterrupt:
        print("\nCapturing stopped by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")

if __name__ == "__main__":
    #logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Suppress the No IPv4 address warning on interfaces
    interfaceName, tracefile, expression = captureOptions()
    main(interfaceName)