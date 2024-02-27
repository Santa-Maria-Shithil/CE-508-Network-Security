import argparse
import pyshark
import os

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


def live_capture(interface=None):
    # Create a live capture on a specific interface or default if None
    capture = pyshark.LiveCapture(interface=interface)
    
    print(f"Starting live capture on {'default interface' if interface is None else interface}...")
    try:
        for packet in capture.sniff_continuously():  # Remove packet_count to capture indefinitely
            print(f"Captured packet: {packet}")
    except KeyboardInterrupt:
        print("\nStopped packet capture.")

if __name__ == "__main__":
    interfaceName, tracefile, expression = captureOptions()
    live_capture(interface=interfaceName)




#ln -s /Applications/Wireshark.app/Contents/MacOS/tshark /usr/local/bin/tshark
