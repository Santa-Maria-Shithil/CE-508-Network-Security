import argparse
from scapy.all import *
import logging
from datetime import datetime


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

def current_time():
    now = datetime.now()
    # Format the current time
    formatted_time = now.strftime('%Y-%m-%d %H:%M:%S') + '.' + str(now.microsecond)
    return formatted_time

def parse_http_headers(payload):
    try:
        headers, body = payload.decode().split("\r\n\r\n", 1)
    except ValueError:
        headers = payload.decode()
        body = ""
    except:
        return None, None  # In case of non-decodable payloads
    header_lines = headers.split("\r\n")
    return header_lines, body

def extract_host_and_url(header_lines):
    host, url = None, None
    for line in header_lines:
        if line.startswith("Host:"):
            host = line.split(":", 1)[1].strip()
        elif line.startswith("GET") or line.startswith("POST"):
            url = line.split(" ")[1]
    return host, url


def handle_packet(packet):
    """
    This function will be called for each captured packet.
    You can add custom logic here to process or filter packets.
    """
    #print(f"Captured packet: {packet}")
    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
    # Check for HTTP (port 80) 
        if tcp_layer.dport == 80 or tcp_layer.sport == 80:
            #print(f"Packet: {ip_layer.src} -> {ip_layer.dst} | {tcp_layer.sport} -> {tcp_layer.dport}")
            if packet.haslayer(Raw):
                # If HTTP, attempt to print the raw data
                try:
                    payload = packet[Raw].load.decode(errors='ignore')
                    if payload.startswith('GET'):
                        header_lines, body = parse_http_headers(packet[Raw].load)
                        if header_lines:
                            host, url = extract_host_and_url(header_lines)
                        print(f"{current_time()} HTTP {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport} {host} GET {url}")
                        #print(payload)
                        #print("----------")
                    if payload.startswith('POST'):
                        header_lines, body = parse_http_headers(packet[Raw].load)
                        if header_lines:
                            host, url = extract_host_and_url(header_lines)
                        print(f"{current_time()} HTTP {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport} {host} POST {url}")
                        #print(payload)
                        #print("----------")
                except Exception as e:
                    print("Could not decode the payload.")


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
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Suppress the No IPv4 address warning on interfaces
    interfaceName, tracefile, expression = captureOptions()
    main(interfaceName)


#ln -s /Applications/Wireshark.app/Contents/MacOS/tshark /usr/local/bin/tshark
