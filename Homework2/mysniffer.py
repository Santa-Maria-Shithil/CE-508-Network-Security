import argparse
from scapy.all import sniff, TCP, Raw, IP
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

def is_http_header(packet):
    """
    Very basic heuristic to check if a packet payload looks like an HTTP request.
    This function checks for the presence of HTTP methods in the payload.
    """
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            # Common HTTP methods that could indicate an HTTP request
            methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'CONNECT ']
            return any(method in payload for method in methods)
        except:
            return False

def is_tls_header(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        # Check for the presence of a TLS handshake (0x16) and "Client Hello" (0x01)
        if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
            return True
    return False

def decimal_to_tls_version(decimal_version):
    tls_versions = {
        769: "TLS v1.0",
        770: "TLS v1.1",
        771: "TLS v1.2",
        772: "TLS v1.3",
    }
    return tls_versions.get(decimal_version, "Unknown TLS Version")

def get_version(packet):


    tls_packet = TLS(packet[Raw].load)
    if tls_packet.haslayer(TLSClientHello):
        client_hello = tls_packet[TLSClientHello]
        version = decimal_to_tls_version(client_hello.version)
        
        for msg in tls_packet.msg: #problem: can not capture the server name from TLS packet
            if isinstance(msg, TLSClientHello):
                print(f"TLS Version: {msg.version}")
                sni = next((ext for ext in msg.ext if isinstance(ext, TLS_Ext_ServerName)), None)
                if sni:
                    for server_name in sni.servernames:
                        print(f"SNI: {server_name.data.decode()}")
                        hostname = server_name.data.decode()
                        return version, hostname
        return version, None
        
 

    return None, None


def handle_packet(packet):
    """
    This function will be called for each captured packet.
    You can add custom logic here to process or filter packets.
    """

    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        if is_http_header(packet):
            try:
                payload = packet[Raw].load.decode('utf-8')
                if payload.startswith('GET'):
                    header_lines, body = parse_http_headers(packet[Raw].load)
                    if header_lines:
                        host, url = extract_host_and_url(header_lines)
                    print(f"{current_time()} HTTP {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport} {host} GET {url}")
                if payload.startswith('POST'):
                    header_lines, body = parse_http_headers(packet[Raw].load)
                    if header_lines:
                        host, url = extract_host_and_url(header_lines)
                    print(f"{current_time()} HTTP {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport} {host} POST {url}")
            except Exception as e:
                print("Could not decode the HTTP payload.")

        if is_tls_header(packet):
            try:

                tls_version, host_name = get_version(packet)
                print(f"{current_time()} {tls_version} {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport} {host_name}")
            except Exception as e:
                print(f"Could not decode the TLS payload.{e}")

def main(interfaceName):
    try:
        print("Packet capturing started. Press Ctrl+C to stop.")
        # Start sniffing packets. The store=0 ensures packets are not kept in memory for performance.
        #sniff(iface=interfaceName, prn=handle_packet, store=0)
        sniff( prn=handle_packet, store=0)
    except KeyboardInterrupt:
        print("\nCapturing stopped by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")

if __name__ == "__main__":
    #logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Suppress the No IPv4 address warning on interfaces
    interfaceName, tracefile, expression = captureOptions()
    main(interfaceName)


#ln -s /Applications/Wireshark.app/Contents/MacOS/tshark /usr/local/bin/tshark
