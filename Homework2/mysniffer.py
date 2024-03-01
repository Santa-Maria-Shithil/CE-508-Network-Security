##################################################################################################
#                                    Imported Packages                                           #
##################################################################################################
import argparse
from datetime import datetime
from scapy.all import *
from scapy.layers.tls.all import *
load_layer("tls")
load_layer("http")




def captureOptions():   
    # Create the parser
    parser = argparse.ArgumentParser(description="Parsing argument from the command line.")

    interface_help_string = "Live capture from the network device <interface> (e.g., eth0). If not specified,  the program should automatically select a default interface to listen on. Capture should continue indefinitely until the user terminatesthe program."
    read_help_string = "Read packets from <tracefile> (tcpdump format). Useful for analyzing network traces that have been captured previously."
    expression_help_string = "The optional <expression> argument is a BPF filter that specifies a subset of the traffic to be monitored (similar to tcpdump)."

    #Adding arguments
    parser.add_argument("-i","--interface", metavar="<interface>", help=interface_help_string, required=False, nargs='?',default=conf.iface)
    parser.add_argument("-r", "--read", metavar ="<tracefile>",help=read_help_string, required=False, nargs='?', default="none")
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

def decimal_to_tls_version(decimal_version):
    tls_versions = {
        769: "TLS v1.0",
        770: "TLS v1.1",
        771: "TLS v1.2",
        772: "TLS v1.3",
    }
    return tls_versions.get(decimal_version, "Unknown TLS Version")

def get_HTTP_Info(packet):
    method = None
    url = None
    host = None
    version = None
    method = packet[HTTPRequest].Method.decode('utf-8')
    url = packet[HTTPRequest].Path.decode('utf-8')
    host = packet[HTTPRequest].Host.decode('utf-8')
    version = packet[HTTPRequest].Http_Version.decode('utf-8')
    return method, url, host, version


def get_TLS_Info(packet):
    version = None
    server_name = None
    tls_layer = packet[TLS]
    if tls_layer.haslayer(TLSClientHello):
        version = decimal_to_tls_version(tls_layer.version)
        #print("TLS Version:", tls_layer.version)
        if tls_layer.haslayer(TLS_Ext_ServerName):
            #print("has exte")
            server_name_ext = tls_layer[TLS_Ext_ServerName]
            server_name = server_name_ext.servernames[0].servername.decode()

    return version, server_name


def handle_packet(packet):
    """
    This function will be called for each captured packet.
    You can add custom logic here to process or filter packets.
    """

    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        if packet.haslayer(HTTPRequest):
            try:
                method, url, host, version = get_HTTP_Info(packet)
                print(f"{current_time()} {version} {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport} {host} {method} {url}")
            except Exception as e:
                print(f"Could not decode the HTTP payload.{e}")

        if packet.haslayer(TLS):
            try:
                tls_version, host_name = get_TLS_Info(packet)
                if tls_version != None and host_name != None:
                    print(f"{current_time()} {tls_version} {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport} {host_name}")
            except Exception as e:
                print(f"Could not decode the TLS payload.{e}")

def trackingFromInterface(interfaceName):
    try:
        print("Packet capturing started. Press Ctrl+C to stop.")
        # Start sniffing packets. The store=0 ensures packets are not kept in memory for performance.
        #sniff(iface=interfaceName, prn=handle_packet, store=0)
        sniff( prn=handle_packet, store=0, iface = interfaceName)
    except KeyboardInterrupt:
        print("\nCapturing stopped by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")

def trackingFromFile(fileName):
    packets = rdpcap(fileName)
    for packet in packets:
        handle_packet(packet)

if __name__ == "__main__":
    interfaceName, tracefile, expression = captureOptions()
    if tracefile == "none":
        trackingFromInterface(interfaceName)
    else:
        trackingFromFile(tracefile)


