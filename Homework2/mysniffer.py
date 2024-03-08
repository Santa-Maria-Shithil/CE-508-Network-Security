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
    interface = conf.iface
    read = None
    expression = None
    parser = argparse.ArgumentParser(description="Parsing argument from the command line.")

    interface_help_string = "Live capture from the network device <interface> (e.g., eth0). If not specified,  the program should automatically select a default interface to listen on. Capture should continue indefinitely until the user terminatesthe program."
    read_help_string = "Read packets from <tracefile> (tcpdump format). Useful for analyzing network traces that have been captured previously."
    expression_help_string = "The optional <expression> argument is a BPF filter that specifies a subset of the traffic to be monitored (similar to tcpdump)."

    #Adding arguments
    parser.add_argument("-i","--interface", metavar="<interface>", help=interface_help_string, required=False)
    parser.add_argument("-r", "--read", metavar ="<tracefile>",help=read_help_string, required=False)
    parser.add_argument("expression", help=expression_help_string, nargs='?', default="")

    # Parse the arguments
    args = parser.parse_args()

    # Access and display the arguments

    if args.interface:
        interface = args.interface

    if args.read:
        read = args.read
        
    if args.expression: 
        expression =args.expression
        
    print(f"Interface: {interface}")
    print(f"Tracefile: {read}")
    print(f"Expression: {expression}")

    return interface, read, expression

def format_time(timestamp):
    # Example packet.time value
    packet_time = 1617709832.123456

    # Convert the integer part to a datetime object
    dt_object = datetime.fromtimestamp(int(packet_time))

    # Add the microsecond precision
    microseconds = int((packet_time - int(packet_time)) * 1_000_000)
    dt_object_with_microseconds = dt_object.replace(microsecond=microseconds)

    # Format as a string for readability
    formatted_time = dt_object_with_microseconds.strftime('%Y-%m-%d %H:%M:%S.%f')

    return formatted_time


def format_tls_version(version):
    # Split the version number into major and minor components
    major = version >> 8  # Get the higher byte
    minor = version & 0xFF  # Get the lower byte
    
    # Adjust the base for the major version if necessary. TLS versions are usually represented with the major version as 3.
    # The minor version then dictates the sub-version of TLS (e.g., 0x0303 is TLS 1.2, so minor version 3 means 1.2)
    formatted_version = f"TLS {major - 2}.{minor}"
    return formatted_version

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
        version = format_tls_version(tls_layer.version)
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
            print(f"{format_time(packet.time)} {version} {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport} {host} {method} {url}")
        except Exception as e:
            print(f"Could not decode the HTTP payload.{e}")

    if packet.haslayer(TLS):
        try:
            tls_version, host_name = get_TLS_Info(packet)
            if tls_version != None and host_name != None:
                print(f"{format_time(packet.time)} {tls_version} {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport} {host_name}")
        except Exception as e:
            print(f"Could not decode the TLS payload.{e}")

def trackingFromInterface(interfaceName,exp):
    try:
        print("Packet capturing started. Press Ctrl+C to stop.")
        sniff( prn=handle_packet, store=0, iface = interfaceName, filter = exp)
    except KeyboardInterrupt:
        print("\nCapturing stopped by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")

def trackingFromFile(fileName,exp):
    try:
        sniff( prn=handle_packet, offline = fileName, filter = exp)
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        
if __name__ == "__main__":
    interfaceName, tracefile, expression = captureOptions()
    if tracefile == None:
        trackingFromInterface(interfaceName,expression)
    else:
        trackingFromFile(tracefile,expression)