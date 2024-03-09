##################################################################################################
#                                    Imported Packages                                           #
##################################################################################################
import argparse
from datetime import datetime
from scapy.all import *
from scapy.layers.tls.all import *
load_layer("tls")
load_layer("http")


##################################################################################################
#                            Command Line Argument Handler Function                              #
#   capture_options(): capture the arguments from the command line and return these              #
#                     to the main function to do the tracing                                     #
##################################################################################################

def capture_options():   
    
    # Initializing the command arguments
    interface = conf.iface
    read = None
    expression = None

    # Initializing the parser of the command arguments
    parser = argparse.ArgumentParser(description="Parsing argument from the command line.")

    # Creating the parser     
    interface_help_string = "Live capture from the network device <interface> (e.g., eth0). If not specified,  the program should automatically select a default interface to listen on. Capture should continue indefinitely until the user terminatesthe program."
    read_help_string = "Read packets from <tracefile> (tcpdump format). Useful for analyzing network traces that have been captured previously."
    expression_help_string = "The optional <expression> argument is a BPF filter that specifies a subset of the traffic to be monitored (similar to tcpdump)."

    #Adding arguments
    parser.add_argument("-i","--interface", metavar="<interface>", help=interface_help_string, required=False)
    parser.add_argument("-r", "--read", metavar ="<tracefile>",help=read_help_string, required=False)
    parser.add_argument("expression", help=expression_help_string, nargs='?', default="")

    # Parsing the arguments
    args = parser.parse_args()

    # Access, display, and return the arguments

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

##################################################################################################
#                                      Helper Functions                                          #
#   format_time(): convert packet captured time to human readable format                         #
#   format_tls_version() : convert the TLS version to human readdable version                    #
#   get_HTTP_Info(): decode and retrive HTTP request method, URI, host, and version              #
#                          number                                                                #
#   get_TLS_Info(): decode and retrive TLS version number, and the                               #
#                         destination host name                                                  #
##################################################################################################

def format_time(packet_time):
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

    formatted_version = f"TLS v{major - 2}.{minor}"
    
    return formatted_version

def get_HTTP_Info(packet):

    #initializing the variables 
    method = None
    url = None
    host = None
    version = None

    #retrieving the method
    method = packet[HTTPRequest].Method.decode('utf-8') 
    #retrieving the Request URI
    url = packet[HTTPRequest].Path.decode('utf-8')
    #retrieving the Host
    host = packet[HTTPRequest].Host.decode('utf-8')
    #retrieving the version number
    version = packet[HTTPRequest].Http_Version.decode('utf-8')

    return method, url, host, version


def get_TLS_Info(packet):
    #initializing the variables
    version = None
    server_name = None
    tls_layer = packet[TLS]

    #checking whether has TLS Client Hello or not
    if tls_layer.haslayer(TLSClientHello):
        # reteive the version number
        version = format_tls_version(tls_layer.version)
        if tls_layer.haslayer(TLS_Ext_ServerName):
            #retrieving server name
            server_name_ext = tls_layer[TLS_Ext_ServerName]
            server_name = server_name_ext.servernames[0].servername.decode()

    return version, server_name

##################################################################################################
#                                         Packet Handler Function                                #
#   handle_packet(): This function is called for each tracked packet, filter HTTP request and    # 
#                    TLSClientHello, and then print the packet info                              #
##################################################################################################

def handle_packet(packet):

    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
    
    #filtering HTTPRequest packet
    if packet.haslayer(HTTPRequest):
        try:
            method, url, host, version = get_HTTP_Info(packet)
            if method == "GET" or method == "POST":
                print(f"{format_time(packet.time)} {version} {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport} {host} {method} {url}")
        except Exception as e:
            print(f"Could not decode the HTTP payload.{e}")
    #filtering TLSClientHello packet
    if packet.haslayer(TLS):
        try:
            tls_version, host_name = get_TLS_Info(packet)
            if tls_version != None and host_name != None:
                print(f"{format_time(packet.time)} {tls_version} {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport} {host_name}")
        except Exception as e:
            print(f"Could not decode the TLS payload.{e}")

##################################################################################################
#                                    Packet Tracing Function(Interface)                          #
#   trackingFromInterface(): trace the packet from the interface                                 #
##################################################################################################
def trackingFromInterface(interfaceName,exp):
    try:
        print("Packet capturing started. Press Ctrl+C to stop.")
        sniff( prn=handle_packet, store=0, iface = interfaceName, filter = exp)
    except KeyboardInterrupt:
        print("\nCapturing stopped by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")

##################################################################################################
#                                    Packet Tracing Function(From File)                          #
#   trackingFromFile(): trace the packet from the file                                           #
##################################################################################################
def trackingFromFile(fileName,exp):
    try:
        sniff( prn=handle_packet, offline = fileName, filter = exp)
    except Exception as e:
        print(f"\nAn error occurred: {e}")

##################################################################################################
#                                    Main Function                                               #
#   This is the main function, program starts from here                                          #
##################################################################################################
if __name__ == "__main__":
    interfaceName, tracefile, expression = capture_options()
    if tracefile == None:
        trackingFromInterface(interfaceName,expression)
    else:
        trackingFromFile(tracefile,expression)