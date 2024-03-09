##################################################################################################
#                                    Imported Packages                                           #
##################################################################################################
import subprocess
import argparse
from scapy.all import *
from scapy.layers.tls.all import *
import re


##################################################################################################
#                            Command Line Argument Handler Function                              #
#   capture_options(): capture the arguments from the command line and return these              #
#                     to the main function to do the tracing                                     #
##################################################################################################
def capture_options():   
    # Initializing the command arguments
    interface = conf.iface

    # Initializing the parser of the command arguments
    parser = argparse.ArgumentParser(description="Parsing argument from the command line.")

    interface_help_string = "Live capture from the network device <interface> (e.g., eth0). If not specified,  the program should automatically select a default interface to listen on. Capture should continue indefinitely until the user terminates the program."

    #Adding arguments
    parser.add_argument("-i","--interface", metavar="<interface>", help=interface_help_string, required=False)


    # Parse the arguments
    args = parser.parse_args()

    # Access, display, and return the arguments

    if args.interface:
        interface = args.interface
        
    print(f"Interface: {interface}")

    return interface

##################################################################################################
#                                      ARP Cache Reading Function                                #
#       read_arp_cache(): This function read the ARP cache                                       #
##################################################################################################
def read_arp_cache():
        
    command = "arp -a"  
    
    # Execute the command
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    # Decode the output from bytes to string
    arp_output = stdout.decode().strip()
    
    if stderr:
        print("Error:", stderr.decode())
    
    return arp_output

##################################################################################################
#                                         ARP Poising Tracker                                    #
#   handle_packet(): This function is called for each tracked packet, check whether is there     #
#   any ARP poising if there is any attack, then detect it and print the warning                 #
##################################################################################################

def handle_packet(packet):

    if packet[ARP].op == 2: # ARP response (op=2)
        tracked_ip = packet[ARP].psrc
        tracked_mac = packet[ARP].hwsrc
        print(packet)
        pattern = re.compile(r'\S+ \(([\d\.]+)\) at ([\da-f:]+) \[ether\] on (\w+)')
        ipfound = False
        macfound = False
        for match in pattern.finditer(ARP_ENTRIES):

            ip, mac, _ = match.groups()
            if ip.strip() == tracked_ip.strip():
                ipfound = True
                if mac.strip().lower() == tracked_mac.strip().lower():
                    macfound = True
                break
                

        if ipfound == True and macfound ==False:
            print("##########################Warning Warning Warning#################")
            print("There is an ARP cache poisoning")
            print(f"{tracked_ip} changed from {mac.lower()} to {tracked_mac.lower()}")

##################################################################################################
#                                    Packet Tracing Function                                     #
#   trackingFromInterface(): trace the packet from the interface                                 #
#   arp_filter(): filter ARP packets                                                             #
##################################################################################################
def arp_filter(packet):
    return "ARP" in packet

def trackingFromInterface(interfaceName):
    try:
        print("ARP cache poisoning detector started. Press Ctrl+C to stop.")
        # Start sniffing packets. The store=0 ensures packets are not kept in memory for performance.
        sniff( prn=handle_packet, store=0, iface = interfaceName, lfilter=arp_filter)
    except KeyboardInterrupt:
        print("\nCapturing stopped by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")

##################################################################################################
#                                    Main Function                                               #
#   This is the main function, program starts from here                                          #
##################################################################################################

ARP_ENTRIES = read_arp_cache()

if __name__ == "__main__":
    interfaceName = capture_options()
    print("The ARP cache is:")
    print(ARP_ENTRIES)

    trackingFromInterface(interfaceName)

    