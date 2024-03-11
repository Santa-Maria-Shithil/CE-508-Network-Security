CSE508: Network Security, Spring 2024
Homework 2: Network Monitoring with Scapy
Student Name: Santa Maria Shithil
SBU ID: 115074486
-------------------------------------------------------------------------------
-------------------------------------------------------------------------------

Install Packages
----------------
Scapy Installation command: sudo apt install python3-scapy (Note: I ran my code in 64-bit Kali Linux 2023.4, so I hadn't need to install
                                                          it separately.)


Task1: HTTP/TLS connection monitoring
--------------------------------------
Implementation:
    1. Main function takes command line arguments from the user with the help of capture_options() function and pass it 
    to the trackingFromInterface() or trackingFromFile() function. If no argument passes to the main function, then by default
    the trackingFromInterface() will be called with the default interface and empty expression. If either only read-file or 
    both read-file and interface pass as argument then trackingFromFile() function will be called and will trace the packet 
    from the file and ignore the interface (Note: tcmdump also works this way). Both these function will call the handle_packet() 
    function for each captured packet. 
    2. capture_options(): This function captures the arguments (interface, file name, expression) from the command line and return 
    these to the main function to do the tracing
    3. trackingFromInterface(): This function will track the packet from the given interface based on the expression until the user
    interrupt. It will send every traced packet to the handle_packet() function.
    4. trackingFromFile(): This function will track the packet from the given file based on the expression. It will also send
    every traced packet to the handle_packet() function.
    5. handle_packet(): This function will filter the HTTP request and the TLSClientHello request. It then retrieve the required
    information from the packet with the help of various handler functions and print it: 
            a. format_time(): convert packet captured time to human readable format              
            b. format_tls_version() : convert the TLS version to human readable version             
            c. get_HTTP_Info(): decode and retrieve HTTP request method, URI, host, and version number                                                                
            d. get_TLS_Info(): decode and retrieve TLS version number, and the destination host name

Sample Output: We can run with various options combination. Following I have given few possible combinations (both correct
and incorrect) with  their output. 

    Sample1: Without any command line argument (Note: Incase of HTTP request, professor only asked to print HTTP as protocol,
                                                I have printed the protocol with the version number)
        Command: 
            Console1: sudo python  mysniffer.py
            Console2: wget http://www.google.com
                      wget http://www.google.com/gmail
                      wget http://www.facebook.com
        Output: 
        Interface: eth0
        Tracefile: None
        Expression: None
        Packet capturing started. Press Ctrl+C to stop.
        2024-03-08 21:29:48.716315 HTTP/1.1 192.168.15.129:41734 -> 172.253.122.103:80 www.google.com GET /
        2024-03-08 21:30:08.245638 HTTP/1.1 192.168.15.129:35848 -> 172.253.122.99:80 www.google.com GET /gmail
        2024-03-08 21:30:08.515520 TLS v1.1 192.168.15.129:59166 -> 142.251.163.19:443 mail.google.com
        2024-03-08 21:30:08.662162 TLS v1.1 192.168.15.129:59970 -> 142.251.111.84:443 accounts.google.com
        2024-03-08 21:30:28.144754 TLS v1.1 192.168.15.129:43954 -> 157.240.241.35:443 www.facebook.com

    Sample2: With an expression as the argument. In this case, though I have used the same wget request as sample1,
    because of the given expression only request of port 80 filtered and printed. 
        Command: 
            Console1: sudo python  mysniffer.py 'port 80'
            Console2: wget http://www.google.com
                      wget http://www.google.com/gmail
                      wget http://www.facebook.com
        Output: 
        Interface: eth0
        Tracefile: None
        Expression: port 80
        Packet capturing started. Press Ctrl+C to stop.
        2024-03-08 21:43:58.347173 HTTP/1.1 192.168.15.129:55738 -> 172.253.63.104:80 www.google.com GET /
        2024-03-08 21:44:03.838232 HTTP/1.1 192.168.15.129:54702 -> 172.253.63.103:80 www.google.com GET /gmail

    Sample3: With interface as an argument. 
        Command: 
            Console1: sudo python  mysniffer.py -i eth0 
            Console2: wget http://www.google.com
                      wget http://www.google.com/gmail
                      wget http://www.facebook.com
        Output: 
        Interface: eth0
        Tracefile: None
        Expression: None
        Packet capturing started. Press Ctrl+C to stop.
        2024-03-08 21:50:20.058094 HTTP/1.1 192.168.15.129:40812 -> 172.253.63.104:80 www.google.com GET /
        2024-03-08 21:50:22.835745 HTTP/1.1 192.168.15.129:51044 -> 172.253.63.105:80 www.google.com GET /gmail
        2024-03-08 21:50:22.877604 TLS v1.1 192.168.15.129:47870 -> 172.253.115.19:443 mail.google.com
        2024-03-08 21:50:23.098479 TLS v1.1 192.168.15.129:58434 -> 142.251.16.84:443 accounts.google.com
        2024-03-08 21:50:26.044213 TLS v1.1 192.168.15.129:40920 -> 157.240.241.35:443 www.facebook.com

    Sample4: With read file as an argument. (Note: though I haven't gave any interface argument but still assigning eth0
                                            as default argument as professor asked. But it will read the trace from
				                            the given trace.pcap file) 
        Command: 
            Console1: sudo python  mysniffer.py -r trace.pcap

        Output:
        Interface: eth0 
        Tracefile: trace.pcap
        Expression: None
        2013-01-12 22:30:49.032953 HTTP/1.0 192.168.0.200:40341 -> 87.98.246.8:80 pic.leech.it:80 GET /i/f166c/479246b0asttas.jpg
        2013-01-12 22:31:19.244125 HTTP/1.0 192.168.0.200:40630 -> 216.137.63.121:80 ecx.images-amazon.com:80 GET /images/I/41oZ1XsiOAL.
        2013-01-12 22:31:50.359908 HTTP/1.0 192.168.0.200:55528 -> 159.148.96.184:80 images4.byinter.net:80 GET /DSC442566.gif
        2013-01-13 02:54:46.028958 HTTP/1.1 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/InRelease
        2013-01-13 02:54:46.032578 HTTP/1.1 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/InRelease
        2013-01-13 02:54:46.056291 HTTP/1.1 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release.gpg
        2013-01-13 02:54:46.062554 HTTP/1.1 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/Release.gpg
        2013-01-13 02:54:46.082239 HTTP/1.1 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release
        2013-01-13 02:54:46.094457 HTTP/1.1 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/Release
        2013-01-13 02:54:46.102039 HTTP/1.1 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/InRelease


    Sample5: With both interface, read, and expression as command line argument.  In this case, the interface is ignored
    and trace the packet from the read file. Because of the given expression, only the packets of port 80 are tracked. 
        Command: 
            Console1: sudo python  mysniffer.py -r trace.pcap -i eth0 "port 80"

        Output:
        Interface: eth0
        Tracefile: trace.pcap
        Expression: port 80
        reading from file trace.pcap, link-type EN10MB (Ethernet), snapshot length 65535
        2013-01-12 22:30:49.032953 HTTP/1.0 192.168.0.200:40341 -> 87.98.246.8:80 pic.leech.it:80 GET /i/f166c/479246b0asttas.jpg
        2013-01-12 22:31:19.244125 HTTP/1.0 192.168.0.200:40630 -> 216.137.63.121:80 ecx.images-amazon.com:80 GET /images/I/41oZ1XsiOAL.
        2013-01-12 22:31:50.359908 HTTP/1.0 192.168.0.200:55528 -> 159.148.96.184:80 images4.byinter.net:80 GET /DSC442566.gif
        2013-01-13 02:54:46.028958 HTTP/1.1 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/InRelease
        2013-01-13 02:54:46.032578 HTTP/1.1 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/InRelease
        2013-01-13 02:54:46.056291 HTTP/1.1 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release.gpg
        2013-01-13 02:54:46.062554 HTTP/1.1 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/Release.gpg
        2013-01-13 02:54:46.082239 HTTP/1.1 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release
        2013-01-13 02:54:46.094457 HTTP/1.1 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/Release
        2013-01-13 02:54:46.102039 HTTP/1.1 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/InRelease


    Sample6: Specified -r option but not mentioned the read-file
        Command: 
            Console1: sudo python  mysniffer.py -r  

        Output:
        usage: mysniffer.py [-h] [-i <interface>] [-r <tracefile>] [expression]
        mysniffer.py: error: argument -r/--read: expected one argument

    Sample7: Specified -i option but not mentioned the interface
        Command: 
            Console1: sudo python  mysniffer.py -i

        Output:
        usage: mysniffer.py [-h] [-i <interface>] [-r <tracefile>] [expression]
        mysniffer.py: error: argument -i/--interface: expected one argument

    Sample8: Wrong expression.
        Command: 
            Console1: sudo python  mysniffer.py NS

        Output:
        Interface: eth0
        Tracefile: None
        Expression: NS
        Packet capturing started. Press Ctrl+C to stop.
        ERROR: Cannot set filter: Failed to compile filter expression NS (-1)

    Sample9: With help as command line argument.
        Command: 
            Console1: sudo python  mysniffer.py -h 

        Output:
        usage: mysniffer.py [-h] [-i <interface>] [-r <tracefile>] [expression]

        Parsing argument from the command line.

        positional arguments:
        expression            The optional <expression> argument is a BPF filter
                                that specifies a subset of the traffic to be
                                monitored (similar to tcpdump).

        options:
        -h, --help            show this help message and exit
        -i <interface>, --interface <interface>
                                Live capture from the network device <interface>
                                (e.g., eth0). If not specified, the program should
                                automatically select a default interface to listen
                                on. Capture should continue indefinitely until the
                                user terminates the program.
        -r <tracefile>, --read <tracefile>
                                Read packets from <tracefile> (tcpdump format).
                                Useful for analyzing network traces that have been
                                captured previously.

Task2: ARP cache poisoning detector
------------------------------------
Implementation:
    1. Main function takes command line arguments from the user with the help of capture_options() function and pass it 
    to the trackingFromInterface() function. This function will call the handle_packet() function for each captured packet.
    2. arp_cache(): This is used to read the ARP cache from the system and store it to a constant. This constant
    will be used as a ground truth to detect the  ARP poisoning. 
    3. capture_options(): This function captures the arguments (interface) from the command line and return these to the main 
    function to do the tracing.
    4. trackingFromInterface(): This function traces the ARP packet with the help of the arp_filter() function. The arp_filter() 
    function is used as a filter to the sniff() function of the Scapy library. 
    5. handle_packet(): This function is used to process every captured ARP response packet and match it with the stored ARP cache (that 
    I have stored in a constant). If it finds any mismatch between the announced MAC-IP binding with the MAC-IP binding of the stored ARP cache
    then it will print a warning. 

Output: 
    Sample1: Without any command line argument. The detector prints the warning whenever it receives a ARP response with a different MAC-IP 
    binding other than the saved ground truth cache. The IP address of the gateway, attacker, and the victim is as follows:
    Victim (VM1): 192.168.15.129
    Attacker (VM2): 192.168.15.130
    gateway: 192.168.15.2

        Command: 
            Console1(VM1): sudo python  arpwatch.py (*Note: ARP cache poisoning detector started)
            Console1(VM2): sudo arpspoof -i eth0 -t 192.168.15.129 192.168.15.2 (*Note: ARP poisoning attack initiated. Poisoning the victim's ARP cache)
            Console2(VM2): sudo arpspoof -i eth0 -t 192.168.15.2 192.168.15.129 (*Note: Poisoning the gateway's ARP cache)
        Output: 
        Interface: eth0
        The ARP cache is:
        ? (192.168.15.2) at 00:50:56:f9:78:b8 [ether] on eth0            (*Note: original MAC-IP binding of the gateway in the cache)
        ? (192.168.15.254) at 00:50:56:eb:be:61 [ether] on eth0
        ? (192.168.15.130) at 00:0c:29:df:98:ab [ether] on eth0          (*Note: attacker's MAC-IP binding in the cache)
        ARP cache poisoning detector started. Press Ctrl+C to stop.
        Ether / ARP is at 00:50:56:f9:78:b8 says 192.168.15.2 / Padding  (*Note: Original ARP response from the gateway)
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding  (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding    (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab

    Sample2: With command line argument. Again the detector prints the warning whenever it receives a ARP response with 
    a different MAC-IP binding other than the saved ground truth cache. The IP address of the gateway, attacker, and the 
    victim is as follows:
    Victim (VM1): 192.168.15.129
    Attacker (VM2): 192.168.15.130
    gateway: 192.168.15.2
    
        Command: 
            Console1(VM1): sudo python  arpwatch.py -i eth0 (*Note: ARP cache poisoning detector started)
            Console1(VM2): sudo arpspoof -i eth0 -t 192.168.15.129 192.168.15.2 (*Note: ARP poisoning attack initiated. Poisoning the victim's ARP cache)
            Console2(VM2): sudo arpspoof -i eth0 -t 192.168.15.2 192.168.15.129 (*Note: Poisoning the gateway's ARP cache)
        Output: 
        Interface: eth0
        The ARP cache is:
        ? (192.168.15.2) at 00:50:56:f9:78:b8 [ether] on eth0            (*Note: Original MAC-IP binding of the gateway in the ARP cache)
        ARP cache poisoning detector started. Press Ctrl+C to stop.
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding     (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab
        Ether / ARP is at 00:0c:29:df:98:ab says 192.168.15.2 / Padding (*Note: Spoofed ARP response from the attacker with a different MAC-IP binding of the gateway)
        ##########################Warning Warning Warning#################
        There is an ARP cache poisoning
        192.168.15.2 changed from 00:50:56:f9:78:b8 to 00:0c:29:df:98:ab

    Sample3: With wrong command line argument. 
        Command: 
            Console1(VM1): sudo python  arpwatch.py -i
        Output: 
        usage: arpwatch.py [-h] [-i <interface>]
        arpwatch.py: error: argument -i/--interface: expected one argument

    Sample4: With help as command line argument. 
        Command: 
            Console1(VM1): sudo python  arpwatch.py -h
        Output: 
        usage: arpwatch.py [-h] [-i <interface>]

        Parsing argument from the command line.

        options:
        -h, --help            show this help message and exit
        -i <interface>, --interface <interface>
                                Live capture from the network device <interface>
                                (e.g., eth0). If not specified, the program should
                                automatically select a default interface to listen
                                on. Capture should continue indefinitely until the
                                user terminates the program.