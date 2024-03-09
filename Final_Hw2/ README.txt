CSE508: Network Security, Spring 2024
Homework 2: Network Monitoring with Scapy
Student Name: Santa Maria Shithil
SBU ID: 115074486
-------------------------------------------------------------------------------
-------------------------------------------------------------------------------

Install Packages
----------------
Scapy Installation command: sudo apt install python3-scapy


Task1: HTTP/TLS connection monitoring
--------------------------------------
Implementation:
    1. Main function takes command line arguments from the user with the help of capture_options() function and pass it 
    to the trackingFromInterface() or trackingFromFile() function. If no argument passes to the main function, then by default
    the trackingFromInterface() will be called with the default interface and empty expression. If either only readfile or 
    both readfile and interface pass as argument then trackingFromFile() function will be called and will trace the packet 
    from the file and ignore the interface (Note: tcmdump also works this way). 
    2. capture_options(): This function captures the arguments from the command line and return these to the main function to do the tracing
    2. trackingFromInterface(): This function will track the packet from the given interface based on the expression. It will send 
    every traced packet to the handle_packet() function.
    3. trackingFromFile(): This function will track the packet from the given file based on the expression. It will also send
    every traced packet to the handle_packet() function.
    4. handle_packet(): This function will filter the HTTP request and the TLSClientHello request. It then retrive the required
    information from the packet with the help of various handler functions and print it: 
            a. format_time(): convert packet captured time to human readable format              
            b. format_tls_version() : convert the TLS version to human readdable version             
            c. get_HTTP_Info(): decode and retrive HTTP request method, URI, host, and version number                                                                #
            d. get_TLS_Info(): decode and retrive TLS version number, and the destination host name

Sample Output: We can run with various iptions. Following I have given all possible options with their output. 

    Sample1: 


