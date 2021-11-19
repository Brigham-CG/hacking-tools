#!/usr/bin/python3


import optparse
import scapy.all as scapy
from scapy.fields import LEIntEnumField

def pingScan(ip):
    print("[+] Scanning the IP address")
    scapy.arping(ip)
    
def arpScan(ip):
    print("[+] Scanning the MAC address")
    
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    print(answered)
    print("\nIP\t\t\tMAC addresses")
    for element in answered:
        print(element[1].psrc+"\t\t"+element[1].hwsrc)

def main():

    try:
        parser = optparse.OptionParser()
        parser.add_option("-P", "--scanping", dest="sp", help="Scan ip address, Use CIDR for multiples addresses. Example: 192.168.1.1")
        parser.add_option("-A", "--scanarp", dest="sa", help="Scan ip address, Use CIDR for multiples addresses. Example: 192.168.1.1")

        (options, arguments) = parser.parse_args()
        sp = options.sp
        sa = options.sa
    
        if(sp):
            pingScan(sp)
        elif(sa):
            arpScan(sa)
        else:
            print("[?] Use the option '-h' or '--help' to view the functions")
    except PermissionError:
        print("[-]You need administrator permission to execute this script")

if(__name__ == "__main__"):
    main()