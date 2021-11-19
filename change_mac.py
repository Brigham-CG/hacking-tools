#!/bin/python3
# change mac_address

import subprocess
import optparse
import re
from random import randint

def gen_command(command, std = 1):

    if std == 1:
        return subprocess.call(command, shell=True)
    elif std == 2:
        return subprocess.call(command, shell=True, stdout=subprocess.DEVNULL)
    elif std == 3:
        return subprocess.call(command, shell=True, stderr=subprocess.DEVNULL)

def gen_rand_mac_add():

    hex_str = ""
    for i in range(6):
        hex_str += str(hex(randint(0,255)))[2:]+":"

    return hex_str[:-1]

def main():

    # define options to run in the terminal
    parser = optparse.OptionParser()
    parser.add_option("-I", "--interface", dest = "interface", help="Input a interface.\n Example: eth0")
    parser.add_option("-M", "--mac", dest = "mac", help="Input a new mac address to change.\n Example: 00:10:fa:c2:bf:d5")

    # obtain a interface and a mac address 
    (options, arguments) = parser.parse_args()

    interface = options.interface 
    new_mac = options.mac

    if(not interface):
        interface = input("[?]Ingrese la interfaz: ")

    # obtain to old mac address
    ifconfig_check = subprocess.check_output(["ifconfig", interface]).decode()
    old_mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_check).group()
    
    print( "[+] Interface: {0}".format(interface))
    gen_command(f"sudo ifconfig {interface} down")    
    if(new_mac):

        if(bool(gen_command("sudo ifconfig {0} hw ether {1}".format(interface, new_mac), 3))):
            print("[-] The mac address joined was wrong")
            print("[-] Can't change the mac address")
            return  
    else:

        print("[+] Genering a random mac address....")

        gen = True
        while(gen):
            new_mac = gen_rand_mac_add()
            gen = bool(gen_command("sudo ifconfig {0} hw ether {1}".format(interface, new_mac), 3))

    gen_command(f"sudo ifconfig {interface} up")
    print("[+] Old mac address: " + old_mac) 
    print("[+] New mac address: " + new_mac)

if __name__ == "__main__":
    main()
