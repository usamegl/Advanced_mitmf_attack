import scapy.all as scapy
from scapy_http import http


def data_collect(interface):
scapy.sniff(iface="eth0", store=False, prn=data_analysis)

def data_analysis(packet):
  #packet.show()
  if packet.haslayer(http.HTTPRequest):
    if packet.haslayer(scapy.Raw):
       print(packet[scapy.Raw].load)
    
data_collect("eth0")

  
