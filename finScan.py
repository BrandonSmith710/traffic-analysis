import sys
from scapy.all import *


def icmp_probe(ip):
    icmp_packet = IP(dst = ip) / ICMP()
    resp_packet = sr1(icmp_packet, timeout = 10)
    return resp_packet != None


def fin_scan(ip, port):
    src = RandShort()
    ip = IP(dst = ip)
    tcp = TCP(sport = src, dport = port, flags = "F")
    pkt = ip / tcp
    res = sr1(pkt, timeout = 1, verbose = 0)
    if res != None:
        if res.haslayer(TCP):
            if res[TCP].flags == 20:
                return True
            if int(res[ICMP].type) == 3 and int(res[ICMP].code) in [1, 2, 3, 9, 10, 13]:
                return 2
    return False
    

if __name__ == "__main__":
    ip = sys.argv[1]
    ports = sys.argv[2].split('-')
    status = ['open', 'closed', 'filtered']
    if icmp_probe(ip):
        for port in range(int(ports[0]), int(ports[-1]) + 1):
            fin_ack_packet = fin_scan(ip, port)
            s = status[fin_ack_packet]
            if s == 'open':
            	print(f"Port {port}: {s}")
    else:
        print("ICMP Probe Failed")