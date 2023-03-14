from scapy.all import *
import sys

def icmp_probe(ip):
    icmp_packet = IP(dst = ip) / ICMP()
    resp_packet = sr1(icmp_packet, timeout = 10)
    return resp_packet != None
    
def syn_scan(ip, dport):
    sport = RandShort()
    syn_packet = sr1(IP(dst = ip) / TCP(sport = sport, dport = dport, flags = "S"),
		 verbose = 0)
    flags = syn_packet.getlayer("TCP").flags    
    if flags.value == 20:
        return True
    return False
    

if __name__ == "__main__":
    ip = sys.argv[1]
    ports = sys.argv[2].split('-')
    status = ['open', 'closed']
    if icmp_probe(ip):
        for port in range(int(ports[0]), int(ports[-1]) + 1):
            syn_ack_packet = syn_scan(ip, port)
            s = status[syn_ack_packet]
            if s == "open":
                print(f"Port {port}: open")
    else:
        print("ICMP Probe Failed")
