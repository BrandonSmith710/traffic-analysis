from scapy.all import *
import sys


common_ports =  [
    21, 22, 23, 25, 53, 69, 80, 88, 109, 110, 
    123, 137, 138, 139, 143, 156, 161, 389, 443, 
    445, 500, 546, 547, 587, 660, 995, 993, 2086, 
    2087, 2082, 2083, 3306, 8443, 10000 
]


def is_up(ip):
    icmp = IP(dst = ip) / ICMP()
    resp = sr1(icmp, timeout = 10)
    if resp == None:
        return False
    else:
        return True

def probe_port(ip, port, result = 1):
    src_port = RandShort()
    try:
        # probe ports using FIN, PSH, and URG flags
        p = IP(dst = ip) / TCP(sport = src_port, dport = port, flags = 'FPU')
        resp = sr1(p, timeout = 2) # Sending packet
        if str(type(resp)) == "<type 'NoneType'>":
            result = 1
        elif resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            if flags == 0x14:
                result = 0
            elif (int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                result = 2

    except Exception as e:
        pass

    return result


if __name__ == '__main__':
    conf.verb = 0
    ip = sys.argv[1]
    ports = map(int, sys.argv[2].split('-'))
    start, ending = ports
    tmp_cmn = set(list(range(start, ending + 1)) + common_ports)
    if is_up(ip):
        status = ['closed', 'open', 'filtered']
        for port in tmp_cmn:
            res = probe_port(ip, port)
            s = status[res]
            if s == 'open':
                print(f'Port {port}: {status[res]}')
    else:
        print ("Host is Down")