#!/usr/bin/env python

import struct
import socket
import subprocess
import re

import netifaces

class Host:
    def __init__(self, ip=None, hostname=None,
                        mac=None, vendor=None):
        self.ip = ip
        self.hostname = hostname
        self.mac = mac
        self.vendor = vendor

    def __str__(self):
        return "IP: {0}\nHostname: {1}\nMAC: {2}\nVendor: {3}"\
                .format(self.ip, self.hostname, self.mac, self.vendor)

def ip2int(ip):
    return struct.unpack('!I', socket.inet_aton(ip))[0]

def int2ip(number):
    return socket.inet_ntoa(struct.pack('!I', number))

def get_lower_ip(broadcast, netmask):
    bcast_int = ip2int(broadcast)
    nmask_int = ip2int(netmask)
    lower = bcast_int & nmask_int + 1
    return int2ip(lower)

def build_face_map(iface):
    ifaddr = netifaces.ifaddresses(iface)
    if 2 not in ifaddr:
        return []
    ipv4 = ifaddr[2][0]
    if 'netmask' not in ipv4 or 'broadcast' not in ipv4:
        return []
    hosts = []
    self_ip = ipv4['addr']
    netmask = ipv4['netmask']
    broadcast = ipv4['broadcast']
    lower = get_lower_ip(broadcast, netmask)
    lower_int = ip2int(lower)
    bcast_int = ip2int(broadcast)
    for i in range(bcast_int - lower_int):
        ip = int2ip(lower_int + i)
        try:
            host_info = socket.gethostbyaddr(ip)
            hosts.append(Host(ip, host_info[0], mac=get_mac(ip)))
        except socket.error:
            pass

    return hosts

def get_mac(ip):
    pid = subprocess.Popen(["arp", "-n", ip], stdout=subprocess.PIPE)
    result = pid.communicate()[0].decode('utf-8')
    re_search = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", result)
    if re_search:
        return re_search.groups()[0]



def build_global_map():
    netmap = dict()
    ifaces = netifaces.interfaces()
    for iface in [f for f in ifaces]:
        netmap[iface] = build_face_map(iface)

    for iface, hosts in netmap.items():
        if len(hosts) == 0:
            continue
        print("Interface {0}:\n".format(iface))
        for host in hosts:
            print(host)
            print('')
        print('')

if __name__ == '__main__':
    build_global_map()
