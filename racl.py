#!/usr/bin/env python2
import socket
import scapy.all as A


ifname = "he-ipv6"

#linkaddr = A.get_if_hwaddr("he-ipv6")
linkaddr = A.get_if_hwaddr("eno1")
source_ip = "::"
source_ip = "fe80::c6a2:34d6%he-ipv6" #he-ipv6

def bound_socket(*a, **k):
    sock = socket.socket(*a, **k)
    if socket.AF_INET6 in a:
        if not socket.has_ipv6:
            raise ValueError("There's no support for IPV6!")
        else:
            address = [addr for addr in socket.getaddrinfo(source_ip, None)
                       if socket.AF_INET6 == addr[0]] # You ussually want the first one.
            if not address:
                raise ValueError("Couldn't find ipv6 address for source %s" % source_ip)
            sock.bind(address[0][-1])
    else:
        sock.bind((source_ip, 0))
    return sock

rawsock = bound_socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
#rawsock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
#socket.SO_BINDTODEVICE = 25
#rawsock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname + '\0')

rawsock.setblocking(0)
#rawsock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

pkt = A.IPv6(src="::", dst="ff02::2")/A.ICMPv6ND_RS() #/A.ICMPv6NDOptSrcLLAddr(lladdr=linkaddr)
rawsock.sendto(pkt.build(), ("ff02::2", 0))
