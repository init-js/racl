#!/usr/bin/env python2
import socket
import scapy.all as A


ifname = "he-ipv6"

#linkaddr = A.get_if_hwaddr("he-ipv6")
linkaddr = A.get_if_hwaddr("eno1")
source_ip = "::"
#source_ip = "fe80::c6a2:34d6%he-ipv6" #he-ipv6

if not socket.has_ipv6:
    raise ValueError("There's no support for IPV6!")


def bound_socket(*a, **k):
    sock = socket.socket(*a, **k)
    address = [addr for addr in socket.getaddrinfo(source_ip, None)
               if socket.AF_INET6 == addr[0]] # You ussually want the first one.
    if not address:
        raise ValueError("Couldn't find ipv6 address for source %s" % source_ip)

    #socket.SO_BINDTODEVICE = 25
    sock.setsockopt(socket.SOL_SOCKET, 25, ifname + '\0')
    sock.bind(address[0][-1])
    return sock

rawsock = bound_socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)

rawsock.setblocking(0)
#rawsock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

pkt = A.IPv6(dst="ff02::2")/A.ICMPv6ND_RS() #/A.ICMPv6NDOptSrcLLAddr(lladdr=linkaddr)
rawsock.sendto(pkt.build(), ("ff02::2", 0))
