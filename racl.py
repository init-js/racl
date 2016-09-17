#!/usr/bin/env python2

"""racl.py

  Solicit a router and listen for Router Advertisement (RA) messages.

"""

import socket
import datetime
import scapy.all as A
import netifaces


def get_if_macaddr(iface):
    """ returns macaddr of interface or None.
        raises ValueError if no such interface
    """
    addrs = netifaces.ifaddresses(iface) # pylint: disable=no-member
    return addrs.get(socket.AF_PACKET, [{"addr":None}])[0]["addr"]

def get_link_local_v6(iface):
    """ returns a link local ipv6 for interface iface, or None.
        raises ValueError if no such interface
    """
    addrs = netifaces.ifaddresses(iface) # pylint: disable=no-member
    link_locals = [x['addr'] for x in addrs.get(socket.AF_INET6, [])
                   if x.get('addr', "").startswith("fe80::")]
    return link_locals[0] if link_locals else None

def get_addrinfo(ipstr):
    """ get the internet address from the given string """
    bind_addr = [addr for addr in socket.getaddrinfo(ipstr, None, socket.AF_INET6)]
    if not bind_addr:
        raise ValueError("couldn't find ipv6 address for ip %s" % (ipstr,))
    return bind_addr

def scopeless(ipstr):
    """ remove link-local scope id from ipv6 addr string (if any)"""
    idx = ipstr.find("%")
    if idx == -1:
        return ipstr
    else:
        return ipstr[:idx]

def _bind_socket(sock, addr6="::", ifname=""):
    """bind given socket to ipv6 addr (string), and/or to given interface"""

    if ifname:
        # bind socket to interface
        #socket.SO_BINDTODEVICE = 25
        sock.setsockopt(socket.SOL_SOCKET, 25, ifname[:16] + '\0')

    # bind socket to address
    bind_addr = get_addrinfo(addr6)
    sock.bind(bind_addr[0][-1])

def send_rs(opts):
    """send a router solicitation message"""

    # valid interface
    if not opts.interface in netifaces.interfaces(): #pylint: disable=no-member
        raise ValueError("invalid interface name '%s'" % (
            opts.interface,))

    # valid router
    get_addrinfo(opts.router)

    if not opts.use_unspecified_src:
        # bind to link-local ipv6 address on interface
        src_ip6addr = get_link_local_v6(opts.interface)
        if not src_ip6addr:
            raise ValueError("interface '%s' has no ipv6 link-local address" % (opts.interface))
    else:
        # any ip on the interface
        src_ip6addr = "::"

    # We need IPPROTO_RAW to be able to override the source address
    # field, and set hops to 255. This is a send-only socket
    # however. The receive path needs to create its own.
    sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)

    sock.setblocking(0)
    _bind_socket(sock, src_ip6addr, opts.interface)

    pkt = A.IPv6(src=scopeless(src_ip6addr), dst=opts.router)/A.ICMPv6ND_RS() #pylint: disable=no-member

    if not opts.use_unspecified_src:
        # when the source IPv6 is not '::', RFC4861 requires a
        # source link local address option to be added.
        src_link_addr = get_if_macaddr(opts.interface)
        if not src_link_addr:
            raise ValueError("interface '%s' requires a mac address" % (opts.interface,))

        pkt = pkt / A.ICMPv6NDOptSrcLLAddr(lladdr=src_link_addr) #pylint: disable=no-member

    sock.sendto(pkt.build(), (opts.router, 0))
    sock.close()

def recv_ra(opts):
    """listen for router advertisement messages"""

    sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.getprotobyname("ipv6-icmp"))

    if not opts.use_unspecified_src:
        # bind to link-local ipv6 address on interface
        src_ip6addr = get_link_local_v6(opts.interface)
        if not src_ip6addr:
            raise ValueError("interface '%s' has no ipv6 link-local address" % (opts.interface))
    else:
        # any ip on the interface
        src_ip6addr = "::"

    _bind_socket(sock, src_ip6addr, opts.interface)

    while True:
        data, addr = sock.recvfrom(1024)
        peer_ipv6 = addr[0]

        # parse
        pkt = A.ICMPv6Unknown(data) #pylint: disable=no-member
        if pkt.type == 134: # router advertisement
            pkt = A.ICMPv6ND_RA(data) #pylint: disable=no-member
            tstamp = datetime.datetime.utcnow().isoformat()
            print "%(ts)s ROUTER %(peer)s M=%(M)s O=%(O)s" % {
                "ts": tstamp,
                "peer": peer_ipv6,
                "M": pkt.M, "O": pkt.O}
            opt = pkt.payload
            while opt:
                if opt.type == 3: # Prefix Information
                    prefix = opt.prefix
                    prefix_len = opt.prefixlen
                    is_on_link = opt.L
                    is_auto = opt.A
                    # seconds that prefix is valid for purposes of
                    # on-link determination.  0xffffffff is infinity.
                    valid_sec = opt.validlifetime
                    # seconds that slaac addresses on prefix should be
                    # considered preferred.
                    pref_sec = opt.preferredlifetime
                    print ("%(ts)s %(prefix)s/%(prefix_len)s is_Auto=%(is_auto)s "
                           "on_Link=%(on_link)s valid_sec=%(valid_sec)s pref_sec=%(pref_sec)s") % {
                               "ts": tstamp,
                               "prefix": prefix, "prefix_len": prefix_len,
                               "is_auto": is_auto, "on_link": is_on_link,
                               "valid_sec": valid_sec, "pref_sec": pref_sec
                           }
                opt = opt.payload

def main():
    """command line entry point"""
    import argparse

    if not socket.has_ipv6:
        raise ValueError("There's no support for IPV6!")

    parser = argparse.ArgumentParser(description="Solicits routers to discover available IPv6 networks.")
    parser.add_argument('interface', action="store",
                        help="the interface from which to send the solicitation")
    parser.add_argument('-r', action="store", dest="router",
                        help="router address to solicit (specify if known)", default="ff02::2")
    parser.add_argument('-u', action="store_true", dest="use_unspecified_src", default=False,
                        help="uses :: as the ipv6 source")
    opts = parser.parse_args()

    send_rs(opts)
    recv_ra(opts)
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
