#!/usr/bin/env python2
 #
 #    racl: Listener and debugger for ICMPv6 Router Advertisements
 #    Copyright (C) 2016  Jean-Sebastien Legare <jslegare@j12n.ca>
 #
 #    This file is part of racl.
 #
 #    racl is free software: you can redistribute it and/or modify
 #    it under the terms of the GNU General Public License as published by
 #    the Free Software Foundation, either version 3 of the License, or
 #    (at your option) any later version.
 #
 #    racl is distributed in the hope that it will be useful,
 #    but WITHOUT ANY WARRANTY; without even the implied warranty of
 #    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 #    GNU General Public License for more details.
 #
 #    You should have received a copy of the GNU General Public License
 #    along with racl.  If not, see <http://www.gnu.org/licenses/>.
 #

"""racl.py

  Solicit a router and listen for Router Advertisement (RA) messages.

"""

import socket
import datetime
import struct
import re
import netifaces

VERSION = "0.1.0"

IP_ICMPV6 = 58
ICMPV6_ND_RS = 133
ICMPV6_ND_RA = 134
ICMPV6_ND_RS_CODE = 0
ICMPV6_ND_SRC_LLADDR = 1


class StructMeta(type):
    """A metaclass for classes defined based on structs

     classes are expected to have a member called FMT which is a
     struct (as struct.pack(fmt)) template where every field is
     preceded with a name.

     The metaclass adds each name to the __slots__, and defines

       cls._struct: a struct.Struct definition for FMT,
       cls._tuple:  the name of each field, in order
    """
    def __new__(mcs, name, parents, dct):
        if not 'FMT' in dct:
            raise ValueError("FMT key missing in class: " + name)

        fmt = dct.get('FMT')

        #!{_foo}B{bar}I -> !BI
        clean = "".join(re.split(r"\{[a-zA-Z_][a-zA-Z0-9_:-]*\}", fmt))
        fields = re.findall(r"\{[a-zA-Z_][a-zA-Z0-9_:-]*\}\d*[a-zA-Z]", fmt)

        #!{_foo:M:O}B{bar}I -> [ _foo:M:O, bar ]
        field_specs = [re.match(r"\{([^}]+)\}", field).group(1)  for field in fields]

        new_fields = []
        # split bitfield "_flags:1M:1O:-6Res1" -> [_flags, 1M, 1O, 6Res1]
        for spec in field_specs:
            bitfields = spec.split(":")
            if len(bitfields) > 1:
                try:
                    props = mcs.bitfield_properties(bitfields[0], bitfields[1:])
                    for propname, prop in props:
                        dct[propname] = prop
                except ValueError:
                    raise ValueError("Error parsing field %s.%s" % (name, bitfields[0]))

            new_fields.append(bitfields[0])

        dct["__slots__"] = dct.setdefault("__slots__", ()) + tuple(new_fields)
        dct["_struct"] = struct.Struct(clean)
        dct["_tuple"] = new_fields
        return super(StructMeta, mcs).__new__(mcs, name, parents, dct)

    @classmethod
    def bitfield_properties(mcs, byte_name, specs):
        'defines a series of getters based on a bitfield'
        def make_bin_getter(flag_field, start, count, is_signed):
            'getter for bits [start, start+count] of field flag_field'
            mask = (0xff >> start) - (0xff >> (start + count))
            def _get_flag(self):
                bits = getattr(self, flag_field) & mask
                signbit = (bits & (0x80 >> start)) and is_signed
                bits = bits >> (8-(start + count))
                return bits if not signbit else bits - (1 << count)
            return property(_get_flag)

        offset = 0
        props = []
        for spec in specs:
            bitlen = 1
            signed = False
            if spec[0] == "-":
                signed = True
                spec = spec[1:]
            if spec[0] in "0123456789":
                bitlen = int(spec[0], 10)
                if offset + bitlen > 8 or bitlen < 1:
                    raise ValueError("bad field length")
                spec = spec[1:]
            if spec:
                props.append((spec, make_bin_getter(byte_name, offset, bitlen, signed)))
            offset += bitlen
        return props

class Struct(object):
    'parseable object from a data string'
    __metaclass__ = StructMeta
    FMT = ""
    __slots__ = ("_struct", "_tuple")

    class NotEnough(Exception):
        'catch cases where not enough data is passed'

    # pylint: disable-msg=no-member
    def __init__(self, data):
        if len(data) < self._struct.size:
            raise Struct.NotEnough("Not enough data to parse " + self.__class__.__name__)

        values = self._struct.unpack_from(data)
        for (i, value) in enumerate(values):
            setattr(self, self._tuple[i], value)
        super(Struct, self).__init__()

    def __len__(self):
        """length of struct in bytes"""
        return self._struct.size

    @classmethod
    def parse(cls, data):
        """reads data from the stream as if it was a message of that type,
        returns (parsed_object, rest_of_data)
        parsed_object is None if there isn't enough data
        """
        try:
            struct_obj = cls(data)
            return struct_obj, data[len(struct_obj):]
        except Struct.NotEnough:
            return None, data

class OptRA(Struct):
    'Common Option Header'
    TYPE = -1
    FMT = ("!"
           '{type}B'
           '{length}B')
    #pylint: disable-msg=no-member

    def __len__(self):
        return self.length*8

class OptAdIval(OptRA):
    'Advertisement Interval'
    FMT = (OptRA.FMT +
           '{reserved}H'
           '{interval_ms}I')
    TYPE = 7

class OptRouteInfo(OptRA):
    'Route Information'
    FMT = (OptRA.FMT +
           '{prefixlen}B{flags:3Res1:-2Prf:3Res2}B'
           '{lifetime}I')
    TYPE = 24
    __slots__ = ('prefix',)

    #pylint: disable-msg=no-member
    def __init__(self, data):
        super(OptRouteInfo, self).__init__(data)
        prefix_bytes = (self.length - 1) * 8
        self.prefix = data[8:8+prefix_bytes]
        self.prefix += "\x00" * (16-len(self.prefix))

class RecursiveDNS(OptRA):
    'Recursive DNS Servers'
    FMT = (OptRA.FMT +
           '{reserved}H'
           '{lifetime}I') # rel max time, in sec, the server may be used. 0xffffffff is infinity
    TYPE = 25
    __slots__ = ('addresses',)

    #pylint: disable-msg=no-member
    def __init__(self, data):
        super(RecursiveDNS, self).__init__(data)
        num_addresses = (self.length - 1) / 2
        self.addresses = [data[i+8:i+24] for i in range(0, num_addresses)]

class DNSSearch(Struct):
    'DNS Search List'
    FMT = (OptRA.FMT +
           '{reserved}H'
           '{lifetime}I')
    TYPE = 31
    __slots__ = ('domain_names',)

    #pylint: disable-msg:no-member
    def __init__(self, data):
        super(DNSSearch, self).__init__(data)
        self.domain_names = data[8:len(self)-8]
        first_nul = self.domain_names.find("\x00")
        if first_nul > -1:
            # remove padding
            self.domain_names = self.domain_names[:first_nul]

class OptMTU(Struct):
    'MTU Option'
    FMT = (OptRA.FMT +
           "{reserved}H"
           "{mtu}I")
    TYPE = 5

class OptSrcLLA(Struct):
    'SrcLinkLayerAddress'
    FMT = (OptRA.FMT +
           '{_mac}6s') # mac)
    TYPE = 1

    @property
    def mac(self):
        'get mac address string'
        return ll_from_b(self._mac) #pylint: disable-msg=no-member


class OptPrefixInfo(Struct):
    'Prefix Information'
    FMT = (OptRA.FMT +
           '{prefixlen}B'
           '{flags:L:A:R}B'  #on link, autoconf, router address
           '{valid_sec}I'
           '{pref_sec}I'
           '{reserved2}I'
           '{_prefix}16s')
    TYPE = 3

    @property
    def prefix(self):
        'get ipv6 string'
        return ipv6_from_b(self._prefix) #pylint: disable-msg=no-member

RA_OPTS = {
    OptAdIval.TYPE: OptAdIval,
    OptRouteInfo.TYPE: OptRouteInfo,
    RecursiveDNS.TYPE: RecursiveDNS,
    DNSSearch.TYPE: DNSSearch,
    OptMTU.TYPE: OptMTU,
    OptSrcLLA.TYPE: OptSrcLLA,
    OptPrefixInfo.TYPE: OptPrefixInfo
}

class RouterAdvertisement(Struct):
    """class containing fields of a router advertisement message"""
    FMT = ('!'
           '{type}B{code}B{checksum}H'
           '{hop_limit}B{flags:M:O:H:-2Prf:Proxy}B{lifetime}H'
           '{reach_sec}I'
           '{retrans_sec}I')  # Retransmission time

def ll_from_b(b6):
    "converts a byte string into mac address string"
    if len(b6) < 6:
        b6 += "\x00" * 6 - len(b6)
    return ":".join(["%02x" % ord(c) for c in b6[:6]])

def ipv6_from_b(b16):
    """converts a 16 byte string into an ipv6 text address.
       Follows RFC5952.
    """
    if len(b16) < 16:
        b16 += "\x00" * (16 - len(b16))
    return socket.inet_ntop(socket.AF_INET6, b16[:16])

def ll_to_b(lladdr):
    """converts a mac address string to a 6b binary string
    >>> for example in ("03:1f:bc:8:c:a",):
    ...     print "".join([ "%02x" % ord(octet) for octet in ll_to_b(example)])
    031fbc080c0a
    """
    octets = lladdr.split(":")
    return "".join([chr(int(octet_s, 16)) for octet_s in octets])

def ipv6_to_b(ipv6):
    """transforms a valid ipv6 address string into a 16b string

    >>> for example in ("cafe::2","fe80:132:12:1::0321:0021:8", "a::", "::", "::fa"):
    ...     print "".join([ "%02x" % ord(octet) for octet in ipv6_to_b(example)])
    cafe0000000000000000000000000002
    fe800132001200010000032100210008
    000a0000000000000000000000000000
    000000000000000000000000000000fa
    """
    return socket.inet_pton(socket.AF_INET6, ipv6)

def ip_checksum(buf):
    """computes the ip checksum over the given buffer"""
    #https://tools.ietf.org/html/rfc1071
    evens = 0
    odds = 0

    # python integers don't overflow.

    for i in range(0, len(buf), 2):
        evens += ord(buf[i])
        odds += ord(buf[i+1])

    if len(buf) % 2 == 1:
        evens += ord(buf[-1])
        # odds += 0

    csum = (evens * 256) + odds

    # add carry
    while csum > 0xffff:
        csum = (csum & 0xffff) + (csum >> 16)

    return (~csum) & 0xffff

def create_rs_packet(src, dst, lladdr=None):
    """src, dst are ip addresses
       lladdr is a src link layer address to add as an icmp option
    """
    def _icmp_header(csum):
        return struct.pack(
            '!'
            'BBH' #type, code, checksum
            'i',   #reserved (4B)
            ICMPV6_ND_RS, ICMPV6_ND_RS_CODE, csum,
            0)

    src = ipv6_to_b(scopeless(src))
    dst = ipv6_to_b(scopeless(dst))

    if lladdr:
        lladdr_opt = struct.pack(
            '!'
            'BB'  #opt type, len (mult of 8b)
            '6s', #src mac address
            ICMPV6_ND_SRC_LLADDR, 1,
            ll_to_b(lladdr))
    else:
        lladdr_opt = ''

    icmp_header = _icmp_header(0)

    pseudo_header = struct.pack(
        '!'
        '16s' # src
        '16s' # dst
        'I'  # icmpv6 len
        'bbbb', # 3B zeros
        src, dst, len(icmp_header) + len(lladdr_opt),
        0, 0, 0, IP_ICMPV6)

    csum = ip_checksum(pseudo_header + icmp_header + lladdr_opt)

    icmp_header = _icmp_header(csum)

    ip_header = struct.pack(
        '!'
        'BBBB' # version (bit 0-3), traffic class (bit 4-11), flow label (12-31)
        'HBB' # payload length, next header, hop limit
        '16s'  # src address
        '16s', # dst address
        0x60, 0, 0, 0,
        len(icmp_header) + len(lladdr_opt), IP_ICMPV6, 255,
        src,
        dst
    )
    return ip_header + icmp_header + lladdr_opt

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

    # We need IPPROTO_RAW (and not the level below i.e. ICMPV6 RAW) to be
    # able to override the source address field and set hops to
    # 255. One cannot receive packets on an IPPROTO_RAW socket
    # (i.e. send-only). RA messages will have to come in on a
    # different socket.
    sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)

    sock.setblocking(0)
    _bind_socket(sock, src_ip6addr, opts.interface)

    src_link_addr = None
    if not opts.use_unspecified_src:
        # when the source IPv6 is not '::', RFC4861 requires a
        # source link local address option to be added.
        src_link_addr = get_if_macaddr(opts.interface)
        if not src_link_addr:
            raise ValueError("interface '%s' requires a mac address" % (opts.interface,))

    rs_packet = create_rs_packet(src=src_ip6addr,
                                 dst=opts.router,
                                 lladdr=src_link_addr)

    sock.sendto(rs_packet, (opts.router, 0))
    sock.close()

def recv_ra(opts):
    """listen for router advertisement messages"""

    #pylint: disable-msg=no-member

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
        # data[0] is the first byte of an IPV6 packet
        data, addr = sock.recvfrom(1024)
        peer_ipv6 = addr[0]

        ra_msg, data = RouterAdvertisement.parse(data)

        if ra_msg.type != ICMPV6_ND_RA:
            continue

        tstamp = datetime.datetime.utcnow().isoformat()
        print "%(ts)s ROUTER %(peer)s M=%(M)s O=%(O)s Pref=%(Prf)s" % {
            "ts": tstamp,
            "peer": peer_ipv6,
            "M": ra_msg.M, "O": ra_msg.O, 'Prf': ra_msg.Prf
        }

        while data:
            opt, data_after = OptRA.parse(data)
            if not opt:
                break

            # RA_OPTS = {
            #     OptAdIval.TYPE: OptAdIval,
            #     OptRouteInfo.TYPE: OptRouteInfo,
            #     RecursiveDNS.TYPE: RecursiveDNS,
            #     DNSSearch.TYPE: DNSSearch,
            #     OptMTU.TYPE: OptMTU,
            #     OptSrcLLA.TYPE: OptSrcLLA,
            #     OptPrefixInfo.TYPE: OptPrefixInfo
            # }

            if opt.type == 3: # Prefix Information
                opt, data = OptPrefixInfo.parse(data)
                print ("%(ts)s %(prefix)s/%(prefixlen)s A=%(A)s "
                       "L=%(L)s valid_sec=%(valid_sec)s pref_sec=%(pref_sec)s") % {
                           "ts": tstamp,
                           "prefix": opt.prefix, "prefixlen": opt.prefixlen,
                           "A": opt.A, "L": opt.L,
                           "valid_sec": opt.valid_sec, "pref_sec": opt.pref_sec
                       }
            else:
                # go to next opt
                data = data_after

def main():
    """command line entry point"""
    import argparse

    if not socket.has_ipv6:
        raise ValueError("There's no support for IPV6!")

    parser = argparse.ArgumentParser(description="Solicits routers to discover available IPv6 networks. "
                                     "(Version %s)" % VERSION)
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
