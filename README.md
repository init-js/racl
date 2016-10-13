# racl - Router Advertisement Message Listener and Debugger

racl will send a router solicitation message on a selected interface
and wait for one or more router advertisement replies. On receipt, it
will print textual information about the packet received.

The program is written in python2, for Linux and has very few external
requirements (netifaces).

Its output will look something like this:

    # ./racl.py eth0
    ...
    2016-10-13T04:27:26.465990 ROUTER fe80::ccd3:a3ff:fe55:bbaa%eth0 M=1 O=1 Pref=0
    2016-10-13T04:27:26.465990    option src_lladdr lladdr=cc:d3:a3:55:bb:aa
    2016-10-13T04:27:26.465990    option mtu mtu=1500
    2016-10-13T04:27:26.465990    option prefix 2001:500:7000:3000::/64 A=1 L=1 valid_sec=337039 pref_sec=164239
    2016-10-13T04:27:26.465990    option prefix fd00:cafe::/64 A=1 L=1 valid_sec=4294967295 pref_sec=4294967295
    2016-10-13T04:27:26.465990    option route 2001:500:7000:3000::/56 Prf=0 lifetime=337039
    2016-10-13T04:27:26.465990    option route fd00:cafe::/48 Prf=0 lifetime=4294967295
    2016-10-13T04:27:26.465990    option rdnss address=fe80::ccd3:a3ff:fe55:bbaa%eth0 lifetime=18000
    2016-10-13T04:27:26.465990    option dnssl search_name=base,foo,bar lifetime=18000
    2016-10-13T04:27:26.465990    option adv_interval interval_ms=1800000
