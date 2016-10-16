## Router Advertisement Listener and Debugger

racl will send a router solicitation message on a selected interface
and wait for one or more router advertisement replies. On receipt, it
will print textual information about the packet received.

It was designed to work in home environments with dynamic ISP prefixes
delegated to internal hosts. racl can be used to monitor a change in prefix,
so that external services relying on fixed IPv6 addresses can be
notified/updated.

racl tries to be as system-agnostic as possible. For instance, it does
not rely on NetworkManager, dbus, or third-party packet capture libraries.

The program is written in python2.7, and has very few
non-standard package requirements (currently only netifaces).
It runs on Linux, and Windows 10.

Its output (stdout) is as follows:

    # ./racl.py eth0
    ...
    2016-10-13T04:27:26 ROUTER fe80::ccd3:a3ff:fe55:bbaa%eth0 M=1 O=1 Pref=0
    2016-10-13T04:27:26    option src_lladdr lladdr=cc:d3:a3:55:bb:aa
    2016-10-13T04:27:26    option mtu mtu=1500
    2016-10-13T04:27:26    option prefix 2001:500:7000:3000::/64 A=1 L=1 valid_sec=337039 pref_sec=164239
    2016-10-13T04:27:26    option prefix fd00:cafe::/64 A=1 L=1 valid_sec=4294967295 pref_sec=4294967295
    2016-10-13T04:27:26    option route 2001:500:7000:3000::/56 Prf=0 lifetime=337039
    2016-10-13T04:27:26    option route fd00:cafe::/48 Prf=0 lifetime=4294967295
    2016-10-13T04:27:26    option rdnss address=fe80::ccd3:a3ff:fe55:bbaa%eth0 lifetime=18000
    2016-10-13T04:27:26    option dnssl search_name=base,foo,bar lifetime=18000
    2016-10-13T04:27:26    option adv_interval interval_ms=1800000

Each RouterAdvertisement message generates a ROUTER line, providing the link-local address of the router.
The following indented lines list the options packaged in that message.
If you receive an option that is not yet supported, please open an issue.
Of interest are the `option prefix` lines, which provide available prefixes on which the hosts on the network configure their interfaces.
There are two in this example, `fd00:cafe::/48` (ULA prefix), and `2001:500:7000:3000::/48` (globally routable prefix).
By monitoring the globally routable prefix, external DNS and firewalls can be updated to make internal services reachable again.

### Windows Notes.

With admnistrator privileges, run:

    python ./racl.py {INTERFACE-GUID}

Interface names on Windows are GUIDs, so the program provides a flag `-l`, to allow listing names of the interfaces. 
The program should run forever. To stop it once it is running, one may have to press `ctrl` + `pause/break`.

_Note:_ On Windows, the program processes packets coming into _and_ out of a selected interface. This is an artifact of using `SIO_RCVALL` to access to
raw icmp packets. So, if racl runs on an interface providing a router, it will print router advertisements exiting the host.

### Linux Notes.

The program must run as root, because it needs to access raw sockets and bind to the given interface `SO_BINDTODEVICE`.

### Roadmap

  - Invoke a script when prefix changes, passing information in environment variables.
  - Distribute with pip/easy_install
  - Debianized package with init.d scripts.
  - solaris support
