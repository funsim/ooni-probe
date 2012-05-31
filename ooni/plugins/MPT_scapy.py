import os,time,struct,re,socket,new
from scapy.all import *

### Create a new packet list
class MultiTracerouteResult(TracerouteResult):

    def get_trace(self):
        trace = {}
        for s,r in self.res:
            if IP not in s:
                continue
            d = s[IP].dst
            if d not in trace:
                trace[d] = {}
            # Mark non ICMP packages and ICMP packages that are of type echo-request or port-unreachable
            trace[d][s[IP].ttl] = r[IP].src, ICMP not in r or r[ICMP].type == 0 or r[ICMP].type == 333 
        for k in trace.values():
            m = filter(lambda x:k[x][1], k.keys())
            if not m:
                continue
            m = min(m)
            for l in k.keys():
                if l > m:
                    del(k[l])
        return trace

@conf.commands.register
def traceroute(target, dport=80, minttl=1, maxttl=30, sport=RandShort(), l4 = None, filter=None, timeout=2, verbose=None, protocol = TCP, **kargs):
    """Instant TCP traceroute
traceroute(target, [maxttl=30,] [dport=80,] [sport=80,] [verbose=conf.verb]) -> None
"""
    if verbose is None:
        verbose = conf.verb
    if filter is None:
        if protocol == TCP:
            # we only consider ICMP error packets and TCP packets with at
            # least the ACK flag set *and* either the SYN or the RST flag
            # set
            filter="(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12)) or (tcp and (tcp[13] & 0x16 > 0x10))"
        elif protocol == UDP:
            # we only consider ICMP error packets and UDP packets 
            filter="(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12)) or udp"
        elif protocol == ICMP:
            # we only consider ICMP error packets and echo-replies
            filter="icmp and (icmp[0]=0 or icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12)"
        else:
            raise ValueError, 'Unkown protocol'

    if l4 is None:
        if protocol == TCP:
            a,b = sr(IP(dst=target, id=RandShort(), ttl=(minttl,maxttl))/protocol(seq=RandInt(),sport=sport, dport=dport),
                     timeout=timeout, filter=filter, verbose=verbose, **kargs)
        elif protocol == UDP:
            a,b = sr(IP(dst=target, id=RandShort(), ttl=(minttl,maxttl))/protocol(sport=sport, dport=dport),
                     timeout=timeout, filter=filter, verbose=verbose, **kargs)
        elif protocol == ICMP:
            a,b = sr(IP(dst=target, id=RandShort(), ttl=(minttl,maxttl))/protocol(),
                     timeout=timeout, filter=filter, verbose=verbose, **kargs)
    else:
        # this should always work
        filter="ip"
        a,b = sr(IP(dst=target, id=RandShort(), ttl=(minttl,maxttl))/l4,
                 timeout=timeout, filter=filter, verbose=verbose, **kargs)

    a = TracerouteResult(a.res)
    if verbose:
        a.show()
    return a,b

