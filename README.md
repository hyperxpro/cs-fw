# CS-FW
CS-FW is a high-performance CS 1.6 firewall based on Linux XDP.

# System Requirements
OS: Ubuntu 22.04 LTS
</br>
Architecture: x86_64
</br>
Memory: 2 GB

### Run:
```bash
$ sudo ./csfw -i eth0 -p 127.0.0.1:11011
```

### Unload
```bash
$ sudo ip link set dev eth0 xdp off
```

# Protection Channels
1. Allows CS 1.6 game packets only. It tracks traffic and maintains list of genuine clients only and discards all garbage packets.
2. Drops packets from common UDP reflectors.
```rust
    if sport ==  17 ||    // tftp
        sport == 19 ||    // chargen
        sport ==  53 ||   // dns
        sport ==  111 ||  // rpcbind
        sport ==  123 ||  // ntp
        sport ==  137 ||  // netbios-ns
        sport ==  161 ||  // snmp
        sport ==  389 ||  // ldap
        sport == 520 ||   // rip
        sport == 751 ||   // kerberos
        sport == 1434 ||  // ms-sql-s
        sport == 1900 ||  // ssdp
        sport == 5353 ||  // mdns
        sport == 6881 ||  // bittorrent
        sport == 11211 {  // memcached
        return Ok(XdpAction::Drop);
    }
```

### Building from Source:
See CI [Workflow file](https://github.com/hyperxpro/cs-fw/blob/main/.github/workflows/build.yml) for more details.
