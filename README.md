# CS-FW
CS-FW is a high-performance CS 1.6 firewall based on Linux XDP.

### Run:
```bash
$ sudo .csfw -i eth0 -p 127.0.0.1:11011
```

### Unload
```bash
# sudo ip link set dev eth0 xdp off
```

### Building from Source:
See CI [Workflow file](https://github.com/hyperxpro/cs-fw/blob/main/.github/workflows/build.yml) for more details.
