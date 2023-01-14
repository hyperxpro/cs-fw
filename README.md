# Deps:

* LLVM 14 (llvm-config --version should print 14.y.z)
* cargo install cargo-bpf --git https://github.com/foniod/redbpf.git

# Build probe:

```bash
$ cd probes
$ cargo b
/probes$ cargo bpf build --target-dir=../target

```

# Run it:

```bash
sbpf$ cargo b && sudo ./target/debug/csfw -i lo -p 127.0.0.1:11011
```

# Unload

```bash
# ip link set dev lo xdp off
```
