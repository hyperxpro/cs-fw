
use clap::Parser;
use redbpf::{load::Loader, xdp, HashMap};
use std::net::SocketAddrV4;

/// Attach eBPF probes to deal with DDOS
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Name of the interface to attach to
    #[clap(short, long)]
    interface: String,
    /// The address of the proxy in format IPv4:PORT
    #[clap(short, long)]
    proxy: SocketAddrV4,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SAddrV4 {
    pub addr: u32,
    pub port: u32,
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/ddos_protection/ddos_protection.elf"
    ))
}

fn main() -> std::result::Result<(), String> {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let args = Args::parse();

    if unsafe { libc::geteuid() != 0 } {
        tracing::error!("You must be root to use eBPF!");
        std::process::exit(1);
    }

    let xdp_mode = xdp::Flags::default();

    let mut loaded = Loader::load(probe_code()).map_err(|err| {
        dbg!(&err);
        format!("{:?}", err)
    })?;

    let proxy_map =
        HashMap::<SAddrV4, u8>::new(loaded.map("PROXYLIST").expect("PROXYLIST map not found")).unwrap();

    let proxy = SAddrV4 {
        addr: u32::from_ne_bytes(args.proxy.ip().octets()).to_le(),
        port: (args.proxy.port() as u32).to_le(),
    };
    proxy_map.set(proxy, /* dummy value */ 0);

    println!(
        "Attach ddos_protection on interface: {} with mode {:?}",
        args.interface, xdp_mode
    );
    for prog in loaded.xdps_mut() {
        prog.attach_xdp(&args.interface, xdp_mode)
            .map_err(|err| {
                dbg!(&err);
                format!("{:?}", err)
            })?;
    }

    // exit without calling destructors so the probe is not unloaded
    std::process::exit(0);
}
