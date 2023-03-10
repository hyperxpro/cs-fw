//
// Copyright (C) 2023, Aayush Atharva
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

use std::io::BufRead;
use clap::Parser;
use redbpf::{load::Loader, xdp, HashMap};
use std::net::{SocketAddrV4};
use std::str::FromStr;

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

fn main() -> Result<(), String> {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let args = Args::parse();

    if unsafe { libc::geteuid() != 0 } {
        tracing::error!("You must be root to use eBPF!");
        std::process::exit(1);
    }

    let mut loaded = Loader::load(probe_code()).map_err(|err| {
        dbg!(&err);
        format!("{:?}", err)
    })?;

    let proxy = SAddrV4 {
        addr: u32::from_ne_bytes(args.proxy.ip().octets()).to_le(),
        port: (args.proxy.port() as u32).to_le(),
    };

    // Map the Server Address to the map
    HashMap::<SAddrV4, u8>::new(loaded.map("SERVERLIST")
        .expect("SERVERLIST map not found"))
        .unwrap()
        .set(proxy, 0);

    for program in loaded.xdps_mut() {
        // First priority:  HwMode
        // Second priority: DrvMode
        // Third priority:  SkbMode
        // Last priority:   Unset
        let xdp_modes = [xdp::Flags::HwMode, xdp::Flags::DrvMode, xdp::Flags::SkbMode, xdp::Flags::default()];

        // Try to attach the program to the interface
        for xdp_mode in xdp_modes {
            println!("Trying to attach XDP program on interface: {} with mode {:?}", args.interface, xdp_mode);

            let result = program.attach_xdp(&args.interface, xdp_mode);
            if result.is_ok() {
                println!("Successfully attached XDP program on interface: {} with mode {:?}", args.interface, xdp_mode);

                // exit without calling destructors so the probe is not unloaded
                std::process::exit(0);
            } else {
                println!("Failed to attach XDP program on interface: {} with mode {:?} with error: {:?}", args.interface, xdp_mode, result);
            }
        }
    }

    println!("Failed to attach XDP program on interface with Modes (HwMode, DrvMode, SkbMode and Unset): {}", args.interface);
    return Err("Error attaching XDP program".to_string());
}

// SPDX-License-Identifier: GPL-3.0
