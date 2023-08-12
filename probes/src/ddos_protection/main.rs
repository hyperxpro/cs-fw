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

#![no_std]
#![no_main]

use redbpf_probes::maps::{HashMap, LruHashMap};
use redbpf_probes::net::Transport;
use redbpf_probes::xdp::prelude::*;

use probes::ddos_protection::SAddrV4;

program!(0xFFFFFFFE, "GPL");

type Ipv4Addr = u32;
type DummyValue = u8;

const fn starts_with<const N: usize>(s: &[u8], needle: [u8; N]) -> bool {
    if s.len() < N {
        return false;
    }

    let mut i = 0;
    while i < N {
        if s[i] != needle[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[map]
static mut SERVERLIST: HashMap<SAddrV4, DummyValue> = HashMap::with_max_entries(256);

#[map]
static mut WHITELIST: LruHashMap<Ipv4Addr, DummyValue> = LruHashMap::with_max_entries(10_00_000);

#[map]
static mut TEMPLIST: LruHashMap<Ipv4Addr, DummyValue> = LruHashMap::with_max_entries(10_000_000);

pub static STEAM_PACKET_START: [u8; 4] = *b"\xff\xff\xff\xff";
pub static PACKET1_START:      [u8; 6] = *b"\xff\xff\xff\xff\x67\x65";
pub static PACKET2_START:      [u8; 9] = *b"\xff\xff\xff\xff\x63\x6f\x6e\x6e\x65";

#[xdp]
pub unsafe fn filter(ctx: XdpContext) -> XdpResult {
    let iph = if let Some(iph) = ctx.ip()?.as_ref() {
        iph
    } else {
        // Not an IP packet. Pass it on.
        return Ok(XdpAction::Pass);
    };

    // We only care about IPv4 packets. We will pass IPv6 packets seamlessly.
    if iph.version() != 4 {
        return Ok(XdpAction::Pass);
    }

    let source_address = iph.saddr;
    let destination_address = iph.daddr;

    drop(iph);

    let transport = ctx.transport()?;

    // We only care about UDP packets. We will pass TCP packets seamlessly.
    if let Transport::TCP(_) = transport {
        return Ok(XdpAction::Pass);
    };

    let sport = transport.source();
    let dport = transport.dest();

    drop(transport);

    let source_socket_address = SAddrV4 { addr: source_address, port: sport as u32 };
    let destination_socket_address = SAddrV4 { addr: destination_address, port: dport as u32 };

    // If packet is going from server to client, we will pass it.
    // If packet is not destined to a server, we will pass it.
    if SERVERLIST.get(&source_socket_address).is_some() || SERVERLIST.get(&destination_socket_address).is_none() {
        return Ok(XdpAction::Pass);
    }

    // Drop common UDP amplification source ports
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

    let data = ctx.data()?;
    let payload_len = data.len();

    if payload_len < (STEAM_PACKET_START.len() + 1) {
        return Ok(XdpAction::Drop);
    }

    let payload = data.slice(STEAM_PACKET_START.len() + 1)?;
    let is_steam_packet = starts_with(payload, STEAM_PACKET_START);

    if is_steam_packet {
        let is_query_request_packet = match payload[4] {
            0x54 => true, // A2S_INFO_REQUEST
            0x56 => true, // A2S_RULES_REQUEST
            0x55 => true, // A2S_PLAYERS_REQUEST
            _ => false,
        };

        // A2S_RESPONSES ATTACK
        let is_illegitimate_request_packet = match payload[4] {
            0x49 => true, // A2S_INFO_RESPONSE
            0x45 => true, // A2S_RULES_RESPONSE
            0x44 => true, // A2S_PLAYERS_RESPONSE
            0x6d => true, // CSGO_UNKNOWN1_RESPONSE
            0x4c => true, // YOU_ARE_BANNED_RESPONSE
            _ => false,
        };

        if is_query_request_packet {
            return Ok(XdpAction::Pass);
        } else if is_illegitimate_request_packet {
            return Ok(XdpAction::Drop);
        }
    }

    if WHITELIST.get(&source_address).is_some() {
        return Ok(XdpAction::Pass);
    }

    if payload_len < PACKET1_START.len() {
        return Ok(XdpAction::Drop);
    }

    let payload = data.slice(PACKET1_START.len())?;
    let is_packet1 = starts_with(payload, PACKET1_START);

    if is_packet1 {
        return if TEMPLIST.get(&source_address).is_none() {
            TEMPLIST.set(&source_address, &0);
            Ok(XdpAction::Pass)
        } else {
            Ok(XdpAction::Drop)
        }
    }

    if payload_len < PACKET2_START.len() {
        return Ok(XdpAction::Drop);
    }

    let payload = data.slice(PACKET2_START.len())?;
    let is_packet2 = starts_with(payload, PACKET2_START);

    if is_packet2 {
        return if TEMPLIST.get(&source_address).is_some() {
            TEMPLIST.delete(&source_address);
            WHITELIST.set(&source_address, &0);
            Ok(XdpAction::Pass)
        } else {
            Ok(XdpAction::Drop)
        }
    }

    return Ok(XdpAction::Drop);
}

// SPDX-License-Identifier: GPL-3.0
