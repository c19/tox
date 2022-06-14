// an example of tox proxy client with current code
//
#![recursion_limit="256"]
#![type_length_limit="4194304"]

#[macro_use]
extern crate log;

use futures::{*, future::TryFutureExt};
use futures::channel::mpsc;
use hex::FromHex;
use anyhow::Error;
use rand::{thread_rng, RngCore};

use std::net::SocketAddr;

use tox_binary_io::*;
use tox_crypto::*;
use tox_packet::dht::packed_node::PackedNode;
use tox_packet::friend_connection::*;
use tox_packet::onion::InnerOnionResponse;
use tox_packet::relay::DataPayload;
use tox_packet::toxid::ToxId;
use tox_core::dht::server::Server as DhtServer;
use tox_core::dht::server_ext::dht_run_socket;
// use tox_core::dht::lan_discovery::LanDiscoverySender;
use tox_core::udp::Server as UdpServer;
use tox_core::friend_connection::FriendConnections;
use tox_core::net_crypto::{NetCrypto, NetCryptoNewArgs};
use tox_core::onion::client::OnionClient;
use tox_core::relay::client::{Connections, IncomingPacket};
use tox_core::stats::Stats;

mod common;

// const TCP_RELAYS: [(&str, &str); 5] = [
//     // ray65536
//     ("8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832", "85.172.30.117:33445"),
//     // MAH69K
//     ("DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43", "185.25.116.107:33445"),
//     // Deliran
//     ("1C5293AEF2114717547B39DA8EA6F1E331E5E358B35F9B6B5F19317911C5F976", "84.22.115.205:33445"),
//     // kpp
//     ("A04F5FE1D006871588C8EC163676458C1EC75B20B4A147433D271E1E85DAF839", "52.53.185.100:33445"),
//     // kurnevsky
//     ("82EF82BA33445A1F91A7DB27189ECFC0C013E06E3DA71F588ED692BED625EC23", "37.139.29.40:33445"),
// ];

fn as_u16_be(array: &[u8; 2]) -> u16 {
    ((array[0] as u16) <<  8) +
    ((array[1] as u16) <<  0)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();

    let mut rng = thread_rng();

    let dht_sk = SecretKey::generate(&mut rng);
    let dht_pk = dht_sk.public_key();

    // create random tox id and print it
    let real_sk = SecretKey::generate(&mut rng);
    let real_pk = real_sk.public_key();
    let id = ToxId::new(&mut rng, real_pk.clone());
    println!("your tox id is: {:X}",id);

    // Create a channel for server to communicate with network
    let (tx, rx) = mpsc::channel(32);
    let mut port: [u8; 2] = [0; 2];
    rng.fill_bytes(&mut port);
    let ip_port = format!("0.0.0.0:{:?}", as_u16_be(&port));
    debug!("{}", ip_port);
    let local_addr: SocketAddr = ip_port.parse()?; // 0.0.0.0 for IPv4
    // let local_addr: SocketAddr = "[::]:33445".parse()?; // [::] for IPv6

    info!("Running tox proxy client on {}", local_addr);

    let socket = common::bind_socket(local_addr).await;
    let stats = Stats::new();

    // let mut lan_discovery_sender = LanDiscoverySender::new(tx.clone(), dht_pk.clone(), local_addr.is_ipv6());

    let (tcp_incoming_tx, mut tcp_incoming_rx) = mpsc::unbounded();

    let mut dht_server = DhtServer::new(tx.clone(), dht_pk.clone(), dht_sk.clone());
    dht_server.enable_lan_discovery(false);
    dht_server.enable_ipv6_mode(local_addr.is_ipv6());

    let tcp_connections = Connections::new(dht_pk.clone(), dht_sk.clone(), tcp_incoming_tx);
    let onion_client = OnionClient::new(dht_server.clone(), tcp_connections.clone(), real_sk.clone(), real_pk.clone());

    let (lossless_tx, mut lossless_rx) = mpsc::unbounded();
    let (lossy_tx, mut lossy_rx) = mpsc::unbounded();

    let (friend_request_tx, mut friend_request_sink_rx) = mpsc::unbounded();
    onion_client.set_friend_request_sink(friend_request_tx).await;

    let net_crypto = NetCrypto::new(NetCryptoNewArgs {
        udp_tx: tx,
        lossless_tx,
        lossy_tx,
        dht_pk,
        dht_sk,
        real_pk: real_pk.clone(),
        real_sk: real_sk.clone(),
        precomputed_keys: dht_server.get_precomputed_keys(),
    });

    let (net_crypto_tcp_tx, mut net_crypto_tcp_rx) = mpsc::channel(32);
    net_crypto.set_tcp_sink(net_crypto_tcp_tx).await;

    let friend_connections = FriendConnections::new(
        real_sk,
        real_pk,
        dht_server.clone(),
        tcp_connections.clone(),
        onion_client.clone(),
        net_crypto.clone(),
    );

    // Bootstrap from nodes
    for &(pk, saddr) in &common::BOOTSTRAP_NODES {
        // get PK bytes of the bootstrap node
        let bootstrap_pk_bytes: [u8; 32] = FromHex::from_hex(pk).unwrap();
        // create PK from bytes
        let bootstrap_pk = PublicKey::from(bootstrap_pk_bytes);

        let node = PackedNode::new(saddr.parse().unwrap(), bootstrap_pk);

        dht_server.add_initial_bootstrap(node.clone());
        onion_client.add_path_node(node).await;
    }

    let mut udp_server = UdpServer::new(dht_server);
    udp_server.set_net_crypto(net_crypto.clone());
    udp_server.set_onion_client(onion_client.clone());

    let net_crypto_tcp_future = async {
        while let Some((packet, pk)) = net_crypto_tcp_rx.next().await {
            tcp_connections.send_data(pk, packet).await?;
        }
        Result::<(), Error>::Ok(())
    };

    let onion_client_c = onion_client.clone();
    let net_crypto_c = net_crypto.clone();
    let tcp_incoming_future = async {
        while let Some((_relay_pk, packet)) = tcp_incoming_rx.next().await { // TODO: do we need relay_pk at all?
            match packet {
                IncomingPacket::Data(sender_pk, packet) => match packet {
                    DataPayload::CookieRequest(packet) => net_crypto_c.handle_tcp_cookie_request(&packet, sender_pk).map_err(Error::from).await,
                    DataPayload::CookieResponse(packet) => net_crypto_c.handle_tcp_cookie_response(&packet, sender_pk).map_err(Error::from).await,
                    DataPayload::CryptoHandshake(packet) => net_crypto_c.handle_tcp_crypto_handshake(&packet, sender_pk).map_err(Error::from).await,
                    DataPayload::CryptoData(packet) => net_crypto_c.handle_tcp_crypto_data(&packet, sender_pk).map_err(Error::from).await,
                },
                IncomingPacket::Oob(_sender_pk, _packet) => Ok(()),
                IncomingPacket::Onion(packet) => match packet {
                    InnerOnionResponse::OnionAnnounceResponse(packet) => onion_client_c.handle_announce_response(&packet, true).map_err(Error::from).await,
                    InnerOnionResponse::OnionDataResponse(packet) => onion_client_c.handle_data_response(&packet).map_err(Error::from).await,
                },
            }?;
        }
        Result::<(), Error>::Ok(())
    };
    let tcp_incoming_future = tcp_incoming_future.map_err(|err| {
        error!("Failed to handle packet: {:?}", err);
        err
    });

    let net_crypto_c = net_crypto.clone();
    let friend_connections_c = friend_connections.clone();
    let lossless_future = async {
        while let Some((pk, packet)) = lossless_rx.next().await {
            match packet[0] {
                PACKET_ID_ALIVE => {
                    friend_connections_c.handle_ping(pk).await;
                },
                PACKET_ID_SHARE_RELAYS => {
                    match ShareRelays::from_bytes(&packet) {
                        Ok((_, share_relays)) =>
                            friend_connections_c.handle_share_relays(pk, share_relays)
                                .map_err(Error::from).await?,
                        _ => return Err(Error::msg("Failed to parse ShareRelays"))
                    }
                },
                0x18 => { // PACKET_ID_ONLINE
                    net_crypto_c.send_lossless(pk.clone(), vec![0x18]).map_err(Error::from).await?;
                    net_crypto_c.send_lossless(pk.clone(), vec![0x32, 0x00]).map_err(Error::from).await?; // PACKET_ID_USERSTATUS
                    net_crypto_c.send_lossless(pk, b"\x30tox-rs".to_vec()).map_err(Error::from).await?;
                },
                0x40 => { // PACKET_ID_CHAT_MESSAGE
                    net_crypto_c.send_lossless(pk, packet).map_err(Error::from).await?;
                },
                _ => { },
            }
        }
        Result::<(), Error>::Ok(())
    };

    // handle incoming friend connections by just accepting all of them
    let friend_connection_c = friend_connections.clone();
    let friend_future = async {
        while let Some((pk, _)) = friend_request_sink_rx.next().await {
            friend_connection_c.add_friend(pk).await;
        }
        Result::<(), Error>::Ok(())
    };

    let lossy_future = async {
        while lossy_rx.next().await.is_some() {
            // ignore
        }
        Result::<(), Error>::Ok(())
    };

    // Add TCP relays
    // for &(pk, saddr) in TCP_RELAYS.iter() {
    //     // get PK bytes of the relay
    //     let relay_pk_bytes: [u8; 32] = FromHex::from_hex(pk).unwrap();
    //     // create PK from bytes
    //     let relay_pk = PublicKey::from(relay_pk_bytes);

    //     tcp_connections.add_relay_global(saddr.parse().unwrap(), relay_pk).await.map_err(Error::from)?;
    // }

    futures::select!(
        res = dht_run_socket(&udp_server, socket, rx, stats).fuse() => res.map_err(Error::from),
        // res = lan_discovery_sender.run().fuse() => res.map_err(Error::from),
        res = tcp_connections.run().fuse() => res.map_err(Error::from),
        res = onion_client.run().fuse() => res.map_err(Error::from),
        res = net_crypto.run().fuse() => res.map_err(Error::from),
        res = friend_connections.run().fuse() => res.map_err(Error::from),
        res = net_crypto_tcp_future.fuse() => res,
        res = tcp_incoming_future.fuse() => res,
        res = lossless_future.fuse() => res,
        res = lossy_future.fuse() => res,
        res = friend_future.fuse() => res,
    )
}
