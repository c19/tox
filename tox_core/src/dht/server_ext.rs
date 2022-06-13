//! Extension trait for running DHT server on `UdpSocket`

use std::io::{Error, ErrorKind};
use std::net::{SocketAddr, IpAddr};

use futures::{FutureExt, SinkExt, StreamExt};
use futures::channel::mpsc::Receiver;
use tokio::net::UdpSocket;

use crate::dht::codec::*;
use tox_packet::dht::Packet;
use crate::udp::Server;
use crate::stats::Stats;

/// Run DHT server on `UdpSocket`.
pub async fn dht_run_socket(
    udp: &Server,
    socket: UdpSocket,
    mut rx: Receiver<(Packet, SocketAddr)>,
    stats: Stats
) -> Result<(), Error> {
    let udp_addr = socket.local_addr()
        .expect("Failed to get socket address");

    let codec = DhtCodec::new(stats);
    let (mut sink, mut stream) =
        tokio_util::udp::UdpFramed::new(socket, codec).split();

    let network_reader = async {
        while let Some(event) = stream.next().await {
            match event {
                Ok((packet, addr)) => {
                    debug!("Received packet {} <= {:?}", packet.to_string(), addr);
                    trace!("Received packet from {:?} {:?}", addr, packet);
                    let res = udp.handle_packet(packet, addr).await;

                    if let Err(ref err) = res {
                        error!("Failed to handle packet: {:?}", err);
                    }
                },
                Err(e) => {
                    error!("packet receive error = {:?}", e);
                    // ignore packet decode errors
                    if let DecodeError::Io(e) = e {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    };

    let network_writer = async {
        while let Some((packet, mut addr)) = rx.next().await {
            // filter out IPv6 packets if node is running in IPv4 mode
            if udp_addr.is_ipv4() && addr.is_ipv6() { continue }

            if udp_addr.is_ipv6() {
                if let IpAddr::V4(ip) = addr.ip() {
                    addr = SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), addr.port());
                }
            }
            debug!("Send {} => {:?}", packet.to_string(), addr);
            trace!("Sending packet {:?} to {:?}", packet, addr);
            sink.send((packet, addr)).await
                .map_err(|e| Error::new(ErrorKind::Other, e))?
        }

        Ok(())
    };

    futures::select! {
        read = network_reader.fuse() => read,
        write = network_writer.fuse() => write,
        run = udp.dht.run().fuse() => { // TODO: should we run it here?
            let res: Result<_, _> = run;
            res.map_err(|e| Error::new(ErrorKind::Other, e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crypto_box::{SalsaBox, SecretKey};
    use futures::channel::mpsc;
    use futures::TryStreamExt;

    use rand::thread_rng;
    use tox_packet::dht::*;
    use crate::dht::server::Server as DhtServer;

    #[tokio::test]
    async fn run_socket() {
        let mut rng = thread_rng();
        let client_sk = SecretKey::generate(&mut rng);
        let client_pk = client_sk.public_key();
        let server_sk = SecretKey::generate(&mut rng);
        let server_pk = server_sk.public_key();
        let shared_secret = SalsaBox::new(&server_pk, &client_sk);

        let (tx, rx) = mpsc::channel(32);

        let server = Server::new(DhtServer::new(tx, server_pk, server_sk));

        // Bind server socket
        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_socket = UdpSocket::bind(&server_addr).await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let stats = Stats::new();
        let server_future = dht_run_socket(&server, server_socket, rx, stats);

        // Bind client socket to communicate with the server
        let client_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let client_socket = UdpSocket::bind(&client_addr).await.unwrap();

        let client_future = async {
            // Send invalid request first to ensure that the server won't crash
            client_socket.send_to(&[42; 123][..], &server_addr)
                .await
                .map_err(|e| Error::new(ErrorKind::Other, e))?;

            let stats = Stats::new();
            let codec = DhtCodec::new(stats);
            let (mut sink, stream) = tokio_util::udp::UdpFramed::new(client_socket, codec).split();

            // Send ping request
            let ping_id = 42;
            let ping_request_payload = PingRequestPayload {
                id: ping_id,
            };
            let ping_request = PingRequest::new(&shared_secret, client_pk, &ping_request_payload);

            sink.send((Packet::PingRequest(ping_request), server_addr)).await
                .map_err(|e| Error::new(ErrorKind::Other, e))?;

            // And wait for ping response
            let ping_response = stream
                .try_filter_map(|(packet, _)| futures::future::ok(
                    match packet {
                        Packet::PingResponse(ping_response) => Some(ping_response),
                        _ => None,
                    }
                ))
                .next()
                .await
                .unwrap();

            let ping_response = ping_response
                .map_err(|e| Error::new(ErrorKind::Other, e))?;
            let ping_response_payload = ping_response.get_payload(&shared_secret).unwrap();

            assert_eq!(ping_response_payload.id, ping_id);

            let res: Result<_, Error> = Ok(());
            res
        };

        futures::select! {
            res = client_future.fuse() => res.unwrap(),
            res = server_future.fuse() => res.unwrap(),
        };
    }
}
