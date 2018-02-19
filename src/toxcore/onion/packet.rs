/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2018 Evgeny Kurnevsky <kurnevsky@gmail.com>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

/*! Onion UDP Packets
*/

use toxcore::binary_io_new::*;
use toxcore::crypto_core::*;

use nom::{be_u16, le_u8, le_u64, rest};
use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
};
use std::io::{Error, ErrorKind};

/// IPv4 is padded with 12 bytes of zeroes so that both IPv4 and
/// IPv6 have the same stored size.
pub const IPV4_PADDING_SIZE: usize = 12;

/// Size of serialized `IpPort` struct.
pub const SIZE_IPPORT: usize = 19;

/// Size of first `OnionReturn` struct with no inner `OnionReturn`s.
pub const ONION_RETURN_1_SIZE: usize = NONCEBYTES + SIZE_IPPORT + MACBYTES; // 59
/// Size of second `OnionReturn` struct with one inner `OnionReturn`.
pub const ONION_RETURN_2_SIZE: usize = NONCEBYTES + SIZE_IPPORT + MACBYTES + ONION_RETURN_1_SIZE; // 118
/// Size of third `OnionReturn` struct with two inner `OnionReturn`s.
pub const ONION_RETURN_3_SIZE: usize = NONCEBYTES + SIZE_IPPORT + MACBYTES + ONION_RETURN_2_SIZE; // 177

/// Parser that returns the length of the remaining input.
pub fn rest_len(input: &[u8]) -> IResult<&[u8], usize> {
    IResult::Done(input, input.len())
}

/** `IpAddr` with a port number. IPv4 is padded with 12 bytes of zeros
so that both IPv4 and IPv6 have the same stored size.

Serialized form:

Length      | Content
----------- | ------
`1`         | IpType
`4` or `16` | IPv4 or IPv6 address
`0` or `12` | Padding for IPv4
`2`         | Port

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpPort {
    /// IP address
    ip_addr: IpAddr,
    /// Port number
    port: u16
}

impl FromBytes for IpPort {
    named!(from_bytes<IpPort>, do_parse!(
        ip_addr: switch!(le_u8,
            2 => terminated!(
                map!(Ipv4Addr::from_bytes, IpAddr::V4),
                take!(IPV4_PADDING_SIZE)
            ) |
            10 => map!(Ipv6Addr::from_bytes, IpAddr::V6)
        ) >>
        port: be_u16 >>
        (IpPort { ip_addr: ip_addr, port: port })
    ));
}

impl ToBytes for IpPort {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_if_else!(self.ip_addr.is_ipv4(), gen_be_u8!(2), gen_be_u8!(10)) >>
            gen_call!(|buf, ip_addr| IpAddr::to_bytes(ip_addr, buf), &self.ip_addr) >>
            gen_cond!(self.ip_addr.is_ipv4(), gen_slice!(&[0; IPV4_PADDING_SIZE])) >>
            gen_be_u16!(self.port)
        )
    }
}

/** Encrypted onion return addresses. Payload contains encrypted with symmetric
key `IpPort` and possibly inner `OnionReturn`.

Serialized form:

Length                | Content
--------              | ------
`24`                  | `Nonce`
`35` or `94` or `153` | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionReturn {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionReturn {
    named!(from_bytes<OnionReturn>, do_parse!(
        nonce: call!(Nonce::from_bytes) >>
        payload: rest >>
        (OnionReturn { nonce: nonce, payload: payload.to_vec() })
    ));
}

impl ToBytes for OnionReturn {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload)
        )
    }
}

impl OnionReturn {
    named!(inner_from_bytes<(IpPort, Option<OnionReturn>)>, do_parse!(
        ip_addr: call!(IpPort::from_bytes) >>
        rest_len: rest_len >>
        inner: cond!(rest_len > 0, OnionReturn::from_bytes) >>
        (ip_addr, inner)
    ));
    /** Decrypt payload and try to parse it as `IpPort` with possibly inner `OnionReturn`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `IpPort` with possibly inner `OnionReturn`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<(IpPort, Option<OnionReturn>), Error> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, &shared_secret)
            .map_err(|e| {
                debug!("Decrypting OnionReturn failed!");
                Error::new(ErrorKind::Other,
                    format!("OnionReturn decrypt error: {:?}", e))
            })?;
        match OnionReturn::inner_from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                error!(target: "Onion", "Inner onion return deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("Inner onion return deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                error!(target: "Onion", "Inner onion return deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("Inner onion return deserialize error: {:?}", e)))
            },
            IResult::Done(_, inner) => {
                Ok(inner)
            }
        }
    }
}

/** First onion request packet. It's sent from DHT node to the first node from
onion chain. Payload can be encrypted with either temporary generated
`SecretKey` or DHT `SecretKey` of sender and with DHT `PublicKey` of receiver.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x80`
`24`     | `Nonce`
`32`     | `PublicKey` of sender
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionRequest0 {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionRequest0 {
    named!(from_bytes<OnionRequest0>, do_parse!(
        tag!(&[0x80][..]) >>
        nonce: call!(Nonce::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        payload: rest >>
        (OnionRequest0 {
            nonce: nonce,
            temporary_pk: temporary_pk,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for OnionRequest0 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x80) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload)
        )
    }
}

/** Second onion request packet. It's sent from the first to the second node from
onion chain. Payload should be encrypted with temporary generated `SecretKey` and
with DHT `PublicKey` of receiver.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x81`
`24`     | `Nonce`
`32`     | Temporary `PublicKey`
variable | Payload
`59`     | `OnionReturn`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionRequest1 {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>,
    /// Return address encrypted by the first node from onion chain
    pub onion_return: OnionReturn
}

impl FromBytes for OnionRequest1 {
    named!(from_bytes<OnionRequest1>, do_parse!(
        tag!(&[0x81][..]) >>
        nonce: call!(Nonce::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        rest_len: rest_len >>
        payload: cond_reduce!(
            rest_len >= ONION_RETURN_1_SIZE,
            take!(rest_len - ONION_RETURN_1_SIZE)
        ) >>
        onion_return: call!(OnionReturn::from_bytes) >>
        (OnionRequest1 {
            nonce: nonce,
            temporary_pk: temporary_pk,
            payload: payload.to_vec(),
            onion_return: onion_return
        })
    ));
}

impl ToBytes for OnionRequest1 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x81) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return)
        )
    }
}

/** Third onion request packet. It's sent from the second to the third node from
onion chain. Payload should be encrypted with temporary generated `SecretKey` and
with DHT `PublicKey` of receiver.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x82`
`24`     | `Nonce`
`32`     | Temporary `PublicKey`
variable | Payload
`118`    | `OnionReturn`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionRequest2 {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>,
    /// Return address encrypted by the second node from onion chain
    pub onion_return: OnionReturn
}

impl FromBytes for OnionRequest2 {
    named!(from_bytes<OnionRequest2>, do_parse!(
        tag!(&[0x82][..]) >>
        nonce: call!(Nonce::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        rest_len: rest_len >>
        payload: cond_reduce!(
            rest_len >= ONION_RETURN_2_SIZE,
            take!(rest_len - ONION_RETURN_2_SIZE)
        ) >>
        onion_return: call!(OnionReturn::from_bytes) >>
        (OnionRequest2 {
            nonce: nonce,
            temporary_pk: temporary_pk,
            payload: payload.to_vec(),
            onion_return: onion_return
        })
    ));
}

impl ToBytes for OnionRequest2 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x82) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return)
        )
    }
}

/** Serialized form:

Length   | Content
-------- | ------
`1`      | `0x83`
`24`     | `Nonce`
`32`     | Temporary or real `PublicKey`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InnerAnnounceRequest {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary or real `PublicKey` for the current encrypted payload
    pub pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for InnerAnnounceRequest {
    named!(from_bytes<InnerAnnounceRequest>, do_parse!(
        tag!(&[0x83][..]) >>
        nonce: call!(Nonce::from_bytes) >>
        pk: call!(PublicKey::from_bytes) >>
        payload: rest >>
        (InnerAnnounceRequest {
            nonce: nonce,
            pk: pk,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for InnerAnnounceRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x83) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.payload)
        )
    }
}

/** Same as `InnerAnnounceRequest` but with `OnionReturn` addresses. It's sent
from the third node from onion chain to the destination node.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x83`
`24`     | `Nonce`
`32`     | Temporary or real `PublicKey`
variable | Payload
`177`    | `OnionReturn`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnounceRequest {
    /// Inner announce request that was enclosed in onion packets
    pub inner: InnerAnnounceRequest,
    /// Return address encrypted by the third node from onion chain
    pub onion_return: OnionReturn
}

impl FromBytes for AnnounceRequest {
    named!(from_bytes<AnnounceRequest>, do_parse!(
        rest_len: rest_len >>
        inner: cond_reduce!(
            rest_len >= ONION_RETURN_3_SIZE,
            flat_map!(take!(rest_len - ONION_RETURN_3_SIZE), InnerAnnounceRequest::from_bytes)
        ) >>
        onion_return: call!(OnionReturn::from_bytes) >>
        (AnnounceRequest { inner: inner, onion_return: onion_return })
    ));
}

impl ToBytes for AnnounceRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, inner| InnerAnnounceRequest::to_bytes(inner, buf), &self.inner) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return)
        )
    }
}

/** Serialized form:

Length   | Content
-------- | ------
`1`      | `0x85`
`32`     | `PublicKey` of destination node
`24`     | `Nonce`
`32`     | Temporary `PublicKey`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InnerOnionDataRequest {
    /// `PublicKey` of destination node
    pub destination_pk: PublicKey,
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for InnerOnionDataRequest {
    named!(from_bytes<InnerOnionDataRequest>, do_parse!(
        tag!(&[0x85][..]) >>
        destination_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        payload: rest >>
        (InnerOnionDataRequest {
            destination_pk: destination_pk,
            nonce: nonce,
            temporary_pk: temporary_pk,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for InnerOnionDataRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x85) >>
            gen_slice!(self.destination_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload)
        )
    }
}

/** Same as `InnerOnionDataRequest` but with `OnionReturn` addresses. It's sent
from the third node from onion chain to the destination node.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x85`
`32`     | `PublicKey` of destination node
`24`     | `Nonce`
`32`     | Temporary `PublicKey`
variable | Payload
`177`    | `OnionReturn`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionDataRequest {
    /// Inner onion data request that was enclosed in onion packets
    pub inner: InnerOnionDataRequest,
    /// Return address encrypted by the third node from onion chain
    pub onion_return: OnionReturn
}

impl FromBytes for OnionDataRequest {
    named!(from_bytes<OnionDataRequest>, do_parse!(
        rest_len: rest_len >>
        inner: cond_reduce!(
            rest_len >= ONION_RETURN_3_SIZE,
            flat_map!(take!(rest_len - ONION_RETURN_3_SIZE), InnerOnionDataRequest::from_bytes)
        ) >>
        onion_return: call!(OnionReturn::from_bytes) >>
        (OnionDataRequest { inner: inner, onion_return: onion_return })
    ));
}

impl ToBytes for OnionDataRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, inner| InnerOnionDataRequest::to_bytes(inner, buf), &self.inner) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return)
        )
    }
}

/** Serialized form:

Length   | Content
-------- | ------
`1`      | `0x86`
`24`     | `Nonce`
`32`     | Temporary `PublicKey`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionDataResponse {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionDataResponse {
    named!(from_bytes<OnionDataResponse>, do_parse!(
        tag!(&[0x86][..]) >>
        nonce: call!(Nonce::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        payload: rest >>
        (OnionDataResponse {
            nonce: nonce,
            temporary_pk: temporary_pk,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for OnionDataResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x86) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload)
        )
    }
}

/** Serialized form:

Length   | Content
-------- | ------
`1`      | `0x84`
`8`      | Data to send back in response
`24`     | `Nonce`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnounceResponse {
    /// Data to send back in response
    pub sendback_data: u64,
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for AnnounceResponse {
    named!(from_bytes<AnnounceResponse>, do_parse!(
        tag!(&[0x84][..]) >>
        sendback_data: le_u64 >>
        nonce: call!(Nonce::from_bytes) >>
        payload: rest >>
        (AnnounceResponse {
            sendback_data: sendback_data,
            nonce: nonce,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for AnnounceResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x84) >>
            gen_le_u64!(self.sendback_data) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload)
        )
    }
}

/** Third onion response packet. It's sent back from the destination node to the
third node from onion chain.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x8c`
`177`    | `OnionReturn`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionResponse3 {
    /// Return address encrypted by the third node from onion chain
    pub onion_return: OnionReturn,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionResponse3 {
    named!(from_bytes<OnionResponse3>, do_parse!(
        tag!(&[0x8c][..]) >>
        onion_return: flat_map!(take!(ONION_RETURN_3_SIZE), OnionReturn::from_bytes) >>
        payload: rest >>
        (OnionResponse3 {
            onion_return: onion_return,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for OnionResponse3 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x8c) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return) >>
            gen_slice!(self.payload)
        )
    }
}

/** Second onion response packet. It's sent back from the third to the second node
from onion chain.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x8d`
`118`    | `OnionReturn`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionResponse2 {
    /// Return address encrypted by the second node from onion chain
    pub onion_return: OnionReturn,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionResponse2 {
    named!(from_bytes<OnionResponse2>, do_parse!(
        tag!(&[0x8d][..]) >>
        onion_return: flat_map!(take!(ONION_RETURN_2_SIZE), OnionReturn::from_bytes) >>
        payload: rest >>
        (OnionResponse2 {
            onion_return: onion_return,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for OnionResponse2 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x8d) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return) >>
            gen_slice!(self.payload)
        )
    }
}

/** First onion response packet. It's sent back from the second to the first node
from onion chain.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x8e`
`59`     | `OnionReturn`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionResponse1 {
    /// Return address encrypted by the first node from onion chain
    pub onion_return: OnionReturn,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionResponse1 {
    named!(from_bytes<OnionResponse1>, do_parse!(
        tag!(&[0x8e][..]) >>
        onion_return: flat_map!(take!(ONION_RETURN_1_SIZE), OnionReturn::from_bytes) >>
        payload: rest >>
        (OnionResponse1 {
            onion_return: onion_return,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for OnionResponse1 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x8e) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return) >>
            gen_slice!(self.payload)
        )
    }
}