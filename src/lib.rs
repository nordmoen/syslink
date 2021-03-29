//! This crate implements the [Crazyflie](https://www.bitcraze.io/) [Syslink
//! packet](https://www.bitcraze.io/documentation/repository/crazyflie2-nrf-firmware/master/protocols/syslink/)
//! format.
//!
//! Syslink is the internal format that is used to communicate messages between the main processor
//! and the communication processor on the Crazyflie.
//!
//! This crate uses [`heapless::Vec`] to allow a [`Packet`] to own its data. The static maximum
//! size of a packet is therefor limited to `64` bytes. This is inspired by the `MTU` used in the
//! official Crazyflie firmware. The downside of this is that we can potentially use a lot more
//! memory than necessary, but the upside is that it is easier to read from a stream of bytes and
//! reclaim the bytes back to the stream once successfully parsed.
//!
//! # Frame format
//! ```raw
//! +----+-----+------+-----+=============+-----+-----+
//! |  START   | TYPE | LEN | DATA        |   CKSUM   |
//! +----+-----+------+-----+=============+-----+-----+
//! ```
//! - `START` is a 2 byte constant
//! - [`TYPE`](PacketType) is the type of packet
//! - `LEN` is byte length of `DATA`
//! - `DATA` is the actual content of the packet, assumed to be `<= 64` bytes
//! - `CKSUM` is a [2 byte Fletcher 8 bit checksum](https://tools.ietf.org/html/rfc1146)
//!
//! The `CKSUM` is calculated over the `TYPE`, `LEN` and `DATA` fields.
//!
//! # Usage
//! The main functions of this crate is [`Packet::from`] and [`Packet::write`].
//!
//! ```
//! use syslink::{Packet, ParseError};
//! // We get some data into our buffer, but the following is an incomplete packet
//! let buffer = [0xBC, 0xCF, 0x00];
//! // We are missing the length parameter
//! assert_eq!(Packet::from(&buffer), Err(ParseError::Incomplete(1)));
//! // ...
//! // Later we get some more data into our buffer
//! let buffer = [0xBC, 0xCF, 0x00, 0, 0, 0];
//! assert_eq!(Packet::from(&buffer),
//!            Ok((&[][..], Packet::new(syslink::PacketType::from(0x00), &[][..]).unwrap())));
//! // The packet above represent a NULL packet without data
//! ```
#![no_std]

use core::convert::{Into, TryFrom};
use heapless::consts::U64;
use heapless::Vec;
use nom::bytes::streaming::{tag, take};
use nom::number::streaming::u8 as take1;

const START_BYTE1: u8 = 0xBC;
const START_BYTE2: u8 = 0xCF;
const GROUP_MASK: u8 = 0xF0;

/// Packet group types
const RADIO_GROUP: u8 = 0x00;
const PM_GROUP: u8 = 0x10;
const OW_GROUP: u8 = 0x20;

/// Type representing a Radio management packet
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum Radio {
    Raw = 0x00,
    Channel = 0x01,
    DataRate = 0x02,
    ContWave = 0x03,
    #[allow(clippy::upper_case_acronyms)]
    RSSI = 0x04,
    Address = 0x05,
    RawBroadcast = 0x06,
    Power = 0x07,
    P2P = 0x08,
    P2PAck = 0x09,
    P2PBroadcast = 0x0A,
}

impl TryFrom<u8> for Radio {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            value if value == Radio::Raw as u8 => Ok(Radio::Raw),
            value if value == Radio::Channel as u8 => Ok(Radio::Channel),
            value if value == Radio::DataRate as u8 => Ok(Radio::DataRate),
            value if value == Radio::ContWave as u8 => Ok(Radio::ContWave),
            value if value == Radio::RSSI as u8 => Ok(Radio::RSSI),
            value if value == Radio::Address as u8 => Ok(Radio::Address),
            value if value == Radio::RawBroadcast as u8 => Ok(Radio::RawBroadcast),
            value if value == Radio::Power as u8 => Ok(Radio::Power),
            value if value == Radio::P2P as u8 => Ok(Radio::P2P),
            value if value == Radio::P2PAck as u8 => Ok(Radio::P2PAck),
            value if value == Radio::P2PBroadcast as u8 => Ok(Radio::P2PBroadcast),
            _ => Err(()),
        }
    }
}

/// Type representing a Power management packet
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum Power {
    Source = 0x10,
    SwitchOff = 0x11,
    BatteryVoltage = 0x12,
    BatteryState = 0x13,
    BatteryAutoUpdate = 0x14,
}

impl TryFrom<u8> for Power {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            value if value == Power::Source as u8 => Ok(Power::Source),
            value if value == Power::SwitchOff as u8 => Ok(Power::SwitchOff),
            value if value == Power::BatteryVoltage as u8 => Ok(Power::BatteryVoltage),
            value if value == Power::BatteryState as u8 => Ok(Power::BatteryState),
            value if value == Power::BatteryAutoUpdate as u8 => Ok(Power::BatteryAutoUpdate),
            _ => Err(()),
        }
    }
}

/// Type representing a OneWire management packet
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum OneWire {
    Scan = 0x20,
    GetInfo = 0x21,
    Read = 0x22,
    Write = 0x23,
}

impl TryFrom<u8> for OneWire {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            value if value == OneWire::Scan as u8 => Ok(OneWire::Scan),
            value if value == OneWire::GetInfo as u8 => Ok(OneWire::GetInfo),
            value if value == OneWire::Read as u8 => Ok(OneWire::Read),
            value if value == OneWire::Write as u8 => Ok(OneWire::Write),
            _ => Err(()),
        }
    }
}

/// Type of Syslink packet
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum PacketType {
    /// Radio management related types
    Radio(Radio),
    /// Power management related types
    #[allow(clippy::upper_case_acronyms)]
    PM(Power),
    /// OneWire management related types
    #[allow(clippy::upper_case_acronyms)]
    OW(OneWire),
    /// An unknown packet type for this create
    Unknown(u8),
}

impl From<u8> for PacketType {
    fn from(value: u8) -> Self {
        match value & GROUP_MASK {
            RADIO_GROUP => {
                Radio::try_from(value).map_or(PacketType::Unknown(value), PacketType::Radio)
            }
            PM_GROUP => Power::try_from(value).map_or(PacketType::Unknown(value), PacketType::PM),
            OW_GROUP => OneWire::try_from(value).map_or(PacketType::Unknown(value), PacketType::OW),
            _ => PacketType::Unknown(value),
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<u8> for PacketType {
    fn into(self) -> u8 {
        match self {
            PacketType::Radio(r) => r as u8,
            PacketType::PM(p) => p as u8,
            PacketType::OW(o) => o as u8,
            PacketType::Unknown(v) => v,
        }
    }
}

/// Errors that can occur when writing a packet to buffer
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum WriteError {
    /// The supplied buffer did not have enough space to write the full message to
    NotEnoughSpace,
}

/// Potential errors that can occur when parsing a [`Packet`] from a byte stream
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ParseError {
    /// There was not enough bytes to completely parse, we need at least `usize` more bytes.
    ///
    /// Note that even though once supplied the parser could still return another `Incomplete`
    /// since the complete size of a packet is unknown until after reading its length.
    Incomplete(usize),
    /// The initial two tag bytes did not match
    ///
    /// This means one can discard the first byte of the stream since the stream does not contain a
    /// valid [`Packet`], but the second byte could be the start of a valid packet.
    WrongTag,
    /// The checksum did was not correct
    ///
    /// This means one can discard the full message, i.e. the `usize` bytes returned in the enum
    WrongChecksum(usize),
    /// Could not create packet since the amount of data overflowed our MTU size
    ///
    /// This means one can discard the full message, i.e. the `usize` bytes return in the enum
    TooMuchData(usize),
}

/// Result type for parsing a packet from a raw byte stream
///
/// On success the result contains the remaining stream of bytes (i.e. the original stream, but
/// with the bytes needed to create the packet consumed) and the parsed packet.
///
/// On failure this returns [`ParseError`], but note that this does directly mean that something
/// failed, it could be that we need more data to complete the parsing.
pub type ParseResult<'a> = Result<(&'a [u8], Packet), ParseError>;

/// Syslink packet
#[derive(Debug, PartialEq)]
pub struct Packet {
    pub typ: PacketType,
    pub data: Vec<u8, U64>,
}

impl Packet {
    /// Create a new packet from raw data
    #[allow(clippy::result_unit_err)]
    pub fn new(typ: PacketType, data: &[u8]) -> Result<Self, ()> {
        Ok(Packet {
            typ,
            data: Vec::from_slice(data)?,
        })
    }

    /// Get the size of this packet, in other words, the number of bytes needed to store the raw
    /// representation of this packet
    pub fn wire_size(&self) -> usize {
        // 2 start bytes, 1 byte type, 1 byte length, the data itself and
        // 2 bytes for the checksum
        2 + 1 + 1 + self.data.len() + 2
    }

    /// Write this packet into the buffer given, if successful return the number of bytes written
    /// to the buffer
    pub fn write(&self, buffer: &mut [u8]) -> core::result::Result<usize, WriteError> {
        // Check that the buffer is large enough to fill with this packet the buffer needs to hold
        if buffer.len() < self.wire_size() {
            return Err(WriteError::NotEnoughSpace);
        }
        // Since there is enough space we can write to the buffer
        buffer[0] = START_BYTE1;
        buffer[1] = START_BYTE2;
        buffer[2] = self.typ.into();
        buffer[3] = self.data.len() as u8;
        buffer[4..4 + self.data.len()].copy_from_slice(&self.data);
        let (a, b) = fletcher_checksum(&buffer[2..4 + self.data.len()]);
        let idx = 4 + self.data.len();
        buffer[idx] = a;
        buffer[idx + 1] = b;
        Ok(self.wire_size())
    }

    /// Parse a packet from a stream of bytes
    pub fn from(input: &[u8]) -> ParseResult {
        type NomError<'a> = nom::Err<nom::error::Error<&'a [u8]>>;

        let (inp, _) =
            tag(&[START_BYTE1, START_BYTE2])(input).map_err(|err: NomError| match err {
                nom::Err::Incomplete(nom::Needed::Size(val)) => ParseError::Incomplete(val.get()),
                nom::Err::Incomplete(_) => ParseError::Incomplete(1),
                _ => ParseError::WrongTag,
            })?;
        let (inp, type_byte) = take1(inp).map_err(|err: NomError| match err {
            nom::Err::Incomplete(_) => ParseError::Incomplete(1),
            _ => unreachable!(), // We can never get here since we are reading a raw byte from a raw stream
        })?;
        let (inp, length) = take1(inp).map_err(|err: NomError| match err {
            nom::Err::Incomplete(_) => ParseError::Incomplete(1),
            _ => unreachable!(), // We can never get here since we are reading a raw byte from a raw stream
        })?;
        let (inp, data) = take(length as usize)(inp).map_err(|err: NomError| match err {
            nom::Err::Incomplete(nom::Needed::Size(val)) => ParseError::Incomplete(val.get()),
            nom::Err::Incomplete(_) => ParseError::Incomplete(1),
            _ => unreachable!(), // We can never get here since we are reading raw bytes from a raw stream
        })?;
        let msg_size = 1 + 1 + length as usize;
        let (a, b) = fletcher_checksum(&input[2..2 + msg_size]);
        let (inp, cksum) = take(2usize)(inp).map_err(|err: NomError| match err {
            nom::Err::Incomplete(nom::Needed::Size(val)) => ParseError::Incomplete(val.get()),
            nom::Err::Incomplete(_) => ParseError::Incomplete(1),
            _ => unreachable!(), // We can never get here since we are reading raw bytes from a raw stream
        })?;
        if a != cksum[0] || b != cksum[1] {
            // Remember to add 2 bytes for the tag, message size and then 2 bytes for the checksum
            return Err(ParseError::WrongChecksum(2 + msg_size + 2));
        }
        let packet = Packet::new(PacketType::from(type_byte), data)
            .map_err(|_| ParseError::TooMuchData(2 + msg_size + 2))?;
        Ok((inp, packet))
    }
}

/// Implementation of a 2 byte Fletcher checksum
fn fletcher_checksum(data: &[u8]) -> (u8, u8) {
    data.iter().fold((0, 0), |(a, b), &v| (a + v, b + a + v))
}

#[cfg(test)]
mod test {
    use super::{
        fletcher_checksum, Packet, PacketType, ParseError, Radio, WriteError, START_BYTE1,
        START_BYTE2,
    };

    #[test]
    fn write() {
        let p = Packet::new(PacketType::from(0x00), &[][..]).unwrap();
        let mut buffer = [0; 2];
        assert_eq!(p.write(&mut buffer), Err(WriteError::NotEnoughSpace));
        let mut buffer = [0; 4];
        assert_eq!(p.write(&mut buffer), Err(WriteError::NotEnoughSpace));
        let mut buffer = [0; 2 + 2 + 0 + 2];
        assert_eq!(p.write(&mut buffer), Ok(6));
        assert_eq!(buffer[0], START_BYTE1);
        assert_eq!(buffer[1], START_BYTE2);
        assert_eq!(buffer[2], 0x00);
        assert_eq!(buffer[3], 0);
        assert_eq!(buffer[4], 0);
        assert_eq!(buffer[5], 0);

        let p = Packet::new(PacketType::from(0x00), &[0, 1, 2, 3][..]).unwrap();
        let mut buffer = [0; 32];
        assert_eq!(p.write(&mut buffer), Ok(10));
        assert_eq!(buffer[0], START_BYTE1);
        assert_eq!(buffer[1], START_BYTE2);
        assert_eq!(buffer[2], 0x00);
        assert_eq!(buffer[3], 4);
        assert_eq!(buffer[4], 0);
        assert_eq!(buffer[5], 1);
        assert_eq!(buffer[6], 2);
        assert_eq!(buffer[7], 3);
    }

    #[test]
    fn incomplete() {
        assert_eq!(Packet::from(&[][..]), Err(ParseError::Incomplete(2)));
        let buffer = [START_BYTE1];
        assert_eq!(Packet::from(&buffer), Err(ParseError::Incomplete(1)));
        let buffer = [START_BYTE1, START_BYTE2];
        assert_eq!(Packet::from(&buffer), Err(ParseError::Incomplete(1)));
        let buffer = [START_BYTE1, START_BYTE2, 0x00, 0];
        assert_eq!(Packet::from(&buffer), Err(ParseError::Incomplete(2)));
        let buffer = [START_BYTE1, START_BYTE2, 0x00, 1];
        assert_eq!(Packet::from(&buffer), Err(ParseError::Incomplete(1)));
        let buffer = [START_BYTE1, START_BYTE2, 0x00, 0];
        let (a, b) = fletcher_checksum(&buffer[2..]);
        let buffer = [START_BYTE1, START_BYTE2, 0x00, 0, a, b];
        let packet = Packet::from(&buffer);
        assert!(packet.is_ok());
        assert_eq!(
            packet.unwrap().1,
            Packet::new(PacketType::Radio(Radio::Raw), &[][..]).unwrap()
        );
    }

    #[test]
    fn parse() {
        let buffer = [START_BYTE1, START_BYTE2, 0x01, 0];
        let (a, b) = fletcher_checksum(&buffer[2..]);
        let buffer = [START_BYTE1, START_BYTE2, 0x01, 0, a, b];
        let packet = Packet::from(&buffer);
        assert!(packet.is_ok());
        assert_eq!(
            packet.unwrap().1,
            Packet::new(PacketType::Radio(Radio::Channel), &[][..]).unwrap()
        );
    }

    #[test]
    fn wrong_tag() {
        let buffer = [START_BYTE2];
        assert_eq!(Packet::from(&buffer), Err(ParseError::WrongTag));
        let buffer = [START_BYTE1, 0x00];
        assert_eq!(Packet::from(&buffer), Err(ParseError::WrongTag));
        let buffer = [START_BYTE1, START_BYTE1];
        assert_eq!(Packet::from(&buffer), Err(ParseError::WrongTag));
    }

    #[test]
    fn wrong_checksum() {
        // Note that we have different Type byte in the two buffers
        let buffer = [START_BYTE1, START_BYTE2, 0x00, 0];
        let (a, b) = fletcher_checksum(&buffer[2..]);
        //                                       /---- Different Type than above
        let buffer = [START_BYTE1, START_BYTE2, 0x01, 0, a, b];
        let packet = Packet::from(&buffer);
        assert_eq!(packet, Err(ParseError::WrongChecksum(6)));
        //                                       /---- Same Type as first time
        let buffer = [START_BYTE1, START_BYTE2, 0x00, 0, a, b];
        let packet = Packet::from(&buffer);
        // Now it works as expected
        assert!(packet.is_ok());
    }
}
