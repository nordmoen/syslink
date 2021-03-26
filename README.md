# Syslink
This crate implements the [Crazyflie](https://www.bitcraze.io/) [Syslink
packet](https://www.bitcraze.io/documentation/repository/crazyflie2-nrf-firmware/master/protocols/syslink/)
format.

Syslink is the internal format that is used to communicate messages between the
main processor and the communication processor on the Crazyflie.

This crate uses [`heapless::Vec`](https://crates.io/crates/heapless) to allow a
`Packet` to own its data. The static maximum size of a packet is therefor
limited to `64` bytes. This is inspired by the `MTU` used in the official
Crazyflie firmware. The downside of this is that we can potentially use a lot
more memory than necessary, but the upside is that it is easier to read from a
stream of bytes and reclaim the bytes back to the stream once successfully
parsed.

# Usage
```rust
use syslink::{Packet, ParseError};
// We get some data into our buffer, but the following is an incomplete packet
let buffer = [0xBC, 0xCF, 0x00];
// We are missing the length parameter
assert_eq!(Packet::from(&buffer), Err(ParseError::Incomplete(1)));
// ...
// Later we get some more data into our buffer
let buffer = [0xBC, 0xCF, 0x00, 0, 0, 0];
assert_eq!(Packet::from(&buffer),
           Ok((&[][..], Packet::new(syslink::PacketType::from(0x00), &[][..]).unwrap())));
// The packet above represent a NULL packet without data
```
