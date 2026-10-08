#[derive(mc_protocol::Packet)]
#[packet(0x00)]
#[packet(0x01)]
struct Twice {
    a: u8,
}

fn main() {}
