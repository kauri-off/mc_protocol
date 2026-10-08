struct Opaque;

#[derive(mc_protocol::Packet)]
struct HasOpaque {
    inner: Opaque,
}

fn main() {}
