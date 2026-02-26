//! Tests for the Position type.
//!
//! Reference example from the Minecraft Java Edition protocol documentation:
//!
//! Example value (big endian): 01000110000001110110001100 10110000010101101101001000 001100111111
//! - X = 18357644
//! - Z = -20882616  
//! - Y = 831

use minecraft_protocol::ser::{Deserialize, Serialize};
use minecraft_protocol::types::{
    Angle, FixedPoint5, Identifier, Position, SoundEvent, TeleportFlags,
};
use std::io::Cursor;

fn round_trip(pos: Position) -> Position {
    let mut buf = Vec::new();
    pos.serialize(&mut buf).unwrap();
    Position::deserialize(&mut Cursor::new(&buf)).unwrap()
}

// ---------------------------------------------------------------------------
// Protocol reference example
// ---------------------------------------------------------------------------

#[test]
fn position_protocol_reference_example() {
    let pos = Position {
        x: 18357644,
        y: 831,
        z: -20882616,
    };
    assert_eq!(round_trip(pos), pos);
}

#[test]
fn position_encodes_to_8_bytes() {
    let pos = Position { x: 0, y: 0, z: 0 };
    let mut buf = Vec::new();
    pos.serialize(&mut buf).unwrap();
    assert_eq!(buf.len(), 8);
}

// ---------------------------------------------------------------------------
// Boundary values
// ---------------------------------------------------------------------------

#[test]
fn position_origin() {
    assert_eq!(
        round_trip(Position { x: 0, y: 0, z: 0 }),
        Position { x: 0, y: 0, z: 0 }
    );
}

#[test]
fn position_max_x() {
    let pos = Position {
        x: 33554431,
        y: 0,
        z: 0,
    };
    assert_eq!(round_trip(pos), pos);
}

#[test]
fn position_min_x() {
    let pos = Position {
        x: -33554432,
        y: 0,
        z: 0,
    };
    assert_eq!(round_trip(pos), pos);
}

#[test]
fn position_max_y() {
    let pos = Position {
        x: 0,
        y: 2047,
        z: 0,
    };
    assert_eq!(round_trip(pos), pos);
}

#[test]
fn position_min_y() {
    let pos = Position {
        x: 0,
        y: -2048,
        z: 0,
    };
    assert_eq!(round_trip(pos), pos);
}

#[test]
fn position_max_z() {
    let pos = Position {
        x: 0,
        y: 0,
        z: 33554431,
    };
    assert_eq!(round_trip(pos), pos);
}

#[test]
fn position_min_z() {
    let pos = Position {
        x: 0,
        y: 0,
        z: -33554432,
    };
    assert_eq!(round_trip(pos), pos);
}

#[test]
fn position_all_negative() {
    let pos = Position {
        x: -100,
        y: -64,
        z: -200,
    };
    assert_eq!(round_trip(pos), pos);
}

#[test]
fn position_mixed() {
    let pos = Position {
        x: 1000,
        y: 64,
        z: -500,
    };
    assert_eq!(round_trip(pos), pos);
}

// ---------------------------------------------------------------------------
// Angle
// ---------------------------------------------------------------------------

#[test]
fn angle_zero() {
    let a = Angle(0);
    let mut buf = Vec::new();
    a.serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x00]);
    assert_eq!(Angle::deserialize(&mut Cursor::new(&buf)).unwrap(), a);
}

#[test]
fn angle_from_degrees_round_trip() {
    let a = Angle::from_degrees(180.0);
    let decoded_degrees = a.to_degrees();
    assert!(
        (decoded_degrees - 180.0).abs() < 2.0,
        "Expected ~180 degrees, got {}",
        decoded_degrees
    );
}

#[test]
fn angle_max() {
    let a = Angle(255);
    let mut buf = Vec::new();
    a.serialize(&mut buf).unwrap();
    assert_eq!(Angle::deserialize(&mut Cursor::new(&buf)).unwrap(), a);
}

// ---------------------------------------------------------------------------
// Identifier
// ---------------------------------------------------------------------------

#[test]
fn identifier_with_namespace() {
    let id = Identifier::new("minecraft:stone");
    assert_eq!(id.namespace(), "minecraft");
    assert_eq!(id.value(), "stone");
}

#[test]
fn identifier_without_namespace_defaults_to_minecraft() {
    let id = Identifier::new("stone");
    assert_eq!(id.namespace(), "minecraft");
    assert_eq!(id.value(), "stone");
    assert_eq!(id.0, "minecraft:stone");
}

#[test]
fn identifier_round_trip() {
    let id = Identifier::new("minecraft:stone");
    let mut buf = Vec::new();
    id.serialize(&mut buf).unwrap();
    let decoded = Identifier::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, id);
}

// ---------------------------------------------------------------------------
// TeleportFlags
// ---------------------------------------------------------------------------

#[test]
fn teleport_flags_round_trip() {
    let flags = TeleportFlags(TeleportFlags::RELATIVE_X | TeleportFlags::RELATIVE_Y);
    let mut buf = Vec::new();
    flags.serialize(&mut buf).unwrap();
    let decoded = TeleportFlags::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, flags);
}

#[test]
fn teleport_flags_is_set() {
    let flags = TeleportFlags(TeleportFlags::RELATIVE_X | TeleportFlags::RELATIVE_Z);
    assert!(flags.is_set(TeleportFlags::RELATIVE_X));
    assert!(!flags.is_set(TeleportFlags::RELATIVE_Y));
    assert!(flags.is_set(TeleportFlags::RELATIVE_Z));
}

#[test]
fn teleport_flags_all_relative() {
    let flags = TeleportFlags::all_relative();
    assert!(flags.is_set(TeleportFlags::RELATIVE_X));
    assert!(flags.is_set(TeleportFlags::RELATIVE_Y));
    assert!(flags.is_set(TeleportFlags::RELATIVE_Z));
    assert!(flags.is_set(TeleportFlags::RELATIVE_YAW));
    assert!(flags.is_set(TeleportFlags::RELATIVE_PITCH));
}

// ---------------------------------------------------------------------------
// FixedPoint5
// ---------------------------------------------------------------------------

#[test]
fn fixed_point_5_from_f64() {
    let fp = FixedPoint5::from_f64(1.0);
    assert_eq!(fp.0, 32); // 1.0 * (1 << 5) = 32
}

#[test]
fn fixed_point_5_to_f64() {
    let fp = FixedPoint5(32);
    assert!((fp.to_f64() - 1.0).abs() < 1e-10);
}

#[test]
fn fixed_point_5_round_trip() {
    let fp = FixedPoint5::from_f64(3.5);
    let mut buf = Vec::new();
    fp.serialize(&mut buf).unwrap();
    let decoded = FixedPoint5::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, fp);
}

// ---------------------------------------------------------------------------
// SoundEvent
// ---------------------------------------------------------------------------

#[test]
fn sound_event_with_no_fixed_range() {
    let evt = SoundEvent {
        name: Identifier::new("minecraft:entity.player.hurt"),
        fixed_range: None,
    };
    let mut buf = Vec::new();
    evt.serialize(&mut buf).unwrap();
    let decoded = SoundEvent::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded.name, evt.name);
    assert_eq!(decoded.fixed_range, None);
}

#[test]
fn sound_event_with_fixed_range() {
    let evt = SoundEvent {
        name: Identifier::new("minecraft:music.game"),
        fixed_range: Some(16.0),
    };
    let mut buf = Vec::new();
    evt.serialize(&mut buf).unwrap();
    let decoded = SoundEvent::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded.name, evt.name);
    assert!((decoded.fixed_range.unwrap() - 16.0).abs() < f32::EPSILON);
}
