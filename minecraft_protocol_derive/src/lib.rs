//! Procedural macros for `minecraft_protocol`.
//!
//! Provides `#[derive(Packet)]` which automatically generates
//! `Serialize`, `Deserialize`, and packet framing helpers for structs.

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Expr, Fields};

/// Derives `Packet` behaviour for a struct.
///
/// # Attributes
///
/// - `#[packet(0x00)]` — sets the packet ID (required)
/// - `#[packet_field(optional)]` — marks a field as `Option<T>` encoded with a presence boolean
/// - `#[packet_field(prefixed_array)]` — marks a field as `Vec<T>` encoded with a VarInt length prefix
///
/// # Example
///
/// ```ignore
/// #[derive(Packet, Debug)]
/// #[packet(0x00)]
/// struct Handshake {
///     protocol_version: VarInt,
///     server_address: String,
///     server_port: u16,
///     next_state: VarInt,
/// }
/// ```
#[proc_macro_derive(Packet, attributes(packet, packet_field))]
pub fn derive_packet(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_packet(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_packet(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let struct_name = &input.ident;

    // Extract packet ID from #[packet(ID)] attribute
    let packet_id_expr = extract_packet_id(input)?;

    let fields = match &input.data {
        Data::Struct(ds) => match &ds.fields {
            Fields::Named(f) => &f.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    struct_name,
                    "Packet can only be derived for structs with named fields",
                ))
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                struct_name,
                "Packet can only be derived for structs",
            ))
        }
    };

    let field_idents: Vec<_> = fields.iter().filter_map(|f| f.ident.as_ref()).collect();
    let field_types: Vec<_> = fields.iter().map(|f| &f.ty).collect();

    // Build serialize calls per field
    let serialize_calls: Vec<_> = field_idents
        .iter()
        .map(|ident| {
            quote! {
                minecraft_protocol::ser::Serialize::serialize(&self.#ident, __writer)?;
            }
        })
        .collect();

    // Build deserialize calls per field
    let deserialize_calls: Vec<_> = field_idents
        .iter()
        .zip(field_types.iter())
        .map(|(ident, ty)| {
            quote! {
                #ident: <#ty as minecraft_protocol::ser::Deserialize>::deserialize(__reader)?,
            }
        })
        .collect();

    let expanded = quote! {
        impl #struct_name {
            /// The numeric ID that identifies this packet on the wire.
            pub const PACKET_ID: i32 = #packet_id_expr as i32;
        }

        impl minecraft_protocol::ser::Serialize for #struct_name {
            fn serialize<W: std::io::Write + Unpin>(
                &self,
                __writer: &mut W,
            ) -> Result<(), minecraft_protocol::ser::SerializationError> {
                #(#serialize_calls)*
                Ok(())
            }
        }

        impl minecraft_protocol::ser::Deserialize for #struct_name {
            fn deserialize<R: std::io::Read + Unpin>(
                __reader: &mut R,
            ) -> Result<Self, minecraft_protocol::ser::SerializationError> {
                Ok(Self {
                    #(#deserialize_calls)*
                })
            }
        }

        impl minecraft_protocol::packet::PacketId for #struct_name {
            fn packet_id(&self) -> i32 {
                Self::PACKET_ID
            }
        }
    };

    Ok(expanded)
}

fn extract_packet_id(input: &DeriveInput) -> syn::Result<Expr> {
    for attr in &input.attrs {
        if attr.path().is_ident("packet") {
            let expr: Expr = attr.parse_args()?;
            return Ok(expr);
        }
    }
    Err(syn::Error::new_spanned(
        &input.ident,
        "Expected #[packet(ID)] attribute with a packet ID, e.g. #[packet(0x00)]",
    ))
}
