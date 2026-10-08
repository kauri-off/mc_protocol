//! Procedural macros for `mc_protocol`.
//!
//! Provides `#[derive(Packet)]` which automatically generates
//! `Serialize`, `Deserialize`, and packet framing helpers for structs.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Expr, Fields, parse_macro_input, parse_quote};

/// Derives `Packet` behaviour for a struct.
///
/// # Attributes
///
/// - `#[packet(0x00)]` — sets the packet ID (optional; omit for nested/helper
///   structs that appear inside another packet's fields and only need
///   `Serialize`/`Deserialize`). When present, the derive also generates a
///   `PACKET_ID: i32` associated const and a `PacketId` impl.
///
/// `Option<T>` fields are encoded with a boolean presence flag and `Vec<T>`
/// fields with a VarInt length prefix automatically — no field attribute is
/// needed.
///
/// # Examples
///
/// A top-level packet with an ID:
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
///
/// A nested field struct without an ID, used inside another packet's `Vec<T>`:
///
/// ```ignore
/// #[derive(Packet, Debug)]
/// struct Item {
///     id: VarInt,
///     count: u8,
/// }
///
/// #[derive(Packet, Debug)]
/// #[packet(0x10)]
/// struct Inventory {
///     items: Vec<Item>,
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

    // Extract packet ID from #[packet(ID)] attribute — absent is allowed for
    // nested helper structs that only need Serialize/Deserialize.
    let packet_id_expr = extract_packet_id(input)?;

    let fields = match &input.data {
        Data::Struct(ds) => match &ds.fields {
            Fields::Named(f) => &f.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    struct_name,
                    "Packet can only be derived for structs with named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                struct_name,
                "Packet can only be derived for structs",
            ));
        }
    };

    let field_idents: Vec<_> = fields.iter().filter_map(|f| f.ident.as_ref()).collect();
    let field_types: Vec<_> = fields.iter().map(|f| &f.ty).collect();

    // Build serialize calls per field
    let serialize_calls: Vec<_> = field_idents
        .iter()
        .zip(field_types.iter())
        .map(|(ident, ty)| {
            quote_spanned! {ty.span()=>
                <#ty as ::mc_protocol::ser::Serialize>::serialize(&self.#ident, __writer)?;
            }
        })
        .collect();

    // Build deserialize calls per field
    let deserialize_calls: Vec<_> = field_idents
        .iter()
        .zip(field_types.iter())
        .map(|(ident, ty)| {
            quote! {
                #ident: <#ty as ::mc_protocol::ser::Deserialize>::deserialize(__reader)?,
            }
        })
        .collect();

    // Generic structs: the trait impls require every type parameter to be
    // serializable/deserializable itself.
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let ser_generics = add_trait_bounds(
        input.generics.clone(),
        parse_quote!(::mc_protocol::ser::Serialize),
    );
    let (ser_impl_generics, _, ser_where_clause) = ser_generics.split_for_impl();

    let de_generics = add_trait_bounds(
        input.generics.clone(),
        parse_quote!(::mc_protocol::ser::Deserialize),
    );
    let (de_impl_generics, _, de_where_clause) = de_generics.split_for_impl();

    let packet_id_impls = packet_id_expr.map(|expr| {
        quote! {
            impl #impl_generics #struct_name #ty_generics #where_clause {
                /// The numeric ID that identifies this packet on the wire.
                pub const PACKET_ID: i32 = #expr as i32;
            }

            #[automatically_derived]
            impl #impl_generics ::mc_protocol::packet::PacketId for #struct_name #ty_generics #where_clause {
                fn packet_id(&self) -> i32 {
                    Self::PACKET_ID
                }
            }
        }
    });

    let expanded = quote! {
        #packet_id_impls

        #[automatically_derived]
        impl #ser_impl_generics ::mc_protocol::ser::Serialize for #struct_name #ty_generics #ser_where_clause {
            fn serialize<W: ::std::io::Write + ::core::marker::Unpin>(
                &self,
                __writer: &mut W,
            ) -> ::core::result::Result<(), ::mc_protocol::ser::SerializationError> {
                #(#serialize_calls)*
                ::core::result::Result::Ok(())
            }
        }

        #[automatically_derived]
        impl #de_impl_generics ::mc_protocol::ser::Deserialize for #struct_name #ty_generics #de_where_clause {
            fn deserialize<R: ::std::io::Read + ::core::marker::Unpin>(
                __reader: &mut R,
            ) -> ::core::result::Result<Self, ::mc_protocol::ser::SerializationError> {
                ::core::result::Result::Ok(Self {
                    #(#deserialize_calls)*
                })
            }
        }
    };

    Ok(expanded)
}

/// Add `bound` to every type parameter in `generics`.
fn add_trait_bounds(mut generics: syn::Generics, bound: syn::TypeParamBound) -> syn::Generics {
    for param in &mut generics.params {
        if let syn::GenericParam::Type(type_param) = param {
            type_param.bounds.push(bound.clone());
        }
    }
    generics
}

fn extract_packet_id(input: &DeriveInput) -> syn::Result<Option<Expr>> {
    let mut id = None;
    for attr in &input.attrs {
        if attr.path().is_ident("packet") {
            if id.is_some() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "duplicate #[packet] attribute",
                ));
            }
            id = Some(attr.parse_args::<Expr>()?);
        }
    }
    Ok(id)
}
