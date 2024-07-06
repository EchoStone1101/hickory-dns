use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, parse_quote, Data, DeriveInput, Fields, GenericParam, Generics, Index,
};

#[proc_macro_derive(Walk)]
pub fn derive_dump(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // Parse the input tokens into a syntax tree.
    let input = parse_macro_input!(input as DeriveInput);

    // Used in the quasi-quotation below as `#name`.
    let name = input.ident;

    // Add a bound `T: std::fmt::Debug` to every type parameter T.
    let generics = add_trait_bounds(input.generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // Generate an expression to dump each field.
    let dump_fields = dump_fields(&input.data);

    let expanded = quote! {
        // The generated impl.
        impl #impl_generics Walk for #name #ty_generics #where_clause {
            fn walk(&self) {
                #dump_fields
            }
        }
    };

    // Hand the output tokens back to the compiler.
    proc_macro::TokenStream::from(expanded)
}

// Add a bound `T: std::fmt::Debug` to every type parameter T.
fn add_trait_bounds(mut generics: Generics) -> Generics {
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param.bounds.push(parse_quote!(Walk));
        }
    }
    generics
}

// Generate an expression to dump each field.
fn dump_fields(data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    let recurse = fields.named.iter().map(|f| {
                        let name = &f.ident;
                        // let name_str = format!("{}", name.as_ref().unwrap());
                        quote_spanned! {f.span()=>
                            self.#name.walk();
                            // println!("Field {}: Address: {:p}, Value: {:?}", #name_str, &self.#name, &self.#name);
                        }
                    });
                    quote! {
                        #(#recurse)*
                    }
                }
                Fields::Unnamed(ref fields) => {
                    let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                        let index = Index::from(i);
                        // let index_str = format!("{}", i);
                        quote_spanned! {f.span()=>
                            self.#index.walk();
                            // println!("Field {}: Address: {:p}, Value: {:?}", #index_str, &self.#index, &self.#index);
                        }
                    });
                    quote! {
                        #(#recurse)*
                    }
                }
                Fields::Unit => {
                    quote! {
                        // println!("Unit struct has no fields.");
                    }
                }
            }
        }
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
}
