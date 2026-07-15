mod isa_parser;

use proc_macro::{TokenStream, TokenTree};
use quote::quote;

fn arg_rs_type(name: &str) -> &str {
    match name {
        "hh" | "cc" | "str_idx" => "u8",
        "oo" => "i32",
        "slot" | "dst" | "src" | "dd" | "ss" | "id" => "u16",
        _ => "u64",
    }
}

fn arg_expr(index: usize, name: &str) -> proc_macro2::TokenStream {
    let i = index;
    match name {
        "hh" | "cc" | "str_idx" => quote! { args[#i] as u8 },
        "oo" => quote! { args[#i] as i32 },
        "slot" | "dst" | "src" | "dd" | "ss" | "id" => quote! { args[#i] as u16 },
        _ => quote! { args[#i] },
    }
}

fn mnemonic_to_variant(mnemonic: &str) -> String {
    match mnemonic {
        "SET" => "SetImm".to_string(),
        "GET" => "Get".to_string(),
        "INC" => "Inc".to_string(),
        "DEC" => "Dec".to_string(),
        "ADD" => "AddImm".to_string(),
        "SUB" => "SubImm".to_string(),
        "ADDV" => "AddV".to_string(),
        "SUBV" => "SubV".to_string(),
        "IMUL" => "Imul".to_string(),
        "CMP" => "Cmp".to_string(),
        "HANDLER" => "HandlerStart".to_string(),
        "CALL" => "CallHh".to_string(),
        "JMP" => "JmpHh".to_string(),
        "JE" => "JeHh".to_string(),
        "JNE" => "JneHh".to_string(),
        "JL" => "JlHh".to_string(),
        "JGE" => "JgeHh".to_string(),
        "JLE" => "JleHh".to_string(),
        "JG" => "JgHh".to_string(),
        "JB" => "JbHh".to_string(),
        "JAE" => "JaeHh".to_string(),
        "JBE" => "JbeHh".to_string(),
        "JA" => "JaHh".to_string(),
        "RET" => "Ret".to_string(),
        "LDB" => "Ldb".to_string(),
        "MEMCPYD" => "MemcpyData".to_string(),
        "MEMCPYS" => "MemcpyState".to_string(),
        "FADD" => "Fadd".to_string(),
        "FSUB" => "Fsub".to_string(),
        "FMUL" => "Fmul".to_string(),
        "FDIV" => "Fdiv".to_string(),
        "FCMP" => "Fcmp".to_string(),
        "RAW_BYTE" => "RawByte".to_string(),
        "RAW_BYTES" => "RawBytes".to_string(),
        "STRING_DEF" => "StringDef".to_string(),
        "RAW_DEF" => "RawDef".to_string(),
        "ALLOC" => "Alloc".to_string(),
        "LOADFILE" => "LoadFile".to_string(),
        "WRITEFILE" => "WriteFile".to_string(),
        "LIBYOYO_ALLOC" => "LibyoyoAlloc".to_string(),
        "LIBYOYO_FREE" => "LibyoyoFree".to_string(),
        "LIBYOYO_OPEN" => "LibyoyoOpen".to_string(),
        "LIBYOYO_READ" => "LibyoyoRead".to_string(),
        "LIBYOYO_WRITE" => "LibyoyoWrite".to_string(),
        "LIBYOYO_CLOSE" => "LibyoyoClose".to_string(),
        "LIBYOYO_EXIT" => "LibyoyoExit".to_string(),
        "LIBYOYO_PRINT" => "LibyoyoPrint".to_string(),
        "LIBYOYO_TIME" => "LibyoyoTime".to_string(),
        "DATA" => "Data".to_string(),
        "STR" => "Str".to_string(),
        "DEF" => "Def".to_string(),
        _ => {
            let capitalized: String = mnemonic
                .chars()
                .enumerate()
                .map(|(i, c)| if i == 0 { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() })
                .collect();
            capitalized
        }
    }
}

struct IsaEntry {
    opcode: u16,
    mnemonic: String,
    args: Vec<String>,
}

fn tokenize_isat(input: TokenStream) -> Vec<IsaEntry> {
    let tokens: Vec<TokenTree> = input.into_iter().collect();
    let mut entries = Vec::new();
    let mut i = 0;

    while i < tokens.len() {
        // Expect opcode literal (e.g., 0x0030)
        let opcode_str = tokens[i].to_string();
        let opcode = opcode_str
            .strip_prefix("0x")
            .and_then(|h| u16::from_str_radix(h, 16).ok())
            .unwrap_or_else(|| panic!("isa: expected hex opcode at token {i}, got '{opcode_str}'"));
        i += 1;

        // Expect mnemonic ident
        let mnemonic = tokens[i].to_string();
        i += 1;

        // Collect args until we hit => (tokenized as '=' then '>')
        let mut args = Vec::new();
        while i < tokens.len() {
            let s = tokens[i].to_string();
            // Stop at => ('=' then '>')
            if s == "=" && i + 1 < tokens.len() && tokens[i + 1].to_string() == ">" {
                i += 2; // skip both
                break;
            }
            // Stop at ';' (inline comment)
            if s == ";" {
                i += 1; // skip ;
                break;
            }
            args.push(s);
            i += 1;
        }
        // If we hit end without finding => or ;, this entry has no emit pattern

        // Skip the rest of this entry (emit pattern) until next hex literal
        while i < tokens.len() {
            let s = tokens[i].to_string();
            if s.starts_with("0x") && s.len() > 2
                && s[2..].chars().all(|c| c.is_ascii_hexdigit())
            {
                break;
            }
            i += 1;
        }

        entries.push(IsaEntry { opcode, mnemonic, args });
    }

    entries
}

#[proc_macro]
pub fn isa(input: TokenStream) -> TokenStream {
    let entries = tokenize_isat(input);

    if entries.is_empty() {
        panic!("isa! requires at least one instruction entry");
    }

    // ---- Build enum variants ----
    let enum_variants: Vec<_> = entries.iter().map(|entry| {
        let variant_name = syn::Ident::new(&mnemonic_to_variant(&entry.mnemonic), proc_macro2::Span::call_site());
        if entry.args.is_empty() {
            quote! { #variant_name }
        } else {
            let fields: Vec<_> = entry.args.iter().map(|arg_name| {
                let field_ident = syn::Ident::new(arg_name, proc_macro2::Span::call_site());
                let field_type_str = arg_rs_type(arg_name);
                let field_type: syn::Type = syn::parse_str(field_type_str).unwrap();
                quote! { #field_ident: #field_type }
            }).collect();
            quote! { #variant_name { #(#fields),* } }
        }
    }).collect();

    // ---- Build lower_op match arms ----
    let lower_arms: Vec<_> = entries.iter().map(|entry| {
        let opcode_val = entry.opcode as u8;
        let variant_name = syn::Ident::new(&mnemonic_to_variant(&entry.mnemonic), proc_macro2::Span::call_site());

        if entry.args.is_empty() {
            quote! {
                #opcode_val => Some(crate::isa::TirOp::#variant_name),
            }
        } else {
            let field_names: Vec<_> = entry.args.iter().map(|name| {
                syn::Ident::new(name, proc_macro2::Span::call_site())
            }).collect();
            let arg_indexed: Vec<_> = entry.args.iter().enumerate().map(|(i, name)| {
                arg_expr(i, name)
            }).collect();

            quote! {
                #opcode_val => {
                    let args = args;
                    Some(crate::isa::TirOp::#variant_name {
                        #(#field_names: #arg_indexed),*
                    })
                }
            }
        }
    }).collect();

    // ---- Build the full output ----
    let expanded = quote! {
        #[derive(Debug, Clone)]
        pub enum TirOp {
            #(#enum_variants),*
        }

        pub fn lower_op(op: u8, args: &[u64]) -> Option<TirOp> {
            match op {
                #(#lower_arms)*
                _ => None,
            }
        }
    };

    expanded.into()
}

#[cfg(test)]
mod tests {
    use crate::isa_parser;

    #[test]
    fn lib_calls_parser() {
        let entry = isa_parser::parse_isa_line(
            "0x0030 SET slot imm => movabs rax imm store_state slot rax",
        )
        .unwrap();
        assert_eq!(entry.opcode, 0x30);
        assert_eq!(entry.mnemonic, "SET");
    }

    #[test]
    fn arg_rs_type_mappings() {
        assert_eq!(super::arg_rs_type("hh"), "u8");
        assert_eq!(super::arg_rs_type("slot"), "u16");
        assert_eq!(super::arg_rs_type("imm"), "u64");
        assert_eq!(super::arg_rs_type("oo"), "i32");
    }

    #[test]
    fn mnemonic_to_variant_mappings() {
        assert_eq!(super::mnemonic_to_variant("SET"), "SetImm");
        assert_eq!(super::mnemonic_to_variant("RET"), "Ret");
        assert_eq!(super::mnemonic_to_variant("HANDLER"), "HandlerStart");
        assert_eq!(super::mnemonic_to_variant("JE"), "JeHh");
    }
}
