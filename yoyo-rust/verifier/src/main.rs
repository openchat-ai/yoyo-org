//! yoyo: byte-level visualization of yoyo .ty source → x86 machine code
//!
//! Subcommands:
//!   decode <file.ty>                     Three-column SOURCE / TIR / X86 view
//!   diff <a.exe> <b.exe> [--source=...]  Byte-level diff with optional .ty annotation
//!
//! See docs/emit-rules.md in the yoyo-ide repo for the yoyo opcode → x86 byte
//! mapping this tool implements.

use std::env;
use std::fs;
use std::process;

mod ty_parser;
mod tir;
mod emit;
mod disasm;
use platform::Platform; // bring trait methods into scope
mod render;
mod pe_read;
mod elf_read;
mod diff;
mod diff_source;
mod linscan;
mod pe_link;
mod types;
mod primitives;
mod isa;
mod fixup;
mod platform;
mod ddc;
mod chain_log;
mod trust_root;
mod variable;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        process::exit(2);
    }
    let subcommand = &args[1];
    match subcommand.as_str() {
        "decode" => run_decode(&args[2..]),
        "diff" => run_diff(&args[2..]),
        "scan-relocs" => run_scan_relocs(&args[2..]),
        "link" => run_link(&args[2..]),
        "resolve-vars" => run_resolve_vars(&args[2..]),
        "ddc" => run_ddc(&args[2..]),
        "-h" | "--help" | "help" => {
            print_usage();
        }
        _ => {
            // Backward compatibility: bare path → decode
            run_decode(&args[1..]);
        }
    }
}

fn print_usage() {
    eprintln!("usage:");
    eprintln!("  yoyo decode <file.ty>");
    eprintln!("  yoyo diff <a.exe> <b.exe> [--source=<file.ty>]");
    eprintln!("  yoyo scan-relocs <file.exe|elf> [--from=<hex>] [--list]");
    eprintln!("  yoyo resolve-vars <file.ty>     Show variable definitions");
    eprintln!("  yoyo link <file.ty> <out> [--platform win32|linux|stub]");
    eprintln!("                                Emit + link into PE/ELF template");
    eprintln!("  yoyo ddc hash <file>            Compute SHA-256");
    eprintln!("  yoyo ddc verify <f> <hash>      Verify file hash");
    eprintln!("  yoyo ddc chain <log>            Show compilation chain log");
    eprintln!("  yoyo <file.ty>          (backward compat: decode)");
}

fn run_decode(args: &[String]) {
    if args.is_empty() {
        eprintln!("decode: need a .ty file path");
        process::exit(2);
    }
    let path = &args[0];
    let src = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", path, e);
            process::exit(1);
        }
    };

    // Extract variable definitions, then parse with vars
    let vars = ty_parser::extract_var_defs(&src);
    let source = ty_parser::parse_with_vars(&src, &vars);

    // Layer 2: lower to TIR
    let tir_program = tir::lower(&source);

    // Layer 3: emit x86 bytes from TIR (with chunks for accurate disasm alignment)
    let (x86_bytes, chunks) = emit::emit_with_chunks(&tir_program);

    // Disassemble the x86 bytes for human-readable output
    let disasm_program = disasm::disasm(&x86_bytes);

    // Render three-column output
    let text = render::render_three_column(&source, &tir_program, &disasm_program, &chunks);
    print!("{}", text);

    eprintln!("\n# summary: {} source lines -> {} TIR ops -> {} x86 bytes",
        source.len(), tir_program.len(), x86_bytes.len());
}

fn run_diff(args: &[String]) {
    if args.len() < 2 {
        eprintln!("diff: need two .exe/.elf paths");
        process::exit(2);
    }

    // Parse: <a.exe> <b.exe> [--source=foo.ty] [--skip-startup=N]
    let paths: [&str; 2] = [&args[0], &args[1]];
    let mut source_file: Option<&str> = None;
    let mut skip_startup: Option<u64> = None;  // None = auto-detect
    for arg in &args[2..] {
        if arg.starts_with("--source=") {
            source_file = Some(&arg[9..]);
        } else if arg.starts_with("--skip-startup=") {
            skip_startup = Some(arg[15..].parse().unwrap_or(0xA1));
        }
    }

    let path_a = paths[0];
    let path_b = paths[1];

    let bytes_a = match fs::read(path_a) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", path_a, e);
            process::exit(1);
        }
    };
    let bytes_b = match fs::read(path_b) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", path_b, e);
            process::exit(1);
        }
    };

    // Extract .text section from each. Try PE first, then ELF.
    let text_a_section = read_text_section_auto(&bytes_a);
    let text_b_section = read_text_section_auto(&bytes_b);

    // Per-binary skip detection (different templates have different startup lengths)
    let detect_skip = |bytes: &[u8], section: &pe_read::TextSection| -> u64 {
        let slice = extract_text_slice(bytes, section);
        if let Some(slice) = slice {
            if let Some(off) = pe_read::find_user_code_offset(&slice) {
                return off;
            }
            if let Some(off) = elf_read::find_user_code_offset(&slice) {
                return off;
            }
        }
        0x40
    };
    let skip_a = skip_startup.unwrap_or_else(|| {
        text_a_section.as_ref().map(|s| detect_skip(&bytes_a, s)).unwrap_or(0x40)
    });
    let skip_b = skip_startup.unwrap_or_else(|| {
        text_b_section.as_ref().map(|s| detect_skip(&bytes_b, s)).unwrap_or(0x40)
    });

    let text_a = match text_a_section {
        Some(s) => extract_user_code(&bytes_a, &s, skip_a),
        None => {
            eprintln!("warning: {}: .text section not found, falling back to whole-file diff", path_a);
            bytes_a.clone()
        }
    };
    let text_b = match text_b_section {
        Some(s) => extract_user_code(&bytes_b, &s, skip_b),
        None => {
            eprintln!("warning: {}: .text section not found, falling back to whole-file diff", path_b);
            bytes_b.clone()
        }
    };

    eprintln!("# startup skipped: a={} bytes, b={} bytes (per-binary auto-detect)", skip_a, skip_b);

    eprintln!("# diff: {} vs {}", path_a, path_b);
    eprintln!("# a.size = {}, b.size = {}", text_a.len(), text_b.len());

    // If --source is provided, annotate the diff with source line numbers
    if let Some(src_path) = source_file {
        run_annotated_diff(&text_a, &text_b, src_path, skip_a);
        return;
    }

    // Otherwise, plain byte diff
    let entries = diff::diff(&text_a, &text_b);
    if entries.is_empty() {
        eprintln!("# .text sections are byte-identical ✓");
        return;
    }
    eprintln!("# {} byte differences found (showing first 30):", entries.len());
    println!();
    println!("{:<8}  {:<10}  {:<10}  {}", "offset", "a", "b", "context");
    for e in entries.iter().take(30) {
        println!("{:<8}  0x{:02X}      0x{:02X}      @ file offset 0x{:04X}",
            e.offset, e.byte_a, e.byte_b, e.offset);
    }
    if entries.len() > 30 {
        println!("... ({} more differences omitted)", entries.len() - 30);
    }
}

/// Run diff with source-line annotation (M3).
fn run_annotated_diff(
    text_a: &[u8],
    text_b: &[u8],
    source_path: &str,
    _skip_startup: u64,
) {
    let _ = text_a;
    let _ = text_b;
    let _ = source_path;
    let _ = _skip_startup;
    let src = match fs::read_to_string(source_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read source file {}: {}", source_path, e);
            process::exit(1);
        }
    };
    let vars = ty_parser::extract_var_defs(&src);
    let source = ty_parser::parse_with_vars(&src, &vars);
    let tir_program = tir::lower(&source);
    // Use the UNFIXED emit so call/jmp placeholders are 0x00 00 00 00.
    // The actual .exe has correct rel32. Searching for the unfixed byte
    // pattern in the .exe (where 0x00 00 00 00 means the same thing) lets
    // us align to the user code region despite yoyo's H_00 wrapper.
    let (expected_bytes, chunks) = emit::emit_with_chunks_unfixed(&tir_program);

    // Sanity check: expected byte length should match .text - startup
    eprintln!("# source: {} ({} lines, {} expected bytes)",
        source_path, source.len(), expected_bytes.len());
    eprintln!("# emit chunks: {}", chunks.len());

    // Align user code streams: search for expected_bytes prefix in text_a
    // to find where yoyo's H_00 wrapper ends. Use enough bytes to
    // disambiguate but not too large.
    // Align user code streams. The H_00 wrapper on Linux contains a
    // `mov rax, 60; syscall` (sys_exit) pattern. We distinguish the
    // wrapper's mov rax,60 from the user code's mov rax,<imm> by using
    // the FULL 10-byte mov rax, imm64 sequence of the first SET.
    //
    // We assume the first SET's imm is 0 (most common case; the .ty
    // source has it but we don't trust mod.ty). The pattern is
    // `48 B8 00 00 00 00 00 00 00 00` (mov rax, 0).
    let prefix_len = if expected_bytes.is_empty() {
        0
    } else {
        // 10-byte mov rax, 0 pattern (the first SET's mov rax, imm64 with
        // imm=0 — the most common case). The first match in text_a marks
        // the end of the H_00 wrapper.
        let pattern: Vec<u8> = vec![0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0];
        find_prefix_offset(text_a, &pattern).unwrap_or(0)
    };
    eprintln!("# H_00 wrapper detected: {} bytes (auto-aligned via first SET's mov rax, 0)", prefix_len);

    // Adjust chunks: subtract 5 so chunks[0] (call H_01, byte_offset 0)
    // aligns with text_a_aligned[0]. HandlerStart is 0 bytes and NOT in
    // the chunks list (emit uses `continue` to skip it). So no skip
    // needed — just shift all chunk byte_offsets by -5.
    let aligned_chunks: Vec<_> = chunks.iter()
        .map(|c| emit::X86Chunk {
            byte_offset: c.byte_offset.saturating_sub(5),
            bytes: c.bytes.clone(),
            tir_source_line: c.tir_source_line,
        })
        .collect();

    let text_a_aligned = &text_a[prefix_len as usize..];
    let text_b_aligned = &text_b[prefix_len as usize..];

    let diffs = diff_source::annotated_diff(text_a_aligned, text_b_aligned, &aligned_chunks, &source);

    if diffs.is_empty() {
        eprintln!("# .text sections are byte-identical ✓");
        return;
    }

    eprintln!("# {} byte differences found (showing first 30):", diffs.len());
    println!();
    println!("{:<10}  {:<8}  {:<10}  {:<10}  {}",
        "line", "offset", "a", "b", "context");
    for d in diffs.iter().take(30) {
        println!("{:<10}  {:<8}  0x{:02X}      0x{:02X}      {}",
            if d.source_line > 0 {
                format!("Line {}", d.source_line)
            } else {
                "-".to_string()
            },
            d.diff.offset, d.diff.byte_a, d.diff.byte_b, d.source_text);
    }
    if diffs.len() > 30 {
        println!("... ({} more differences omitted)", diffs.len() - 30);
    }
}

/// Skip the startup blob at the start of the .text section. yoyo's startup
/// blob is the first N bytes of .text. The exact length is determined by the
/// embedded startup code (see yoyo's pe-builder.js). We use a fixed skip
/// value (--skip-startup, default auto-detect) which is a reasonable estimate.
///
/// For more accurate alignment, future work: parse the startup and locate
/// the first handler (H_00) precisely.
fn extract_user_code(_file: &[u8], section: &pe_read::TextSection, skip: u64) -> Vec<u8> {
    let start = section.file_offset as usize;
    let end = (section.file_offset + section.size) as usize;
    if start >= end || end > _file.len() {
        return Vec::new();
    }
    let skip = std::cmp::min(skip as usize, _file.len() - start);
    let user_start = start + skip;
    _file[user_start..end].to_vec()
}

/// Extract the .text section as a contiguous byte slice (no skip).
/// Used for pattern detection (E8 + C3 C3).
fn extract_text_slice(file: &[u8], section: &pe_read::TextSection) -> Option<Vec<u8>> {
    let start = section.file_offset as usize;
    let end = (section.file_offset + section.size) as usize;
    if start >= end || end > file.len() {
        return None;
    }
    Some(file[start..end].to_vec())
}

/// Find the offset in `text` where `prefix` first appears.
/// Returns None if not found. Used to align yoyo's emitted bytes
/// with the user code in the actual .text section (skipping yoyo's H_00
/// wrapper that wraps H_01).
fn find_prefix_offset(text: &[u8], prefix: &[u8]) -> Option<u64> {
    if prefix.is_empty() || text.len() < prefix.len() {
        return if prefix.is_empty() { Some(0) } else { None };
    }
    for i in 0..=(text.len() - prefix.len()) {
        if &text[i..i + prefix.len()] == prefix {
            return Some(i as u64);
        }
    }
    None
}

/// M5: relocation-safety scanner. Linearly disassembles a yoyo .exe/.elf's
/// .text and reports (a) genuine rel32 relocation sites and (b) "trap bytes"
/// — stray E8/E9 bytes a naive `relocateSlice` would wrongly relocate.
fn run_scan_relocs(args: &[String]) {
    if args.is_empty() {
        eprintln!("scan-relocs: need a .exe/.elf path");
        process::exit(2);
    }
    let path = &args[0];
    let mut from: Option<usize> = None; // offset within .text to start; None = whole section
    let mut list = false;
    for arg in &args[1..] {
        if let Some(v) = arg.strip_prefix("--from=") {
            let v = v.trim_start_matches("0x");
            from = usize::from_str_radix(v, 16).ok();
        } else if arg == "--list" {
            list = true;
        }
    }

    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", path, e);
            process::exit(1);
        }
    };

    let section = match read_text_section_auto(&bytes) {
        Some(s) => s,
        None => {
            eprintln!("error: {}: .text section not found (not a yoyo PE/ELF?)", path);
            process::exit(1);
        }
    };
    let slice = match extract_text_slice(&bytes, &section) {
        Some(s) => s,
        None => {
            eprintln!("error: {}: .text section out of file bounds", path);
            process::exit(1);
        }
    };

    // Default: scan the whole .text (startup blob included, since relocateSlice
    // corruption is observed there too). --from=<hex> restricts the start.
    let start = from.unwrap_or(0).min(slice.len());
    let code = &slice[start..];

    let report = linscan::scan(code);

    eprintln!("# scan-relocs: {}", path);
    eprintln!("# .text file offset 0x{:X}, size {} bytes", section.file_offset, section.size);
    eprintln!("# scanning from .text+0x{:X} ({} bytes)", start, code.len());
    eprintln!("# instructions decoded: {}", report.instrs.len());
    if report.unknown_count > 0 {
        eprintln!(
            "# WARNING: {} undecodable byte(s) — linear sweep may have desynced; \
             results below are best-effort",
            report.unknown_count
        );
        let shown: Vec<String> = report
            .unknown_offsets
            .iter()
            .take(20)
            .map(|o| format!("0x{:X}", start + o))
            .collect();
        eprintln!("# undecodable at .text+: {}", shown.join(", "));
    }
    eprintln!("# genuine rel32 relocation sites: {}", report.reloc_sites.len());
    eprintln!("# naive-relocator trap bytes (E8/E9 in immediates/disps): {}", report.traps.len());

    // Break traps down by owning instruction kind — this decides whether the
    // proposed "skip 8 bytes after movabs (48 B8-BF)" fix is sufficient.
    let mut in_movabs = 0usize;
    let mut in_lea_rip = 0usize;
    let mut in_call_rip = 0usize;
    let mut in_jmp_rip = 0usize;
    let mut in_reljcc = 0usize;
    let mut in_other = 0usize;
    for t in &report.traps {
        match t.owner_kind {
            linscan::Kind::Movabs => in_movabs += 1,
            linscan::Kind::LeaRip => in_lea_rip += 1,
            linscan::Kind::CallRip => in_call_rip += 1,
            linscan::Kind::JmpRip => in_jmp_rip += 1,
            linscan::Kind::RelJcc => in_reljcc += 1,
            _ => in_other += 1,
        }
    }

    if !report.traps.is_empty() {
        println!();
        println!("TRAP BYTES (a naive E8/E9 byte-scan would corrupt these):");
        println!("{:<12}  {:<6}  {:<16}  {}", "text+off", "byte", "owning instr", "owner @");
        for t in report.traps.iter().take(40) {
            println!(
                "0x{:<10X}  0x{:02X}    {:<16}  0x{:X}",
                start + t.offset,
                t.byte,
                linscan::kind_name(t.owner_kind),
                start + t.owner_offset,
            );
        }
        if report.traps.len() > 40 {
            println!("... ({} more traps omitted)", report.traps.len() - 40);
        }

        println!();
        println!("TRAP BREAKDOWN by owning instruction:");
        println!("  movabs imm64 : {}", in_movabs);
        println!("  lea [rip+d32]: {}", in_lea_rip);
        println!("  call [rip+d32]: {}", in_call_rip);
        println!("  jmp [rip+d32]: {}", in_jmp_rip);
        println!("  jcc rel32    : {}", in_reljcc);
        println!("  other        : {}", in_other);

        println!();
        let non_movabs = report.traps.len() - in_movabs;
        if non_movabs == 0 {
            println!(
                "VERDICT: all {} traps live inside movabs immediates. The proposed fix\n\
                 (skip 8 bytes after 48 B8-BF) WOULD eliminate every trap.",
                report.traps.len()
            );
        } else {
            println!(
                "VERDICT: {} of {} traps are NOT inside movabs (lea_rip/call_rip/disp).\n\
                 The movabs-skip fix alone is INSUFFICIENT — relocateSlice must also\n\
                 skip RIP-relative disp32 and rel32 displacement fields.",
                non_movabs, report.traps.len()
            );
        }
    } else {
        println!();
        println!("VERDICT: no trap bytes — a naive E8/E9 byte-scan is safe on this .text.");
    }

    if list {
        println!();
        println!("RELOCATION SITES (genuine rel32 branches):");
        println!("{:<12}  {:<12}  {:<12}  {}", "text+off", "kind", "rel32", "target(text+off)");
        for s in &report.reloc_sites {
            let rel = s.rel32.unwrap_or(0);
            let rel_off = s.rel32_off.unwrap_or(0);
            let target = (start as i64 + s.offset as i64 + s.len as i64 + rel as i64) as i64;
            println!(
                "0x{:<10X}  {:<12}  {:<12}  0x{:X}",
                start + rel_off,
                linscan::kind_name(s.kind),
                rel,
                target,
            );
        }
    }
}

/// Detect the file format (PE or ELF) and extract the .text section's
/// file offset and size. Returns None if neither format is recognized.
fn read_text_section_auto(file: &[u8]) -> Option<pe_read::TextSection> {
    // Try PE first
    if let Ok(sec) = pe_read::read_text_section(file) {
        return Some(sec);
    }
    // Try ELF
    if let Ok(sec) = elf_read::read_text_section(file) {
        return Some(sec);
    }
    None
}

/// Phase 3.A: read .ty, emit x64 bytes, patch into PE/ELF template, write output.
/// Supports --platform win32|linux|stub (default win32).
fn run_link(args: &[String]) {
    if args.is_empty() {
        eprintln!("link: need <file.ty> <out.exe> [--platform win32|linux|stub]");
        process::exit(2);
    }
    let ty_path = &args[0];
    let mut out_path = std::path::Path::new("output.exe");
    let mut platform_name = "win32";

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            a if a.starts_with("--platform=") => {
                platform_name = a.trim_start_matches("--platform=");
            }
            a if a == "--platform" => {
                i += 1;
                if i < args.len() { platform_name = &args[i]; }
            }
            a if !a.starts_with('-') => {
                out_path = std::path::Path::new(a);
            }
            _ => {}
        }
        i += 1;
    }

    let platform: platform::PlatformKind = match platform_name {
        "win32" => platform::PlatformKind::Win32,
        "linux" => platform::PlatformKind::Linux,
        "stub" => platform::PlatformKind::Stub,
        _ => {
            eprintln!("link: unknown platform '{}' (use win32, linux, or stub)", platform_name);
            process::exit(2);
        }
    };

    let src = match fs::read_to_string(ty_path) {
        Ok(s) => s,
        Err(e) => { eprintln!("error: cannot read {}: {}", ty_path, e); process::exit(1); }
    };
    let vars = ty_parser::extract_var_defs(&src);
    let source = ty_parser::parse_with_vars(&src, &vars);
    let tir = tir::lower(&source);
    let handler_code = emit::emit_on(&tir, platform);
    let startup_blob = platform.startup_blob();
    eprintln!(
        "link: {} source lines -> {} TIR ops -> {} x64 bytes + {} startup = {} total (platform={})",
        source.len(),
        tir.len(),
        handler_code.len(),
        startup_blob.len(),
        handler_code.len() + startup_blob.len(),
        platform.name(),
    );

    pe_link::link(startup_blob, &handler_code, out_path).unwrap_or_else(|e| {
        eprintln!("link error: {}", e);
        process::exit(1);
    });
    eprintln!("link: wrote {} bytes to {}", out_path.display(),
        std::fs::metadata(out_path).map(|m| m.len()).unwrap_or(0));
}

/// Show variable definitions from a .ty file.
fn run_resolve_vars(args: &[String]) {
    if args.is_empty() {
        eprintln!("resolve-vars: need a .ty file path");
        process::exit(2);
    }
    let path = &args[0];
    let src = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => { eprintln!("error: cannot read {}: {}", path, e); process::exit(1); }
    };
    let vars = ty_parser::extract_var_defs(&src);
    let mut count = 0;
    for (name, val) in vars.iter() {
        println!("{:<16} → 0x{:02X} ({})", name, val, val);
        count += 1;
    }
    if count == 0 {
        eprintln!("(no variable definitions found in {})", path);
    }
}

/// DDC subcommands: verify, hash, chain, trust-root
fn run_ddc(args: &[String]) {
    if args.is_empty() {
        eprintln!("ddc subcommands:");
        eprintln!("  hash <file>              Compute SHA-256");
        eprintln!("  verify <file> <expected>  Verify file hash");
        eprintln!("  chain <log> [--last=N]    Show chain log");
        eprintln!("  trust-root init <seed>    Create trust root from seed compiler");
        eprintln!("  trust-root check <root> <compiler>  Verify compiler against trust root");
        process::exit(2);
    }
    match args[0].as_str() {
        "hash" => {
            if args.len() < 2 {
                eprintln!("hash: need a file path"); process::exit(2);
            }
            match ddc::sha256_file(&args[1]) {
                Ok(h) => println!("{h}"),
                Err(e) => { eprintln!("error: {e}"); process::exit(1); }
            }
        }
        "verify" => {
            if args.len() < 3 {
                eprintln!("verify: need <file> <expected_hash>"); process::exit(2);
            }
            match ddc::verify(&args[1], &args[2], 0) {
                Ok(r) => {
                    println!("Computed: {}", r.computed_hash);
                    println!("Expected: {}", r.expected_hash);
                    println!("Verdict: {}", if r.pass { "PASS" } else { "FAIL" });
                }
                Err(e) => { eprintln!("error: {e}"); process::exit(1); }
            }
        }
        "chain" => {
            if args.len() < 2 {
                eprintln!("chain: need <log.jsonl> [--last=N]"); process::exit(2);
            }
            let log_path = &args[1];
            let n = args.iter()
                .find_map(|a| a.strip_prefix("--last="))
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(usize::MAX);
            match chain_log::last_entries(log_path, n) {
                Ok(entries) => {
                    if entries.is_empty() {
                        eprintln!("(no chain entries)");
                    }
                    for (i, e) in entries.iter().enumerate() {
                        println!("--- Entry {} ---", i + 1);
                        println!("  timestamp:    {}", e.timestamp);
                        println!("  compiler:     {}", e.compiler_id);
                        println!("  input:        {}", e.input_path);
                        println!("  output:       {}", e.output_path);
                        println!("  input_sha:    {}", e.input_sha);
                        println!("  output_sha:   {}", e.output_sha);
                    }
                }
                Err(e) => { eprintln!("error: {e}"); process::exit(1); }
            }
        }
        "trust-root" => {
            if args.len() < 2 {
                eprintln!("trust-root: need subcommand (init|check)");
                process::exit(2);
            }
            match args[1].as_str() {
                "init" => {
                    if args.len() < 3 {
                        eprintln!("trust-root init: need <seed_path> [--out=<root.json>]");
                        process::exit(2);
                    }
                    let seed_path = &args[2];
                    let out = args.iter()
                        .find_map(|a| a.strip_prefix("--out="))
                        .unwrap_or("trust-root.json");
                    match trust_root::from_seed(seed_path) {
                        Ok(root) => {
                            trust_root::save(out, &root).unwrap_or_else(|e| {
                                eprintln!("error: {e}"); process::exit(1);
                            });
                            println!("Trust root written to {out}");
                            println!("  hash: {}", root.seed_compiler_hash);
                            println!("  label: {}", root.label);
                        }
                        Err(e) => { eprintln!("error: {e}"); process::exit(1); }
                    }
                }
                "check" => {
                    if args.len() < 4 {
                        eprintln!("trust-root check: need <root.json> <compiler_path>");
                        process::exit(2);
                    }
                    match trust_root::verify_report(&args[2], &args[3]) {
                        Ok(report) => println!("{report}"),
                        Err(e) => { eprintln!("error: {e}"); process::exit(1); }
                    }
                }
                _ => {
                    eprintln!("unknown trust-root subcommand: {}", args[1]);
                    process::exit(2);
                }
            }
        }
        _ => {
            eprintln!("unknown ddc subcommand: {}", args[0]);
            process::exit(2);
        }
    }
}