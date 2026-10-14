use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{DirEntry, File};
use std::io::Write;
use std::path::Path;

use heck::ToSnakeCase;

fn main() -> Result<(), Box<dyn Error>> {
    let out_dir = std::env::var("OUT_DIR")?;
    let mut config_vars_file = File::create(Path::new(&out_dir).join("config_vars.rs"))?;

    let processors_root = "ghidra/Ghidra/Processors";
    let mut sla_data = Vec::new();
    let mut pspec_data = Vec::new();
    let mut cspec_data = Vec::new();
    // `sla-<stem>` features select single languages (`CARGO_FEATURE_SLA_<VAR>`).
    let mut unmatched: BTreeSet<String> = std::env::vars_os()
        .filter_map(|(key, _)| key.into_string().ok())
        .filter(|key| key.starts_with("CARGO_FEATURE_SLA_"))
        .collect();

    for processor_dir in sorted_entries(Path::new(processors_root))? {
        let processor_name = processor_dir.file_name().to_str().unwrap().to_owned();
        let feature_env_name = processor_name.to_uppercase().replace("-", "_");
        // A processor feature selects all of its languages; `sla-<stem>` selects one.
        let processor_selected = std::env::var(format!("CARGO_FEATURE_{feature_env_name}")).is_ok();
        let lang_entries = sorted_entries(&processor_dir.path().join("data/languages"))?;
        let selected = |entry: &DirEntry| {
            let path = entry.path();
            path.extension().is_some_and(|ext| ext == "slaspec")
                && (processor_selected
                    || feature_var(&path).is_some_and(|key| std::env::var(key).is_ok()))
        };
        // A processor with no selected language emits nothing.
        if lang_entries.iter().any(selected) {
            // pub mod NAME {
            let mod_name = format!(
                "processor_{name}",
                name = processor_name.replace("-", "_").to_snake_case()
            );

            writeln!(
                &mut config_vars_file,
                r#"/// Configurations for the processor `{processor_name}`"#
            )?;
            writeln!(&mut config_vars_file, r#"pub mod {mod_name} {{"#)?;
            // Every file by its name, so a language definition's references resolve.
            let mut module_files = Vec::new();
            let mut module_slas = Vec::new();

            for lang_entry in &lang_entries {
                let file_stem = lang_entry.path().file_stem().unwrap().display().to_string();
                let var_name = file_stem.replace("-", "_").replace(".", "_").to_uppercase();

                match lang_entry.path().extension() {
                    Some(ext) if ext == "slaspec" => {
                        if !selected(lang_entry) {
                            continue;
                        }
                        unmatched.remove(&feature_var(&lang_entry.path()).unwrap_or_default());
                        let output_path = Path::new(&out_dir).join(format!("{file_stem}.sla"));
                        let var_name = format!("SLA_{var_name}");

                        let mut compiler = sleigh_compiler::SleighCompiler::default();
                        compiler.compile(lang_entry.path(), &output_path)?;
                        writeln!(
                            &mut config_vars_file,
                            r##"pub static {var_name}: &[u8] = include_bytes!(r#"{path}"#);"##,
                            path = output_path.display()
                        )?;

                        sla_data.push(format!("{mod_name}::{var_name}"));
                        module_slas.push((format!("{file_stem}.sla"), var_name));
                    }
                    Some(ext) if ext == "pspec" => {
                        // File extension is pspec
                        let var_name = format!("PSPEC_{var_name}");
                        let output_path = Path::new(&out_dir).join(lang_entry.file_name());
                        std::fs::copy(lang_entry.path(), &output_path)?;

                        writeln!(
                            &mut config_vars_file,
                            r##"pub static {var_name}: &str = include_str!(r#"{path}"#);"##,
                            path = output_path.display()
                        )?;

                        pspec_data.push(format!("{mod_name}::{var_name}"));
                        module_files.push((lang_entry.file_name().display().to_string(), var_name));
                    }
                    Some(ext) if ext == "cspec" => {
                        // File extension is cspec. It names the stack pointer
                        // and the prototype models, which nothing else carries.
                        let var_name = format!("CSPEC_{var_name}");
                        let output_path = Path::new(&out_dir).join(lang_entry.file_name());
                        std::fs::copy(lang_entry.path(), &output_path)?;

                        writeln!(
                            &mut config_vars_file,
                            r##"pub static {var_name}: &str = include_str!(r#"{path}"#);"##,
                            path = output_path.display()
                        )?;

                        cspec_data.push(format!("{mod_name}::{var_name}"));
                        module_files.push((lang_entry.file_name().display().to_string(), var_name));
                    }

                    // A DWARF register numbering or the language definitions.
                    Some(ext) if ext == "dwarf" || ext == "ldefs" => {
                        let prefix = ext.to_str().unwrap().to_uppercase();
                        let var_name = format!("{prefix}_{var_name}");
                        let output_path = Path::new(&out_dir).join(lang_entry.file_name());
                        std::fs::copy(lang_entry.path(), &output_path)?;
                        writeln!(
                            &mut config_vars_file,
                            r##"pub static {var_name}: &str = include_str!(r#"{path}"#);"##,
                            path = output_path.display()
                        )?;
                        module_files.push((lang_entry.file_name().display().to_string(), var_name));
                    }

                    // No match, nothing to do
                    _ => (),
                } // End match
            } // End language directory for loop
            module_files.sort();
            module_slas.sort();
            writeln!(
                &mut config_vars_file,
                "pub static FILES: &[(&str, &str)] = &["
            )?;
            for (name, var) in &module_files {
                writeln!(&mut config_vars_file, r##"(r#"{name}"#, {var}),"##)?;
            }
            writeln!(&mut config_vars_file, "];")?;
            writeln!(
                &mut config_vars_file,
                "pub static SLAS: &[(&str, &[u8])] = &["
            )?;
            for (name, var) in &module_slas {
                writeln!(&mut config_vars_file, r##"(r#"{name}"#, {var}),"##)?;
            }
            writeln!(&mut config_vars_file, "];")?;
            writeln!(&mut config_vars_file, r#"}}"#)?;
        } // End selected-language check
    } // End processor directory for loop
    if let Some(feature) = unmatched.first() {
        return Err(format!("{feature} names no .slaspec under {processors_root}").into());
    }

    writeln!(
        &mut config_vars_file,
        r##"pub static SLA_DATA: [(&str, &[u8]); {len}] = ["##,
        len = sla_data.len()
    )?;
    for entry in &sla_data {
        writeln!(&mut config_vars_file, r##"(r#"{entry}"#, &{entry}),"##)?;
    }
    writeln!(&mut config_vars_file, r##"];"##)?;

    writeln!(
        &mut config_vars_file,
        r##"pub static PSPEC_DATA: [(&str, &str); {len}] = ["##,
        len = pspec_data.len()
    )?;
    for entry in &pspec_data {
        writeln!(&mut config_vars_file, r##"(r#"{entry}"#, &{entry}),"##)?;
    }
    writeln!(&mut config_vars_file, r##"];"##)?;

    writeln!(
        &mut config_vars_file,
        r##"pub static CSPEC_DATA: [(&str, &str); {len}] = ["##,
        len = cspec_data.len()
    )?;
    for entry in &cspec_data {
        writeln!(&mut config_vars_file, r##"(r#"{entry}"#, &{entry}),"##)?;
    }
    writeln!(&mut config_vars_file, r##"];"##)?;

    Ok(())
}

/// A directory's entries in name order, so the generated tables do not follow the file system's.
fn sorted_entries(dir: &Path) -> Result<Vec<DirEntry>, Box<dyn Error>> {
    let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(DirEntry::file_name);
    Ok(entries)
}

/// The feature variable that selects a `.slaspec`: `x86-64.slaspec` is `sla-x86-64`.
fn feature_var(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    Some(format!(
        "CARGO_FEATURE_SLA_{}",
        stem.replace(['-', '.'], "_").to_uppercase()
    ))
}
