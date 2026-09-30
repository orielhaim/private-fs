use std::{env, fs, path::PathBuf};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let check = match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [arg] if arg == "--check" => true,
        _ => return Err("usage: private-fs-windows-bindings [--check]".into()),
    };
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bindings = root.join("src/windows/bindings.rs");
    let output = if check {
        let target = root.join("target");
        fs::create_dir_all(&target)?;
        target.join(format!(
            "windows-bindings-{}-{}.rs",
            std::env::consts::OS,
            std::process::id()
        ))
    } else {
        bindings.clone()
    };
    windows_bindgen::builder()
        .input_default()
        .flat()
        .sys()
        .filter_file(root.join("tools/windows-bindings/apis.txt"))
        .output(&output)
        .write();
    if check {
        let expected = fs::read(bindings)?;
        let generated = fs::read(&output)?;
        fs::remove_file(output)?;
        if expected != generated {
            return Err("bindings are stale; run cargo run -p private-fs-windows-bindings".into());
        }
    }
    Ok(())
}
