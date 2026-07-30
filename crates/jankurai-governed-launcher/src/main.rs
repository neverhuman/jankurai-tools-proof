use std::ffi::OsString;

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<OsString>>();
    if let Err(error) = jankurai_governed_launcher::verify_and_exec(arguments) {
        eprintln!("governed Jankurai launch refused: {error}");
        std::process::exit(126);
    }
}
