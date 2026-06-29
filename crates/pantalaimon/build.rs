use clap::{Arg, ArgAction, Command};
use std::path::PathBuf;

fn pantalaimon_command() -> Command {
    Command::new("pantalaimon")
        .version("0.11.0")
        .about("E2E encryption-aware Matrix reverse proxy daemon")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Path to the config file (default: $XDG_CONFIG_HOME/pantalaimon/pantalaimon.conf)"),
        )
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .value_name("LEVEL")
                .value_parser(["error", "warning", "info", "debug"])
                .help("Override the log level from the config file"),
        )
        .arg(
            Arg::new("data-path")
                .long("data-path")
                .value_name("DIR")
                .help("Override the data directory (default: $XDG_DATA_HOME/pantalaimon)"),
        )
        .arg(
            Arg::new("debug-encryption")
                .long("debug-encryption")
                .action(ArgAction::SetTrue)
                .help("Enable verbose Olm/Megolm debug logging"),
        )
}

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let man_dir = out_dir.join("man");
    std::fs::create_dir_all(&man_dir).unwrap();

    let cmd = pantalaimon_command();
    let man = clap_mangen::Man::new(cmd);
    let mut buf = Vec::<u8>::new();
    man.render(&mut buf).unwrap();
    std::fs::write(man_dir.join("pantalaimon.1"), buf).unwrap();

    println!("cargo::warning=man page written to {}/pantalaimon.1", man_dir.display());
}
