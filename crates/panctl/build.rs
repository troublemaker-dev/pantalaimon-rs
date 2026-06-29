use clap::{Arg, Command};
use std::path::PathBuf;

fn panctl_command() -> Command {
    let user_args = || {
        [
            Arg::new("pan_user").help("The pantalaimon session user (@alice:matrix.org)"),
            Arg::new("user_id").help("The target Matrix user ID"),
            Arg::new("device_id").help("The target device ID"),
        ]
    };

    Command::new("panctl")
        .version("0.11.0")
        .about("Control pantalaimon via D-Bus")
        .subcommand_required(true)
        .subcommand(Command::new("list-servers").about("List all configured homeserver proxies"))
        .subcommand(Command::new("list-users").about("List all tracked users (logged-in sessions)"))
        .subcommand(
            Command::new("list-devices")
                .about("List known devices for a Matrix user")
                .arg(Arg::new("pan_user").help("The pantalaimon session user (@alice:matrix.org)"))
                .arg(Arg::new("user_id").help("The Matrix user whose devices to list")),
        )
        .subcommand(
            Command::new("verify-device")
                .about("Mark a device as verified")
                .args(user_args()),
        )
        .subcommand(
            Command::new("unverify-device")
                .about("Mark a device as unverified")
                .args(user_args()),
        )
        .subcommand(
            Command::new("blacklist-device")
                .about("Blacklist a device (never trust, never encrypt to)")
                .args(user_args()),
        )
        .subcommand(
            Command::new("unblacklist-device")
                .about("Remove a device from the blacklist")
                .args(user_args()),
        )
        .subcommand(
            Command::new("start-verification")
                .about("Initiate SAS emoji verification with a device")
                .args(user_args()),
        )
        .subcommand(
            Command::new("accept-verification")
                .about("Accept an incoming SAS verification request")
                .args(user_args()),
        )
        .subcommand(
            Command::new("confirm-verification")
                .about("Confirm that the SAS emoji match")
                .args(user_args()),
        )
        .subcommand(
            Command::new("cancel-verification")
                .about("Cancel a SAS verification in progress")
                .args(user_args()),
        )
        .subcommand(
            Command::new("import-keys")
                .about("Import E2E key backup from a file")
                .arg(Arg::new("pan_user").help("The pantalaimon session user"))
                .arg(Arg::new("file_path").help("Path to the key backup file"))
                .arg(Arg::new("passphrase").help("Passphrase for the key backup")),
        )
        .subcommand(
            Command::new("export-keys")
                .about("Export E2E keys to a file")
                .arg(Arg::new("pan_user").help("The pantalaimon session user"))
                .arg(Arg::new("file_path").help("Path for the exported key file"))
                .arg(Arg::new("passphrase").help("Passphrase to encrypt the export")),
        )
        .subcommand(
            Command::new("send-anyways")
                .about("Send a blocked message despite unverified devices")
                .arg(Arg::new("pan_user").help("The pantalaimon session user"))
                .arg(Arg::new("room_id").help("The room ID of the blocked message")),
        )
        .subcommand(
            Command::new("cancel-sending")
                .about("Cancel a blocked message")
                .arg(Arg::new("pan_user").help("The pantalaimon session user"))
                .arg(Arg::new("room_id").help("The room ID of the blocked message")),
        )
        .subcommand(
            Command::new("continue-keyshare")
                .about("Forward a pending key-share request")
                .args(user_args()),
        )
        .subcommand(
            Command::new("cancel-keyshare")
                .about("Reject a pending key-share request")
                .args(user_args()),
        )
}

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let man_dir = out_dir.join("man");
    std::fs::create_dir_all(&man_dir).unwrap();

    let cmd = panctl_command();

    // Top-level page
    let man = clap_mangen::Man::new(cmd.clone());
    let mut buf = Vec::<u8>::new();
    man.render(&mut buf).unwrap();
    std::fs::write(man_dir.join("panctl.1"), buf).unwrap();

    // Per-subcommand pages: rename each so the file is panctl-<subcmd>.1
    for subcmd in cmd.get_subcommands() {
        let page_name = format!("panctl-{}", subcmd.get_name());
        // Box::leak is fine in a build script (process exits immediately after).
        let static_name: &'static str = Box::leak(page_name.clone().into_boxed_str());
        let man = clap_mangen::Man::new(subcmd.clone().name(static_name));
        let mut buf = Vec::<u8>::new();
        man.render(&mut buf).unwrap();
        std::fs::write(man_dir.join(format!("{page_name}.1")), buf).unwrap();
    }

    println!("cargo::warning=man pages written to {}", man_dir.display());
}
