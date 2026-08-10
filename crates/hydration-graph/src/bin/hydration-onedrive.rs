//! Minimal OneDrive daemon entry point. Device-code enrollment remains a separate step.

use hydration_client::daemon_loop::{self, Config};
use hydration_graph::auth::AuthConfig;
use hydration_graph::{DriveId, DriveScope, GraphAccess, TagSource};
use std::io;
use std::path::PathBuf;
use std::time::Duration;

fn value(name: &str) -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == name {
            return args.next();
        }
    }
    None
}

fn required(name: &str) -> String {
    value(name).unwrap_or_else(|| {
        eprintln!("hydration-onedrive: missing {name}");
        std::process::exit(2)
    })
}

fn main() -> io::Result<()> {
    let mount = PathBuf::from(required("--mount"));
    let state = PathBuf::from(required("--state-dir"));
    let drive = DriveId::parse(&required("--drive-id"))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid --drive-id"))?;
    let client_id = required("--client-id");
    let credential = value("--credential")
        .map(PathBuf::from)
        .unwrap_or_else(|| state.join("refresh-token"));
    let socket = value("--socket")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/hydration-onedrive.sock"));

    let auth =
        AuthConfig::public_client(client_id).with_scopes(["Files.ReadWrite.All", "User.Read"]);
    let access = GraphAccess::new(
        DriveScope::primary(drive),
        &mount,
        &state,
        credential,
        auth,
        TagSource::CTag,
    );
    daemon_loop::run(
        Config {
            mount,
            socket,
            debounce: Duration::from_secs(900),
        },
        access,
    )
}
