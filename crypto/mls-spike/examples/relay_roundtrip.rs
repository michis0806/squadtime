//! Interactive synthetic ciphertext harness. No network access or persisted keys.
use std::io::{self, BufRead, Read, Write};

use squadtime_mls_spike::ApplicationReceiver;
#[path = "../support/mod.rs"]
mod support;
use support::{ApprovedDevices, Device};

const EVENT: &[u8] = br#"{"v":1,"type":"availability.set","eventId":"synthetic-relay-check","start":"2026-10-21T15:00:00Z","durationMinutes":60}"#;
const MAX_INPUT_BYTES: u64 = 1_048_576;

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
fn decode_hex(input: &str) -> Result<Vec<u8>, &'static str> {
    fn nibble(byte: u8) -> Result<u8, &'static str> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err("invalid relay encoding"),
        }
    }
    let input = input.trim_end_matches(['\r', '\n']);
    if input.is_empty() || !input.len().is_multiple_of(2) {
        return Err("invalid relay encoding");
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn run() -> Result<(), &'static str> {
    let alice = Device::new("synthetic-account-a/device-a");
    let bob = Device::new("synthetic-account-b/device-b");
    let approved = ApprovedDevices(vec![alice.identity.clone(), bob.identity.clone()]);
    let alice = alice.client(approved.clone());
    let bob = bob.client(approved);
    let mut group = alice
        .group_builder()
        .map_err(|_| "group creation failed")?
        .build()
        .map_err(|_| "group creation failed")?;
    let package = bob
        .generate_key_package_message(Default::default(), Default::default(), None)
        .map_err(|_| "key package creation failed")?;
    let commit = group
        .commit_builder()
        .add_member(package)
        .map_err(|_| "device approval failed")?
        .build()
        .map_err(|_| "device approval failed")?;
    group.apply_pending_commit().map_err(|_| "commit failed")?;
    let (recipient, _) = bob
        .join_group(None, &commit.welcome_messages[0], None)
        .map_err(|_| "join failed")?;
    let mut recipient = ApplicationReceiver::initialize(&bob, recipient)
        .map_err(|_| "receiver initialization failed")?;
    let encrypted = group
        .encrypt_application_message(EVENT, Default::default())
        .map_err(|_| "encryption failed")?;
    let ciphertext = encrypted.to_bytes().map_err(|_| "serialization failed")?;
    // The only outbound data is an encrypted MLS packet, followed by a status.
    let mut output = io::stdout().lock();
    writeln!(output, "{}", encode_hex(&ciphertext)).map_err(|_| "output failed")?;
    output.flush().map_err(|_| "output failed")?;
    let mut input = String::new();
    let size = io::stdin()
        .lock()
        .take(MAX_INPUT_BYTES + 1)
        .read_line(&mut input)
        .map_err(|_| "input failed")?;
    if size == 0 || size as u64 > MAX_INPUT_BYTES {
        return Err("invalid relay input length");
    }
    let received = decode_hex(&input)?;
    recipient
        .receive(&received, |event| {
            event.data() == EVENT && event.sender_index == group.current_member_index()
        })
        .map_err(|_| "MLS verification failed")?;
    writeln!(output, "verified").map_err(|_| "output failed")?;
    output.flush().map_err(|_| "output failed")?;
    Ok(())
}

fn main() {
    if let Err(reason) = run() {
        eprintln!("{reason}");
        std::process::exit(1);
    }
}
