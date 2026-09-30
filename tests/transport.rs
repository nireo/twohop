mod common;

use common::*;
use std::{
    fs,
    net::{SocketAddr, UdpSocket},
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

#[test]
fn authenticated_udp_round_trip_and_rejections() {
    let temp = TestDir::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let credentials = temp.0.join("credentials");
    let generated = Command::new("sh")
        .arg(root.join("scripts/dev/generate-credentials.sh"))
        .arg(&credentials)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "credential generation failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );

    let wg = UdpSocket::bind("127.0.0.1:0").unwrap();
    let exit = UdpSocket::bind("127.0.0.1:0").unwrap();
    wg.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    exit.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let wg_port = wg.local_addr().unwrap().port();
    let exit_port = exit.local_addr().unwrap().port();
    let relay_reservation = UdpSocket::bind("127.0.0.1:0").unwrap();
    let local_reservation = UdpSocket::bind("127.0.0.1:0").unwrap();
    let relay_port = relay_reservation.local_addr().unwrap().port();
    let local_port = local_reservation.local_addr().unwrap().port();
    drop(relay_reservation);
    drop(local_reservation);
    let relay_path = temp.0.join("relay.toml");
    fs::write(
        &relay_path,
        format!(
            "listen = \"127.0.0.1:{relay_port}\"\n\
         exit_addr = \"127.0.0.1:{exit_port}\"\n\
         cert_file = \"{}\"\n\
         key_file = \"{}\"\n\
         token_file = \"{}\"\n\
         [limits]\n\
         max_active_sessions = 32\n\
         max_pending_handshakes = 32\n\
         setup_timeout_secs = 10\n\
         idle_timeout_secs = 60\n",
            credentials.join("relay.pem").display(),
            credentials.join("relay-key.pem").display(),
            credentials.join("token").display()
        ),
    )
    .unwrap();
    let client_path = temp.0.join("client.toml");
    fs::write(
        &client_path,
        client_config(
            local_port,
            wg_port,
            relay_port,
            "relay.twohop.test",
            &credentials.join("ca.pem"),
            &credentials.join("token"),
        ),
    )
    .unwrap();

    let mut relay = Process::start("relay", &relay_path);
    relay.wait_for_log("relay listening", 1);
    relay.assert_running();
    let mut client = Process::start("client", &client_path);
    let local_addr = SocketAddr::from(([127, 0, 0, 1], local_port));
    let deadline = Instant::now() + Duration::from_secs(5);
    let relay_source = loop {
        client.assert_running();
        wg.send_to(b"probe", local_addr).unwrap();
        let mut buffer = [0_u8; 65_536];
        match exit.recv_from(&mut buffer) {
            Ok((5, source)) if &buffer[..5] == b"probe" => break source,
            Ok(_) => continue,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => panic!("exit receive failed: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "client packet did not reach exit"
        );
    };
    exit.send_to(b"reply", relay_source).unwrap();
    assert_eq!(
        recv_matching(&wg, b"reply", Instant::now() + Duration::from_secs(2)),
        local_addr
    );

    let boundary = vec![0x5a; 1040];
    wg.send_to(&boundary, local_addr).unwrap();
    assert_eq!(
        recv_matching(&exit, &boundary, Instant::now() + Duration::from_secs(2)),
        relay_source
    );
    exit.send_to(&boundary, relay_source).unwrap();
    assert_eq!(
        recv_matching(&wg, &boundary, Instant::now() + Duration::from_secs(2)),
        local_addr
    );

    drain(&exit);
    drain(&wg);
    wg.send_to(&vec![0xaa; 1041], local_addr).unwrap();
    assert_no_packet(&exit);
    exit.send_to(&vec![0xbb; 1041], relay_source).unwrap();
    assert_no_packet(&wg);

    let bad_token = temp.0.join("bad-token");
    fs::write(&bad_token, "0".repeat(64)).unwrap();
    let bad_path = temp.0.join("bad-client.toml");
    let bad_port = free_port();
    fs::write(
        &bad_path,
        client_config(
            bad_port,
            wg_port,
            relay_port,
            "relay.twohop.test",
            &credentials.join("ca.pem"),
            &bad_token,
        ),
    )
    .unwrap();
    let mut bad_client = Process::start("client", &bad_path);
    bad_client.wait_for_failure();
    assert_no_packet(&exit);

    reject_control(relay_port, &credentials.join("ca.pem"), 4097, &[]);
    assert_no_packet(&exit);
    reject_control(relay_port, &credentials.join("ca.pem"), 4, b"oops");
    assert_no_packet(&exit);
    let wrong_version = format!(
        "{{\"version\":2,\"token\":\"{}\"}}",
        fs::read_to_string(credentials.join("token"))
            .unwrap()
            .trim_end()
    );
    reject_control(
        relay_port,
        &credentials.join("ca.pem"),
        wrong_version.len() as u32,
        wrong_version.as_bytes(),
    );
    assert_no_packet(&exit);

    let other_credentials = temp.0.join("other-credentials");
    let generated = Command::new("sh")
        .arg(root.join("scripts/dev/generate-credentials.sh"))
        .arg(&other_credentials)
        .output()
        .unwrap();
    assert!(generated.status.success());
    let untrusted_path = temp.0.join("untrusted-client.toml");
    fs::write(
        &untrusted_path,
        client_config(
            free_port(),
            wg_port,
            relay_port,
            "relay.twohop.test",
            &other_credentials.join("ca.pem"),
            &credentials.join("token"),
        ),
    )
    .unwrap();
    let mut untrusted_client = Process::start("client", &untrusted_path);
    untrusted_client.wait_for_failure();

    let wrong_name_path = temp.0.join("wrong-name-client.toml");
    fs::write(
        &wrong_name_path,
        client_config(
            free_port(),
            wg_port,
            relay_port,
            "other.twohop.test",
            &credentials.join("ca.pem"),
            &credentials.join("token"),
        ),
    )
    .unwrap();
    let mut wrong_name_client = Process::start("client", &wrong_name_path);
    wrong_name_client.wait_for_failure();

    client.stop("TERM");
    relay.stop("TERM");
    assert!(client.logs().contains("udp_to_quic_oversized=1"));
    assert!(relay.logs().contains("udp_to_quic_oversized=1"));
    let token = fs::read_to_string(credentials.join("token")).unwrap();
    assert!(!client.logs().contains(token.trim()));
    assert!(!relay.logs().contains(token.trim()));
}
