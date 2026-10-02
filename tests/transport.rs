mod common;

use common::*;
use std::{
    fs,
    time::{Duration, Instant},
};

#[test]
fn authenticated_udp_round_trip_and_rejections() {
    let mut fixture = Fixture::new(32, 32, 10, 60);
    let mut relay = fixture.relay();
    let (mut client, wg, local) = fixture.client(1);
    client.wait_for_log("client session ready", 1);
    let source = round_trip(&fixture, &wg, local, b"probe");
    fixture.exit.send_to(b"reply", source).unwrap();
    assert_eq!(
        recv_matching(&wg, b"reply", Instant::now() + Duration::from_secs(2)),
        local
    );
    assert_eq!(round_trip(&fixture, &wg, local, &[0x5a; 1040]), source);

    drain(&fixture.exit);
    drain(&wg);
    // Include a large UDP packet so a too-small receive buffer cannot silently
    // truncate an oversized packet into an accepted payload.
    for size in [1041, 8192] {
        wg.send_to(&vec![0xaa; size], local).unwrap();
        assert_no_packet(&fixture.exit);
        fixture.exit.send_to(&vec![0xbb; size], source).unwrap();
        assert_no_packet(&wg);
    }

    let bad_token = fixture.temp.0.join("bad-token");
    fs::write(&bad_token, "0".repeat(64)).unwrap();
    let wg_port = wg.local_addr().unwrap().port();
    let ca = fixture.credentials.join("ca.pem");
    let token_file = fixture.credentials.join("token");
    let mut bad_client = fixture.client_with(2, wg_port, "relay.twohop.test", &ca, &bad_token);
    bad_client.wait_for_failure();
    assert_no_packet(&fixture.exit);

    let wrong_version = format!("{{\"version\":2,\"token\":\"{}\"}}", fixture.token());
    for (length, payload) in [
        (0, &[][..]),
        (4097, &[][..]),
        (4, &b"oops"[..]),
        (wrong_version.len() as u32, wrong_version.as_bytes()),
    ] {
        reject_control(&fixture, length, payload);
        assert_no_packet(&fixture.exit);
    }

    let other_credentials = fixture.temp.0.join("other-credentials");
    generate_credentials(&other_credentials);
    for (id, name, ca) in [
        (3, "relay.twohop.test", other_credentials.join("ca.pem")),
        (4, "other.twohop.test", ca),
    ] {
        let mut invalid = fixture.client_with(id, wg_port, name, &ca, &token_file);
        invalid.wait_for_failure();
    }

    client.stop("TERM");
    relay.stop("TERM");
    assert!(client.logs().contains("udp_to_quic_oversized=2"));
    assert!(relay.logs().contains("udp_to_quic_oversized=2"));
    assert!(!client.logs().contains(&fixture.token()));
    assert!(!relay.logs().contains(&fixture.token()));
}
