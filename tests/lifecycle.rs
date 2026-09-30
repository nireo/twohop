mod common;

use std::{
    fs,
    net::{SocketAddr, UdpSocket},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use bytes::Bytes;
use common::*;

fn idle_events(relay: &Process) -> usize {
    relay
        .logs()
        .lines()
        .filter(|line| line.contains("relay resources pending=0 active=0 tasks=0"))
        .count()
}

fn wait_idle(relay: &mut Process, previous: usize) {
    relay.wait_for_log("relay resources pending=0 active=0 tasks=0", previous + 1);
}

fn counter(process: &Process, name: &str) -> u64 {
    let logs = process.logs();
    let line = logs
        .lines()
        .rev()
        .find(|line| line.contains("traffic counters"))
        .unwrap();
    let prefix = format!("{name}=");
    line.split_whitespace()
        .find_map(|field| field.strip_prefix(&prefix))
        .unwrap()
        .parse()
        .unwrap()
}

fn round_trip(fixture: &Fixture, wg: &UdpSocket, local: SocketAddr, packet: &[u8]) -> SocketAddr {
    wg.send_to(packet, local).unwrap();
    let source = recv_matching(
        &fixture.exit,
        packet,
        Instant::now() + Duration::from_secs(3),
    );
    fixture.exit.send_to(packet, source).unwrap();
    assert_eq!(
        recv_matching(wg, packet, Instant::now() + Duration::from_secs(3)),
        local
    );
    source
}

#[test]
fn concurrent_clients_recover_after_crash_without_replaying_outage_packets() {
    // Short idle timeout makes hard-crash detection fast; graceful restart is covered below.
    let fixture = Fixture::new(2, 4, 2, 3);
    let mut relay = fixture.relay();
    let (mut client_a, wg_a, local_a) = fixture.client(1);
    let (mut client_b, wg_b, local_b) = fixture.client(2);
    client_a.wait_for_log("client session ready", 1);
    client_b.wait_for_log("client session ready", 1);
    let source_a = round_trip(&fixture, &wg_a, local_a, b"client-a");
    let source_b = round_trip(&fixture, &wg_b, local_b, b"client-b");
    assert_ne!(source_a, source_b);
    fixture.exit.send_to(b"only-a", source_a).unwrap();
    recv_matching(&wg_a, b"only-a", Instant::now() + Duration::from_secs(2));
    assert_no_packet(&wg_b);
    fixture.exit.send_to(b"only-b", source_b).unwrap();
    recv_matching(&wg_b, b"only-b", Instant::now() + Duration::from_secs(2));
    assert_no_packet(&wg_a);

    relay.0.kill().unwrap();
    relay.0.wait().unwrap();
    client_a.wait_for_log("client reconnect scheduled", 1);
    client_b.wait_for_log("client reconnect scheduled", 1);
    assert!(
        UdpSocket::bind(local_a).is_err(),
        "client lost its local bind"
    );
    for _ in 0..100 {
        wg_a.send_to(b"outage-a", local_a).unwrap();
        wg_b.send_to(b"outage-b", local_b).unwrap();
    }
    assert_no_packet(&fixture.exit);
    let mut relay = fixture.relay();
    client_a.wait_for_log("client session ready", 2);
    client_b.wait_for_log("client session ready", 2);
    assert_no_packet(&fixture.exit);
    let new_a = round_trip(&fixture, &wg_a, local_a, b"recovered-a");
    let new_b = round_trip(&fixture, &wg_b, local_b, b"recovered-b");
    assert_ne!(new_a, new_b);
    client_a.stop("INT");
    client_b.stop("TERM");
    assert!(UdpSocket::bind(local_a).is_ok());
    assert!(UdpSocket::bind(local_b).is_ok());
    assert!(counter(&client_a, "disconnected_drops") >= 100);
    assert!(counter(&client_b, "disconnected_drops") >= 100);
    assert!(counter(&client_a, "reconnects") >= 1);
    relay.stop("TERM");
    assert!(UdpSocket::bind(fixture.relay_addr).is_ok());
    assert!(
        relay
            .logs()
            .contains("relay resources pending=0 active=0 tasks=0 connections=0")
    );
}

#[test]
fn pending_limit_and_setup_timeout_release_capacity() {
    let fixture = Fixture::new(1, 1, 1, 60);
    let mut relay = fixture.relay();
    runtime().block_on(async {
        let (endpoint, stalled) = raw_connection(&fixture).await;
        let excess_endpoint = raw_endpoint(&fixture);
        let error = tokio::time::timeout(Duration::from_secs(2), excess_endpoint.connect(fixture.relay_addr, "relay.twohop.test").unwrap()).await.unwrap().unwrap_err();
        assert!(matches!(error, quinn::ConnectionError::ConnectionClosed(close) if close.error_code == quinn::TransportErrorCode::CONNECTION_REFUSED));
        assert_no_packet(&fixture.exit);
        let idle = idle_events(&relay);
        closed(&stalled).await;
        wait_idle(&mut relay, idle);
        relay.wait_for_log("reason=\"setup_timeout\"", 1);
        endpoint.wait_idle().await;
        let (replacement_endpoint, replacement) = raw_connection(&fixture).await;
        let (_send, _recv) = authenticate(&replacement, &fixture.token()).await.unwrap();
        replacement.send_datagram(Bytes::from_static(b"after-timeout")).unwrap();
        recv_matching(&fixture.exit, b"after-timeout", Instant::now() + Duration::from_secs(2));
        replacement.close(0_u32.into(), b"done");
        replacement_endpoint.wait_idle().await;
    });
    relay.stop("INT");
    assert!(counter(&relay, "rejected") >= 1);
    assert!(counter(&relay, "setup_errors") >= 1);
}

#[test]
fn active_limit_is_retryable_and_graceful_restart_recovers() {
    let fixture = Fixture::new(1, 4, 2, 60);
    let mut relay = fixture.relay();
    runtime().block_on(async {
        let (endpoint, occupied) = raw_connection(&fixture).await;
        let (_send, _recv) = authenticate(&occupied, &fixture.token()).await.unwrap();
        let (mut client, wg, local) = fixture.client(1);
        client.wait_for_log("reason=\"relay_busy\"", 1);
        client.assert_running();
        occupied.close(0_u32.into(), b"done");
        endpoint.wait_idle().await;
        client.wait_for_log("client session ready", 1);
        round_trip(&fixture, &wg, local, b"after-capacity");
        assert!(relay.logs().contains("reason=\"active_limit\""));
        relay.stop("TERM");
        client.wait_for_log("client reconnect scheduled", 2);
        let mut replacement = fixture.relay();
        client.wait_for_log("client session ready", 2);
        round_trip(&fixture, &wg, local, b"after-graceful-restart");
        client.stop("TERM");
        replacement.stop("TERM");
    });
}

#[test]
fn shutdown_cancels_setup_and_client_connecting_or_backoff() {
    let fixture = Fixture::new(1, 2, 10, 60);
    let mut relay = fixture.relay();
    runtime().block_on(async {
        let (_endpoint, pending) = raw_connection(&fixture).await;
        relay.stop("TERM");
        closed(&pending).await;
    });
    assert!(
        relay
            .logs()
            .contains("relay resources pending=0 active=0 tasks=0 connections=0")
    );
    assert!(UdpSocket::bind(fixture.relay_addr).is_ok());

    let (mut connecting, _wg, local) = fixture.client(1);
    connecting.wait_for_log("client connecting", 1);
    connecting.stop("TERM");
    assert!(UdpSocket::bind(local).is_ok());

    // A bound UDP socket that never responds forces a setup timeout and then backoff.
    let blackhole = UdpSocket::bind(fixture.relay_addr).unwrap();
    let (mut retrying, wg, local) = fixture.client(2);
    wg.send_to(b"discard-during-setup", local).unwrap();
    retrying.wait_for_log("client connecting", 1);
    let deadline = Instant::now() + Duration::from_secs(13);
    while !retrying.logs().contains("client reconnect scheduled") {
        assert!(Instant::now() < deadline, "setup did not time out");
        retrying.assert_running();
        thread::sleep(Duration::from_millis(10));
    }
    retrying.stop("INT");
    assert!(UdpSocket::bind(local).is_ok());
    drop(blackhole);
}

#[test]
fn protocol_errors_and_control_eof_release_sessions_without_logging_payloads() {
    let fixture = Fixture::new(2, 4, 2, 60);
    let mut relay = fixture.relay();
    runtime().block_on(async {
        let (endpoint, connection) = raw_connection(&fixture).await;
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        let secret = fixture.token();
        let malformed = serde_json::to_vec(&serde_json::json!({"version": secret, "token": secret})).unwrap();
        send.write_all(&(malformed.len() as u32).to_be_bytes()).await.unwrap();
        send.write_all(&malformed).await.unwrap();
        let idle = idle_events(&relay);
        assert!(matches!(closed(&connection).await, quinn::ConnectionError::ApplicationClosed(close) if close.error_code == 2_u32.into()));
        wait_idle(&mut relay, idle);
        endpoint.wait_idle().await;

        let (endpoint, connection) = raw_connection(&fixture).await;
        let (mut send, _recv) = authenticate(&connection, &fixture.token()).await.unwrap();
        let idle = idle_events(&relay);
        send.write_all(b"private-packet-body").await.unwrap();
        assert!(matches!(closed(&connection).await, quinn::ConnectionError::ApplicationClosed(close) if close.error_code == 2_u32.into()));
        wait_idle(&mut relay, idle);
        endpoint.wait_idle().await;

        let (endpoint, connection) = raw_connection(&fixture).await;
        let (mut send, _recv) = authenticate(&connection, &fixture.token()).await.unwrap();
        let idle = idle_events(&relay);
        send.finish().unwrap();
        closed(&connection).await;
        wait_idle(&mut relay, idle);
        endpoint.wait_idle().await;
    });
    assert_no_packet(&fixture.exit);
    relay.stop("TERM");
    assert_eq!(counter(&relay, "session_errors"), 2);
    assert!(!relay.logs().contains(&fixture.token()));
    assert!(!relay.logs().contains("private-packet-body"));
}

fn resources(process: &Process) -> (u64, usize) {
    let pid = process.0.id().to_string();
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .unwrap();
    assert!(output.status.success());
    let rss = String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let proc_fd = std::path::PathBuf::from(format!("/proc/{pid}/fd"));
    let fds = if proc_fd.exists() {
        fs::read_dir(proc_fd).unwrap().count()
    } else {
        let output = Command::new("lsof")
            .args(["-a", "-p", &pid, "-F", "f"])
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .filter(|line| {
                line.strip_prefix('f').is_some_and(|fd| {
                    !fd.is_empty() && fd.bytes().all(|byte| byte.is_ascii_digit())
                })
            })
            .count()
    };
    (rss, fds)
}

#[test]
fn churn_and_slow_receiver_keep_resources_bounded() {
    let fixture = Fixture::new(2, 4, 2, 60);
    let mut relay = fixture.relay();
    runtime().block_on(async {
        let endpoint = raw_endpoint(&fixture);
        let mut baseline = None;
        for round in 0..2 {
            for _ in 0..20 {
                let connection = endpoint.connect(fixture.relay_addr, "relay.twohop.test").unwrap().await.unwrap();
                let (_send, _recv) = authenticate(&connection, &fixture.token()).await.unwrap();
                let idle = idle_events(&relay);
                connection.close(0_u32.into(), b"churn complete");
                wait_idle(&mut relay, idle);
                endpoint.wait_idle().await;
            }
            let usage = resources(&relay);
            if round == 0 {
                baseline = Some(usage);
            } else {
                let baseline = baseline.unwrap();
                assert!(usage.0 <= baseline.0 + 8 * 1024, "RSS grew across churn: {baseline:?} -> {usage:?}");
                assert!(usage.1 <= baseline.1 + 2, "file descriptors leaked: {baseline:?} -> {usage:?}");
            }
        }
        let baseline = baseline.unwrap();
        let (slow_endpoint, slow) = raw_connection(&fixture).await;
        let (_slow_send, _slow_recv) = authenticate(&slow, &fixture.token()).await.unwrap();
        slow.send_datagram(Bytes::from_static(b"slow-peer-probe")).unwrap();
        let source = recv_matching(&fixture.exit, b"slow-peer-probe", Instant::now() + Duration::from_secs(2));
        let flood_socket = fixture.exit.try_clone().unwrap();
        let flood = thread::spawn(move || {
            let packet = [0x5a; 1040];
            for _ in 0..20_000 {
                flood_socket.send_to(&packet, source).unwrap();
            }
        });
        // The slow peer never reads its QUIC datagrams; another session must still progress.
        let (healthy_endpoint, healthy) = raw_connection(&fixture).await;
        let (_healthy_send, _healthy_recv) = authenticate(&healthy, &fixture.token()).await.unwrap();
        healthy.send_datagram(Bytes::from_static(b"healthy-peer")).unwrap();
        let healthy_source = recv_matching(&fixture.exit, b"healthy-peer", Instant::now() + Duration::from_secs(3));
        fixture.exit.send_to(b"healthy-reply", healthy_source).unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(3), healthy.read_datagram()).await.unwrap().unwrap(), b"healthy-reply"[..]);
        flood.join().unwrap();
        let loaded = resources(&relay);
        assert!(loaded.0 <= baseline.0 + 32 * 1024, "RSS grew during overload: {baseline:?} -> {loaded:?}");
        let idle = idle_events(&relay);
        slow.close(0_u32.into(), b"done");
        healthy.close(0_u32.into(), b"done");
        wait_idle(&mut relay, idle);
        slow_endpoint.wait_idle().await;
        healthy_endpoint.wait_idle().await;
        let final_usage = resources(&relay);
        assert!(final_usage.1 <= baseline.1 + 2, "session sockets leaked: {baseline:?} -> {final_usage:?}");
        eprintln!("relay resources (RSS KiB, descriptors): baseline={baseline:?}, loaded={loaded:?}, final={final_usage:?}");
    });
    relay.stop("TERM");
}

#[test]
fn keepalive_preserves_an_idle_client_session() {
    let fixture = Fixture::new(1, 2, 2, 23);
    let mut relay = fixture.relay();
    let (mut client, wg, local) = fixture.client(1);
    client.wait_for_log("client session ready", 1);
    // Longer than the negotiated idle timeout, so the client's 20-second keepalive is required.
    thread::sleep(Duration::from_secs(25));
    round_trip(&fixture, &wg, local, b"after-idle");
    assert_eq!(
        client
            .logs()
            .lines()
            .filter(|line| line.contains("client session ready"))
            .count(),
        1
    );
    client.stop("TERM");
    relay.stop("TERM");
}

#[test]
fn client_stops_if_a_ready_relay_sends_unexpected_control_data() {
    let fixture = Fixture::new(1, 2, 2, 60);
    runtime().block_on(async {
        use quinn::crypto::rustls::QuicServerConfig;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
        use std::sync::Arc;

        let certificate =
            CertificateDer::from_pem_file(fixture.credentials.join("relay.pem")).unwrap();
        let key = PrivateKeyDer::from_pem_file(fixture.credentials.join("relay-key.pem")).unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap();
        tls.alpn_protocols = vec![b"twohop/1".to_vec()];
        let mut server =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
        let mut transport = quinn::TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(64 * 1024));
        server.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(server, fixture.relay_addr).unwrap();
        let (mut client, _wg, local) = fixture.client(1);
        let connection = tokio::time::timeout(Duration::from_secs(3), async {
            endpoint.accept().await.unwrap().await.unwrap()
        })
        .await
        .unwrap();
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let mut length = [0; 4];
        recv.read_exact(&mut length).await.unwrap();
        let length = u32::from_be_bytes(length) as usize;
        assert!(length <= 4096);
        let mut request = vec![0; length];
        recv.read_exact(&mut request).await.unwrap();
        let response = br#"{"version":1,"max_datagram_size":1040}"#;
        send.write_all(&(response.len() as u32).to_be_bytes())
            .await
            .unwrap();
        send.write_all(response).await.unwrap();
        send.write_all(b"secret-unexpected-control").await.unwrap();
        client.wait_for_failure();
        assert!(
            client
                .logs()
                .contains("relay violated the session protocol")
        );
        assert!(!client.logs().contains("secret-unexpected-control"));
        assert_eq!(counter(&client, "session_errors"), 1);
        assert!(UdpSocket::bind(local).is_ok());
        endpoint.close(0_u32.into(), b"done");
        endpoint.wait_idle().await;
    });
}
