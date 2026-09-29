use std::{
    fs,
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("twohop-test-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Process(Child);

impl Process {
    fn start(role: &str, config: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_twohop"))
            .arg(role)
            .arg("--config")
            .arg(config)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        Self(child)
    }

    fn assert_running(&mut self) {
        assert!(self.0.try_wait().unwrap().is_none(), "process exited early");
    }

    fn wait_for_failure(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(!status.success(), "invalid client unexpectedly succeeded");
                return;
            }
            assert!(Instant::now() < deadline, "invalid client did not fail");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn client_config(
    local_port: u16,
    wg_port: u16,
    relay_port: u16,
    server_name: &str,
    ca: &Path,
    token: &Path,
) -> String {
    format!(
        "local_bind = \"127.0.0.1:{local_port}\"\n\
         wireguard_port = {wg_port}\n\
         relay_addr = \"127.0.0.1:{relay_port}\"\n\
         server_name = \"{server_name}\"\n\
         ca_cert_file = \"{}\"\n\
         token_file = \"{}\"\n",
        ca.display(),
        token.display()
    )
}

fn recv_matching(socket: &UdpSocket, expected: &[u8], deadline: Instant) -> SocketAddr {
    let mut buffer = [0_u8; 65_536];
    loop {
        assert!(Instant::now() < deadline, "timed out waiting for packet");
        match socket.recv_from(&mut buffer) {
            Ok((size, source)) if &buffer[..size] == expected => return source,
            Ok(_) => continue,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => panic!("UDP receive failed: {error}"),
        }
    }
}

fn assert_no_packet(socket: &UdpSocket) {
    let mut buffer = [0_u8; 65_536];
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let result = socket.recv_from(&mut buffer);
    assert!(
        matches!(&result, Err(error) if error.kind() == std::io::ErrorKind::WouldBlock || error.kind() == std::io::ErrorKind::TimedOut),
        "unexpected UDP packet: {result:?}"
    );
}

fn drain(socket: &UdpSocket) {
    socket.set_nonblocking(true).unwrap();
    let mut buffer = [0_u8; 65_536];
    loop {
        match socket.recv_from(&mut buffer) {
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("UDP drain failed: {error}"),
        }
    }
    socket.set_nonblocking(false).unwrap();
}

fn reject_control(relay_port: u16, ca: &Path, length: u32, payload: &[u8]) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_file(ca).unwrap())
            .unwrap();
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"twohop/1".to_vec()];
        let mut quic = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));
        let mut transport = quinn::TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(64 * 1024));
        quic.transport_config(Arc::new(transport));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quic);
        let connection = endpoint
            .connect(
                SocketAddr::from(([127, 0, 0, 1], relay_port)),
                "relay.twohop.test",
            )
            .unwrap()
            .await
            .unwrap();
        connection
            .send_datagram(Bytes::from_static(b"unauthenticated"))
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(&length.to_be_bytes()).await.unwrap();
        send.write_all(payload).await.unwrap();
        let mut response = [0_u8; 4];
        let result =
            tokio::time::timeout(Duration::from_secs(2), recv.read_exact(&mut response)).await;
        assert!(
            matches!(result, Ok(Err(_))),
            "invalid control message was not rejected"
        );
        connection.close(0_u32.into(), b"test complete");
        endpoint.wait_idle().await;
    });
}

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
    thread::sleep(Duration::from_millis(100));
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
}
