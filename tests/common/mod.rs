#![allow(dead_code)]

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

pub struct TestDir(pub PathBuf);

static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl TestDir {
    pub fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let id = NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("twohop-test-{}-{nonce}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub struct Process(pub Child, PathBuf);

impl Process {
    pub fn start(role: &str, config: &Path) -> Self {
        let log = config.with_extension(format!("{role}.log"));
        let stderr = fs::File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_twohop"))
            .arg(role)
            .arg("--config")
            .arg(config)
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()
            .unwrap();
        Self(child, log)
    }

    pub fn assert_running(&mut self) {
        assert!(self.0.try_wait().unwrap().is_none(), "process exited early");
    }

    pub fn wait_for_failure(&mut self) {
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

pub fn recv_matching(socket: &UdpSocket, expected: &[u8], deadline: Instant) -> SocketAddr {
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

pub fn assert_no_packet(socket: &UdpSocket) {
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

pub fn drain(socket: &UdpSocket) {
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

pub fn reject_control(fixture: &Fixture, length: u32, payload: &[u8]) {
    runtime().block_on(async {
        let (endpoint, connection) = raw_connection(fixture).await;
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

impl Process {
    pub fn logs(&self) -> String {
        fs::read_to_string(&self.1).unwrap()
    }

    pub fn wait_for_log(&mut self, message: &str, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let logs = self.logs();
            if logs.lines().filter(|line| line.contains(message)).count() >= count {
                return;
            }
            self.assert_running();
            assert!(Instant::now() < deadline, "missing log {message}: {logs}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn listening_addr(&mut self, message: &str, field: &str) -> SocketAddr {
        self.wait_for_log(message, 1);
        let logs = self.logs();
        let line = logs.lines().find(|line| line.contains(message)).unwrap();
        let prefix = format!("{field}=");
        line.split_whitespace()
            .find_map(|word| word.strip_prefix(&prefix))
            .unwrap()
            .parse()
            .unwrap()
    }

    pub fn stop(&mut self, signal: &str) {
        let status = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(self.0.id().to_string())
            .status()
            .unwrap();
        assert!(status.success());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success(), "shutdown failed: {}", self.logs());
                return;
            }
            assert!(Instant::now() < deadline, "shutdown hung: {}", self.logs());
            thread::sleep(Duration::from_millis(10));
        }
    }
}

pub struct Fixture {
    pub temp: TestDir,
    pub credentials: PathBuf,
    pub exit: UdpSocket,
    pub relay_addr: SocketAddr,
    pub relay_config: PathBuf,
}

impl Fixture {
    pub fn new(active: usize, pending: usize, setup_secs: u64, idle_secs: u64) -> Self {
        let temp = TestDir::new();
        let credentials = temp.0.join("credentials");
        generate_credentials(&credentials);
        let exit = UdpSocket::bind("127.0.0.1:0").unwrap();
        exit.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let relay_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let relay_config = temp.0.join("relay.toml");
        write_config(
            &relay_config,
            &serde_json::json!({
                "listen": relay_addr.to_string(), "exit_addr": exit.local_addr().unwrap().to_string(),
                "cert_file": credentials.join("relay.pem"), "key_file": credentials.join("relay-key.pem"),
                "token_file": credentials.join("token"),
                "limits": { "max_active_sessions": active, "max_pending_handshakes": pending,
                    "setup_timeout_secs": setup_secs, "idle_timeout_secs": idle_secs }
            }),
        );
        Self {
            temp,
            credentials,
            exit,
            relay_addr,
            relay_config,
        }
    }

    pub fn relay(&mut self) -> Process {
        let mut relay = Process::start("relay", &self.relay_config);
        let addr = relay.listening_addr("relay listening", "listen");
        if self.relay_addr.port() == 0 {
            // Subsequent restarts use the address discovered from the first OS-assigned bind.
            let mut config: toml::Value =
                toml::from_str(&fs::read_to_string(&self.relay_config).unwrap()).unwrap();
            config["listen"] = addr.to_string().into();
            write_config(&self.relay_config, &config);
            self.relay_addr = addr;
        }
        assert_eq!(addr, self.relay_addr);
        relay
    }

    pub fn client(&self, id: usize) -> (Process, UdpSocket, SocketAddr) {
        let wg = UdpSocket::bind("127.0.0.1:0").unwrap();
        wg.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut client = self.client_with(
            id,
            wg.local_addr().unwrap().port(),
            "relay.twohop.test",
            &self.credentials.join("ca.pem"),
            &self.credentials.join("token"),
        );
        let local = client.listening_addr("client listening", "local");
        (client, wg, local)
    }

    pub fn client_with(
        &self,
        id: usize,
        wg_port: u16,
        server_name: &str,
        ca: &Path,
        token: &Path,
    ) -> Process {
        let config = self.temp.0.join(format!("client-{id}.toml"));
        write_config(
            &config,
            &serde_json::json!({
                "local_bind": "127.0.0.1:0", "wireguard_port": wg_port,
                "relay_addr": self.relay_addr.to_string(), "server_name": server_name,
                "ca_cert_file": ca, "token_file": token
            }),
        );
        Process::start("client", &config)
    }

    pub fn token(&self) -> String {
        fs::read_to_string(self.credentials.join("token"))
            .unwrap()
            .trim()
            .to_owned()
    }
}

pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

pub fn raw_endpoint(fixture: &Fixture) -> quinn::Endpoint {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(fixture.credentials.join("ca.pem")).unwrap())
        .unwrap();
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"twohop/1".to_vec()];
    let mut quic = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    transport.datagram_send_buffer_size(64 * 1024);
    quic.transport_config(Arc::new(transport));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quic);
    endpoint
}

pub async fn raw_connection(fixture: &Fixture) -> (quinn::Endpoint, quinn::Connection) {
    let endpoint = raw_endpoint(fixture);
    let connection = tokio::time::timeout(
        Duration::from_secs(3),
        endpoint
            .connect(fixture.relay_addr, "relay.twohop.test")
            .unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    (endpoint, connection)
}

pub async fn authenticate(
    connection: &quinn::Connection,
    token: &str,
) -> Result<(quinn::SendStream, quinn::RecvStream), quinn::ReadExactError> {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let payload = serde_json::to_vec(&serde_json::json!({"version": 1, "token": token})).unwrap();
    send.write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    send.write_all(&payload).await.unwrap();
    let mut length = [0; 4];
    recv.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    assert!(length <= 4096);
    let mut response = vec![0; length];
    recv.read_exact(&mut response).await?;
    let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(
        response,
        serde_json::json!({"version": 1, "max_datagram_size": 1040})
    );
    Ok((send, recv))
}

pub async fn closed(connection: &quinn::Connection) -> quinn::ConnectionError {
    tokio::time::timeout(Duration::from_secs(3), connection.closed())
        .await
        .unwrap()
}

pub fn generate_credentials(path: &Path) {
    let generated = Command::new("sh")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/dev/generate-credentials.sh"))
        .arg(path)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "credential generation failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
}

pub fn round_trip(
    fixture: &Fixture,
    wg: &UdpSocket,
    local: SocketAddr,
    packet: &[u8],
) -> SocketAddr {
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

fn write_config(path: &Path, config: &impl serde::Serialize) {
    fs::write(path, toml::to_string(config).unwrap()).unwrap();
}
