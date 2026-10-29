use super::*;

#[test]
fn host_key_fingerprint_and_endpoint_are_stable() {
    assert_eq!(
        fingerprint(b"vaultmesh-host-key"),
        "SHA256:8oHDb5PRKSvrgACKsgtHc3CJKNWbEzwVSJYJh4QDaFs"
    );
    assert_eq!(
        SshTarget {
            host: "2001:db8::1".into(),
            port: 2222,
            username: "deploy".into(),
        }
        .endpoint(),
        "deploy@[2001:db8::1]:2222"
    );
}

#[test]
fn agent_output_redacts_direct_base64_and_hex_secret_canaries() {
    let secret = "not-a-real-password";
    let encoded = STANDARD.encode(secret.as_bytes());
    let hex = secret
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let output = format!("direct={secret} encoded={encoded} hex={hex} safe=ok");
    let redacted = redact_canaries(&output, &[secret.to_owned()]);
    assert!(!redacted.contains(secret));
    assert!(!redacted.contains(&encoded));
    assert!(!redacted.contains(&hex));
    assert!(redacted.contains("safe=ok"));
}

#[test]
fn agent_output_reader_never_exceeds_the_approved_limit() {
    let mut source = std::io::Cursor::new(vec![b'x'; 32]);
    let mut output = Vec::new();
    let mut truncated = false;
    assert!(read_bounded(&mut source, &mut output, 8, &mut truncated).unwrap());
    assert_eq!(output.len(), 8);
    assert!(truncated);
}

#[test]
fn agent_sftp_paths_are_component_bounded_and_never_prefix_confused() {
    assert!(valid_remote_path("/srv/app/releases/build.bin"));
    assert!(path_is_within("/srv/app/releases/build.bin", "/srv/app"));
    assert!(!path_is_within("/srv/application/secret", "/srv/app"));
    for denied in [
        "/",
        "/srv/app/../secret",
        "/srv//app/file",
        "/srv/app\\file",
        "srv/app/file",
    ] {
        assert!(!valid_remote_path(denied));
    }
}

#[test]
fn install_command_uses_stdin_and_never_interpolates_key_material() {
    assert!(INSTALL_PUBLIC_KEY_COMMAND.starts_with("sh -c '"));
    assert!(INSTALL_PUBLIC_KEY_COMMAND.ends_with('\''));
    assert!(INSTALL_PUBLIC_KEY_COMMAND.contains("key=$(cat)"));
    assert!(INSTALL_PUBLIC_KEY_COMMAND.contains("grep -qxF"));
    assert!(INSTALL_PUBLIC_KEY_COMMAND.contains("chmod 600"));
    assert!(!INSTALL_PUBLIC_KEY_COMMAND.contains("ssh-ed25519"));
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires the local OpenSSH daemon"]
fn local_openssh_install_repeat_and_key_verification_round_trip() {
    use std::{
        fs,
        net::TcpListener,
        os::unix::fs::PermissionsExt,
        path::Path,
        process::{Child, Command, Stdio},
        thread,
    };

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn generate_key(path: &Path) {
        let status = Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(path)
            .status()
            .expect("ssh-keygen");
        assert!(status.success());
    }

    let root = std::env::temp_dir().join(format!("vaultmesh-ssh-e2e-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).expect("test root");
    let host_key = root.join("host_key");
    let authentication_key = root.join("authentication_key");
    let upload_key = root.join("upload_key");
    generate_key(&host_key);
    generate_key(&authentication_key);
    generate_key(&upload_key);
    let authentication_public = fs::read_to_string(authentication_key.with_extension("pub"))
        .expect("authentication public key");
    let upload_public =
        fs::read_to_string(upload_key.with_extension("pub")).expect("upload public key");
    let authorized_keys = root.join("authorized_keys");
    fs::write(
        &authorized_keys,
        format!("{}\n", authentication_public.trim()),
    )
    .expect("authorized keys");
    let install_wrapper = root.join("install-wrapper.sh");
    fs::write(
            &install_wrapper,
            format!(
                "#!/bin/sh\nkey=$(cat)\nif grep -qxF \"$key\" '{}'; then exit 20; fi\nprintf '%s\\n' \"$key\" >> '{}'\n",
                authorized_keys.display(),
                authorized_keys.display(),
            ),
        )
        .expect("install wrapper");
    fs::set_permissions(&install_wrapper, fs::Permissions::from_mode(0o700))
        .expect("wrapper permissions");

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("ephemeral port");
    let port = listener.local_addr().expect("address").port();
    drop(listener);
    let config = root.join("sshd_config");
    fs::write(
            &config,
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nLogLevel ERROR\nForceCommand {}\n",
                host_key.display(),
                root.join("sshd.pid").display(),
                authorized_keys.display(),
                install_wrapper.display(),
            ),
        )
        .expect("sshd config");
    let child = Command::new("/usr/sbin/sshd")
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sshd");
    let mut child = ChildGuard(child);
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(
            child.0.try_wait().expect("sshd status").is_none(),
            "sshd exited"
        );
        thread::sleep(Duration::from_millis(100));
    }

    let target = SshTarget {
        host: "127.0.0.1".into(),
        port,
        username: std::env::var("USER").expect("USER"),
    };
    let preview = inspect_host_key(target.clone()).expect("host key preview");
    let authentication_private =
        fs::read_to_string(&authentication_key).expect("authentication private");
    let upload_private = fs::read_to_string(&upload_key).expect("upload private");
    let install = || PublicKeyInstallRequest {
        target: target.clone(),
        expected_host_key_fingerprint: preview.fingerprint.clone(),
        public_key: Zeroizing::new(upload_public.trim().to_owned()),
        authentication: AuthenticationMaterial::AuthenticationKey(PrivateKeyMaterial {
            public_key: Some(Zeroizing::new(authentication_public.trim().to_owned())),
            private_key: Zeroizing::new(authentication_private.clone()),
            passphrase: None,
        }),
        verification_key: Some(PrivateKeyMaterial {
            public_key: Some(Zeroizing::new(upload_public.trim().to_owned())),
            private_key: Zeroizing::new(upload_private.clone()),
            passphrase: None,
        }),
    };
    let mut mismatched = install();
    mismatched.expected_host_key_fingerprint =
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
    assert!(
        install_public_key(mismatched)
            .expect_err("changed host key")
            .contains("主机密钥已变化")
    );
    assert_eq!(
        fs::read_to_string(&authorized_keys)
            .expect("unchanged authorized keys")
            .lines()
            .count(),
        1
    );
    let first = install_public_key(install()).expect("first install");
    assert_eq!(first.status, "installed");
    assert!(first.key_login_verified);
    assert_eq!(first.key_login_verification, KeyLoginVerification::Verified);
    let repeated = install_public_key(install()).expect("repeated install");
    assert_eq!(repeated.status, "alreadyPresent");
    assert!(repeated.key_login_verified);
    assert_eq!(
        repeated.key_login_verification,
        KeyLoginVerification::Verified
    );
    assert_eq!(
        fs::read_to_string(&authorized_keys)
            .expect("final authorized keys")
            .lines()
            .count(),
        2
    );

    drop(child);

    let transfer_root = root.join("transfer");
    fs::create_dir_all(&transfer_root).expect("transfer root");
    fs::write(
            &config,
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nPermitTTY yes\nAllowTcpForwarding yes\nSubsystem sftp internal-sftp\nLogLevel ERROR\n",
                host_key.display(),
                root.join("sshd.pid").display(),
                authorized_keys.display(),
            ),
        )
        .expect("agent sshd config");
    let child = Command::new("/usr/sbin/sshd")
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("agent sshd");
    let mut child = ChildGuard(child);
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(
            child.0.try_wait().expect("agent sshd status").is_none(),
            "agent sshd exited"
        );
        thread::sleep(Duration::from_millis(100));
    }
    let authentication = || {
        AuthenticationMaterial::AuthenticationKey(PrivateKeyMaterial {
            public_key: Some(Zeroizing::new(upload_public.trim().to_owned())),
            private_key: Zeroizing::new(upload_private.clone()),
            passphrase: None,
        })
    };

    let command = execute_agent_command(
        AgentSshExecRequest {
            target: target.clone(),
            expected_host_key_fingerprint: preview.fingerprint.clone(),
            command: "printf '{\"status\":\"ready\"}'".into(),
            authentication: authentication(),
            allowed_fields: vec!["exit_status".into(), "stdout".into(), "stderr".into()],
            max_output_bytes: 4_096,
        },
        &AtomicBool::new(false),
    )
    .expect("agent exec");
    assert_eq!(command["exitStatus"], 0);
    assert_eq!(command["stdout"], r#"{"status":"ready"}"#);
    assert_eq!(command["stderr"], "");

    let remote_path = transfer_root.join("round-trip.bin");
    let remote_path = remote_path.to_string_lossy().into_owned();
    let prefix = transfer_root.to_string_lossy().into_owned();
    let payload = b"vaultmesh-agent-sftp-round-trip";
    let upload = execute_agent_upload(
        AgentSshTransferRequest {
            target: target.clone(),
            expected_host_key_fingerprint: preview.fingerprint.clone(),
            remote_path: remote_path.clone(),
            remote_path_prefixes: vec![prefix.clone()],
            authentication: authentication(),
        },
        payload,
        &AtomicBool::new(false),
    )
    .expect("agent upload");
    assert_eq!(upload["status"], "uploaded");
    let download = execute_agent_download(
        AgentSshTransferRequest {
            target: target.clone(),
            expected_host_key_fingerprint: preview.fingerprint.clone(),
            remote_path,
            remote_path_prefixes: vec![prefix],
            authentication: authentication(),
        },
        &AtomicBool::new(false),
    )
    .expect("agent download");
    assert_eq!(download.basename, "round-trip.bin");
    assert_eq!(download.bytes.as_slice(), payload);

    let mut pty = AgentSshPtySession::open(
        AgentSshPtyRequest {
            target: target.clone(),
            expected_host_key_fingerprint: preview.fingerprint.clone(),
            authentication: authentication(),
            max_output_bytes: 8_192,
        },
        "xterm-256color",
        80,
        24,
        &AtomicBool::new(false),
    )
    .expect("agent pty");
    pty.resize(100, 30).expect("resize pty");
    pty.write_all(
        b"printf 'pty-ready\\n'; exit\n",
        &AtomicBool::new(false),
    )
        .expect("write pty");
    let mut pty_output = Vec::new();
    for _ in 0..200 {
        let (chunk, eof, _) = pty.read_available(8_192).expect("read pty");
        pty_output.extend_from_slice(&chunk);
        if eof {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(String::from_utf8_lossy(&pty_output).contains("pty-ready"));
    let _ = pty.close();

    let echo_listener = TcpListener::bind(("127.0.0.1", 0)).expect("echo listener");
    let echo_port = echo_listener.local_addr().expect("echo address").port();
    let echo = thread::spawn(move || {
        let (mut stream, _) = echo_listener.accept().expect("echo accept");
        let mut bytes = [0_u8; 4];
        std::io::Read::read_exact(&mut stream, &mut bytes).expect("echo read");
        std::io::Write::write_all(&mut stream, &bytes).expect("echo write");
    });
    let local_listener = TcpListener::bind(("127.0.0.1", 0)).expect("tunnel port");
    let local_port = local_listener.local_addr().expect("tunnel address").port();
    drop(local_listener);
    let tunnel = open_agent_tunnel(
        AgentSshTunnelRequest {
            target,
            expected_host_key_fingerprint: preview.fingerprint,
            authentication: authentication(),
            local_host: "127.0.0.1".into(),
            local_port,
            destination_host: "127.0.0.1".into(),
            destination_port: echo_port,
            max_connections: 1,
            ttl_millis: 5_000,
        },
        current_millis(),
        &AtomicBool::new(false),
    )
    .expect("agent tunnel");
    let mut tunneled = TcpStream::connect(("127.0.0.1", local_port)).expect("connect tunnel");
    tunneled
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("tunnel timeout");
    std::io::Write::write_all(&mut tunneled, b"ping").expect("tunnel write");
    let mut echoed = [0_u8; 4];
    std::io::Read::read_exact(&mut tunneled, &mut echoed).expect("tunnel read");
    assert_eq!(&echoed, b"ping");
    drop(tunnel);
    echo.join().expect("echo thread");

    drop(child);
    fs::remove_dir_all(root).expect("cleanup");
}
