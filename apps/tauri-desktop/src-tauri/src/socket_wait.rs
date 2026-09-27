//! Readiness waits for local listeners.
//!
//! Blocking in `poll()` wakes as soon as a connection arrives. Sleeping between
//! nonblocking `accept()` calls instead depends on timers, which macOS App Nap
//! throttles while the desktop window is in the background.

use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Readiness {
    Ready,
    Woken,
    TimedOut,
}

/// Waits until `source` is readable, `wake` is signalled or `timeout` elapses.
/// A signalled `wake` socket is drained before returning.
#[cfg(unix)]
pub(crate) fn wait_readable(
    source: std::os::fd::BorrowedFd<'_>,
    wake: Option<&std::os::unix::net::UnixStream>,
    timeout: Option<Duration>,
) -> std::io::Result<Readiness> {
    use std::os::fd::AsRawFd;
    let mut descriptors = [
        libc::pollfd {
            fd: source.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake.map_or(-1, AsRawFd::as_raw_fd),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let timeout = timeout.map_or(-1, |timeout| {
        i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX)
    });
    let ready = loop {
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, timeout) };
        if result >= 0 {
            break result;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    if ready == 0 {
        return Ok(Readiness::TimedOut);
    }
    if let Some(mut wake) = wake
        && descriptors[1].revents != 0
    {
        let mut buffer = [0_u8; 64];
        while matches!(std::io::Read::read(&mut wake, &mut buffer), Ok(count) if count > 0) {}
        return Ok(Readiness::Woken);
    }
    if descriptors[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err(std::io::Error::other("listener unavailable"));
    }
    Ok(Readiness::Ready)
}

/// Waits up to `timeout` for a pending connection on `listener`. The caller
/// still treats `WouldBlock` from `accept()` as a spurious wake-up.
#[cfg(unix)]
pub(crate) fn wait_for_connection(
    listener: &impl std::os::fd::AsFd,
    timeout: Duration,
) -> std::io::Result<Readiness> {
    wait_readable(listener.as_fd(), None, Some(timeout))
}

/// Platforms without App Nap keep the bounded polling interval.
#[cfg(not(unix))]
pub(crate) fn wait_for_connection<L>(_listener: &L, timeout: Duration) -> std::io::Result<Readiness> {
    std::thread::sleep(timeout.min(Duration::from_millis(10)));
    Ok(Readiness::Ready)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn wait_readable_reports_connection_wake_and_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            wait_for_connection(&listener, Duration::from_millis(20)).unwrap(),
            Readiness::TimedOut
        );

        let (wake_reader, mut wake_writer) = UnixStream::pair().unwrap();
        wake_reader.set_nonblocking(true).unwrap();
        wake_writer.write_all(&[1]).unwrap();
        assert_eq!(
            wait_readable(listener.as_fd(), Some(&wake_reader), None).unwrap(),
            Readiness::Woken
        );

        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        assert_eq!(
            wait_readable(listener.as_fd(), Some(&wake_reader), Some(Duration::from_secs(5))).unwrap(),
            Readiness::Ready
        );
        assert!(listener.accept().is_ok());
    }
}
