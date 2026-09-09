use std::{fs, io::Write, path::Path};

use atomic_write_file::OpenOptions as AtomicOpenOptions;

const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) fn read_vault(path: &Path) -> Result<Vec<u8>, ()> {
    let metadata = fs::metadata(path).map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() > MAX_VAULT_BYTES {
        return Err(());
    }
    fs::read(path).map_err(|_| ())
}

#[cfg(test)]
thread_local! { pub(crate) static FAIL_WRITE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

pub(crate) fn write_vault(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    #[cfg(test)]
    if FAIL_WRITE.with(|count| {
        let n = count.get();
        if n > 0 {
            count.set(n - 1);
            n == 1
        } else {
            false
        }
    }) {
        return Err(());
    }
    if bytes.len() as u64 > MAX_VAULT_BYTES {
        return Err(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| ())?;
    }

    let mut options = AtomicOpenOptions::new();
    #[cfg(unix)]
    {
        use atomic_write_file::unix::OpenOptionsExt as AtomicOpenOptionsExt;
        use std::os::unix::fs::OpenOptionsExt as StandardOpenOptionsExt;

        AtomicOpenOptionsExt::preserve_mode(&mut options, false);
        StandardOpenOptionsExt::mode(&mut options, 0o600);
    }

    let mut file = options.open(path).map_err(|_| ())?;
    file.write_all(bytes).map_err(|_| ())?;
    file.commit().map_err(|_| ())?;

    Ok(())
}
