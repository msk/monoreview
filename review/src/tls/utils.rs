use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use tempfile::Builder;

use super::TlsError;

pub(super) fn date() -> (i32, u8, u8) {
    use chrono::Datelike;

    let now = chrono::Utc::now();
    let year = now.year();
    let month: u8 = now
        .month()
        .try_into()
        .expect("month() returns value range from 1 to 12");
    let day: u8 = now
        .day()
        .try_into()
        .expect("day() returns value range from 1 to 31");

    (year, month, day)
}

/// Atomically writes certificates to a file using a temporary file approach.
///
/// This function creates a temporary file in the same directory as the target
/// file, writes the certificate to it, flushes the data to ensure it's written
/// to disk, and then atomically moves the temporary file to the target path.
/// This approach ensures that the target file is never left in a partially
/// written state, even if the process is interrupted during the write
/// operation.
///
/// # Errors
///
/// If any I/O operation fails.
pub(super) fn write_cert_to_file(target_path: &PathBuf, cert: &[u8]) -> Result<(), TlsError> {
    let target_dir = target_path.parent().unwrap_or(Path::new("."));
    let target_file_name = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed");
    let mut temp_file = Builder::new()
        .prefix(&format!(".{target_file_name}_"))
        .suffix(".tmp")
        .tempfile_in(target_dir)
        .map_err(TlsError::Write)?;

    temp_file.write_all(cert).map_err(TlsError::Write)?;
    temp_file.flush().map_err(TlsError::Write)?;
    temp_file
        .persist(target_path)
        .map_err(|e| TlsError::Write(e.error))?;

    Ok(())
}

/// Securely writes both a certificate and its private key to separate files
/// atomically.
///
/// This function writes certificate and private key data to their respective
/// paths using temporary files and atomic rename operations. Both files are
/// written concurrently and both operations must succeed for the function to
/// return success. If either write fails, neither file will be left in a
/// partial state.
///
/// # Errors
///
/// Returns `TlsError::SamePath` if both paths point to the same file.
/// Returns `TlsError::Write` if any I/O operation fails.
pub(super) fn write_cert_key_to_file(
    cert_target_path: &PathBuf,
    key_target_path: &PathBuf,
    cert: &[u8],
    key: &[u8],
) -> Result<(), TlsError> {
    // Check if both paths point to the same file
    if cert_target_path == key_target_path {
        return Err(TlsError::SamePath);
    }

    let cert_backup = if cert_target_path.exists() {
        Some(fs::read(cert_target_path).map_err(|e| TlsError::Read("Certificate".to_string(), e))?)
    } else {
        None
    };

    let cert_target_dir = cert_target_path.parent().unwrap_or(Path::new("."));
    let key_target_dir = key_target_path.parent().unwrap_or(Path::new("."));

    let cert_file_name = cert_target_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed_cert");
    let key_file_name = key_target_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed_key");

    let mut cert_temp_file = Builder::new()
        .prefix(&format!(".{cert_file_name}_"))
        .suffix(".tmp")
        .tempfile_in(cert_target_dir)
        .map_err(TlsError::Write)?;
    let mut key_temp_file = Builder::new()
        .prefix(&format!(".{key_file_name}_"))
        .suffix(".tmp")
        .tempfile_in(key_target_dir)
        .map_err(TlsError::Write)?;

    cert_temp_file.write_all(cert).map_err(TlsError::Write)?;
    cert_temp_file.flush().map_err(TlsError::Write)?;
    key_temp_file.write_all(key).map_err(TlsError::Write)?;
    key_temp_file.flush().map_err(TlsError::Write)?;

    cert_temp_file
        .persist(cert_target_path)
        .map_err(|e| TlsError::Write(e.error))?;

    if let Err(e) = key_temp_file.persist(key_target_path) {
        // Only need to rollback the certificate since key persist failed
        // The original key file is still unchanged
        if let Some(original_cert) = cert_backup {
            let _ = fs::write(cert_target_path, original_cert);
        } else {
            let _ = fs::remove_file(cert_target_path);
        }
        return Err(TlsError::Write(e.error));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_write_cert_to_file_success() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("test_cert.pem");
        let cert_data = b"test certificate data";

        let result = write_cert_to_file(&cert_path, cert_data);

        assert!(result.is_ok());
        assert!(cert_path.exists());

        let written_data = fs::read(&cert_path).unwrap();
        assert_eq!(written_data, cert_data);
    }

    #[test]
    fn test_write_cert_key_to_file_success() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("test_cert.pem");
        let key_path = temp_dir.path().join("test_key.pem");

        let cert_data = b"test certificate data";
        let key_data = b"test private key data";

        let result = write_cert_key_to_file(&cert_path, &key_path, cert_data, key_data);

        assert!(result.is_ok());
        assert!(cert_path.exists());
        assert!(key_path.exists());

        let written_cert = fs::read(&cert_path).unwrap();
        let written_key = fs::read(&key_path).unwrap();
        assert_eq!(written_cert, cert_data);
        assert_eq!(written_key, key_data);
    }

    #[test]
    fn test_write_cert_to_file_overwrite_existing() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("overwrite_cert.pem");

        // Write initial data
        let initial_data = b"initial certificate data";
        fs::write(&cert_path, initial_data).unwrap();

        // Overwrite with new data
        let new_data = b"new certificate data";
        let result = write_cert_to_file(&cert_path, new_data);

        assert!(result.is_ok());

        let written_data = fs::read(&cert_path).unwrap();
        assert_eq!(written_data, new_data);
    }

    #[test]
    fn test_write_cert_key_to_file_overwrite_existing() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("overwrite_cert.pem");
        let key_path = temp_dir.path().join("overwrite_key.pem");

        // Write initial data
        let initial_cert = b"initial certificate";
        let initial_key = b"initial key";
        fs::write(&cert_path, initial_cert).unwrap();
        fs::write(&key_path, initial_key).unwrap();

        // Overwrite with new data
        let new_cert = b"new certificate";
        let new_key = b"new key";
        let result = write_cert_key_to_file(&cert_path, &key_path, new_cert, new_key);

        assert!(result.is_ok());

        let written_cert = fs::read(&cert_path).unwrap();
        let written_key = fs::read(&key_path).unwrap();
        assert_eq!(written_cert, new_cert);
        assert_eq!(written_key, new_key);
    }

    #[test]
    fn test_write_cert_to_file_nested_directory() {
        let temp_dir = TempDir::new().unwrap();
        let nested_dir = temp_dir.path().join("nested").join("deep");
        fs::create_dir_all(&nested_dir).unwrap();

        let cert_path = nested_dir.join("nested_cert.pem");
        let cert_data = b"test certificate in nested directory";

        let result = write_cert_to_file(&cert_path, cert_data);

        assert!(result.is_ok());
        assert!(cert_path.exists());

        let written_data = fs::read(&cert_path).unwrap();
        assert_eq!(written_data, cert_data);
    }

    #[test]
    fn test_write_cert_key_to_file_different_directories() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path().join("certs");
        let key_dir = temp_dir.path().join("keys");

        fs::create_dir_all(&cert_dir).unwrap();
        fs::create_dir_all(&key_dir).unwrap();

        let cert_path = cert_dir.join("test_cert.pem");
        let key_path = key_dir.join("test_key.pem");

        let cert_data = b"certificate in certs directory";
        let key_data = b"key in keys directory";

        let result = write_cert_key_to_file(&cert_path, &key_path, cert_data, key_data);

        assert!(result.is_ok());
        assert!(cert_path.exists());
        assert!(key_path.exists());

        let written_cert = fs::read(&cert_path).unwrap();
        let written_key = fs::read(&key_path).unwrap();
        assert_eq!(written_cert, cert_data);
        assert_eq!(written_key, key_data);
    }

    #[test]
    fn test_write_cert_key_to_file_same_path_error() {
        let temp_dir = TempDir::new().unwrap();
        let same_path = temp_dir.path().join("same_file.pem");

        let cert_data = b"certificate data";
        let key_data = b"key data";

        let result = write_cert_key_to_file(&same_path, &same_path, cert_data, key_data);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TlsError::SamePath));
        assert!(!same_path.exists()); // No file should be created
    }

    #[test]
    fn test_write_cert_key_to_file_rollback_on_key_failure() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("test_cert.pem");
        let key_path = temp_dir.path().join("test_key.pem");

        // Write initial cert and key files
        let original_cert = b"original certificate";
        let original_key = b"original key";
        fs::write(&cert_path, original_cert).unwrap();
        fs::write(&key_path, original_key).unwrap();

        // Create a directory with the same name as key_path to make persist() fail
        // so that it can't overwrite a directory with a file
        fs::remove_file(&key_path).unwrap(); // Remove the key file first
        fs::create_dir(&key_path).unwrap(); // Create directory with same name

        let new_cert = b"new certificate";
        let new_key = b"new key";

        // This should fail when trying to persist the key because key_path is now a directory
        let result = write_cert_key_to_file(&cert_path, &key_path, new_cert, new_key);

        // Clean up the directory we created
        fs::remove_dir(&key_path).unwrap();

        // Restore the original key file manually for test
        fs::write(&key_path, original_key).unwrap();

        // The operation should fail
        assert!(result.is_err());

        // Certificate should be restored to original content
        let restored_cert = fs::read(&cert_path).unwrap();
        assert_eq!(restored_cert, original_cert);

        // Key should be back to original content (We manually restored original key)
        let restored_key = fs::read(&key_path).unwrap();
        assert_eq!(restored_key, original_key);
    }

    #[test]
    fn test_write_cert_key_to_file_rollback_removes_new_files() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("new_cert.pem");
        let key_path = temp_dir.path().join("new_key.pem");

        // No original files exist
        assert!(!cert_path.exists());
        assert!(!key_path.exists());

        // Create a directory with the same name as key_path to make persist() fail
        fs::create_dir(&key_path).unwrap();

        let new_cert = b"new certificate";
        let new_key = b"new key";

        // This should fail when trying to persist the key because key_path is a directory
        let result = write_cert_key_to_file(&cert_path, &key_path, new_cert, new_key);

        // Clean up the directory we created
        fs::remove_dir(&key_path).unwrap();

        // The operation should fail
        assert!(result.is_err());

        // Certificate should be removed since no original existed
        assert!(!cert_path.exists());

        // Key should not exist (it was never successfully persisted)
        assert!(!key_path.exists());
    }
}
