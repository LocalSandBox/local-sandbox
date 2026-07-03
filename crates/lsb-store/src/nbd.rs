#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use anyhow::{bail, Context};
#[cfg(unix)]
use tracing::{debug, warn};

#[cfg(unix)]
type NbdStream = std::os::unix::net::UnixStream;

pub trait NbdBackend: Send + Sync {
    fn size(&self) -> u64;
    fn read(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize>;
    fn write(&self, offset: u64, buf: &[u8]) -> std::io::Result<usize>;
    fn flush(&self) -> std::io::Result<()>;
}

impl NbdBackend for crate::backend::FlatFileBackend {
    fn size(&self) -> u64 {
        self.size()
    }

    fn read(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read(offset, buf)
    }

    fn write(&self, offset: u64, buf: &[u8]) -> std::io::Result<usize> {
        self.write(offset, buf)
    }

    fn flush(&self) -> std::io::Result<()> {
        self.flush()
    }
}

impl NbdBackend for crate::cas::CasBackend {
    fn size(&self) -> u64 {
        self.size()
    }

    fn read(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read(offset, buf)
    }

    fn write(&self, offset: u64, buf: &[u8]) -> std::io::Result<usize> {
        self.write(offset, buf)
    }

    fn flush(&self) -> std::io::Result<()> {
        self.flush()
    }
}

#[cfg(unix)]
const NBDMAGIC: u64 = 0x4e42444d41474943;
#[cfg(unix)]
const IHAVEOPT: u64 = 0x49484156454F5054;
#[cfg(unix)]
const REPLY_MAGIC: u64 = 0x3e889045565a9;
#[cfg(unix)]
const NBD_FLAG_FIXED_NEWSTYLE: u16 = 1 << 0;
#[cfg(unix)]
const NBD_FLAG_NO_ZEROES: u16 = 1 << 1;
#[cfg(unix)]
const NBD_FLAG_C_NO_ZEROES: u32 = 1 << 1;
#[cfg(unix)]
const NBD_FLAG_HAS_FLAGS: u16 = 1 << 0;
#[cfg(unix)]
const NBD_FLAG_SEND_FLUSH: u16 = 1 << 2;
#[cfg(unix)]
const NBD_OPT_EXPORT_NAME: u32 = 1;
#[cfg(unix)]
const NBD_OPT_ABORT: u32 = 2;
#[cfg(unix)]
const NBD_OPT_INFO: u32 = 6;
#[cfg(unix)]
const NBD_OPT_GO: u32 = 7;
#[cfg(unix)]
const NBD_REP_ACK: u32 = 1;
#[cfg(unix)]
const NBD_REP_INFO: u32 = 3;
#[cfg(unix)]
const NBD_REP_ERR_UNSUP: u32 = (1 << 31) | 1;
#[cfg(unix)]
const NBD_INFO_EXPORT: u16 = 0;
#[cfg(unix)]
const NBD_INFO_BLOCK_SIZE: u16 = 3;
#[cfg(unix)]
const NBD_CMD_READ: u16 = 0;
#[cfg(unix)]
const NBD_CMD_WRITE: u16 = 1;
#[cfg(unix)]
const NBD_CMD_DISC: u16 = 2;
#[cfg(unix)]
const NBD_CMD_FLUSH: u16 = 3;
#[cfg(unix)]
const NBD_SIMPLE_REPLY_MAGIC: u32 = 0x67446698;
#[cfg(unix)]
const NBD_OK: u32 = 0;
#[cfg(unix)]
const NBD_EIO: u32 = 5;
#[cfg(unix)]
const NBD_EINVAL: u32 = 22;

#[cfg(unix)]
pub fn handle_client(mut stream: NbdStream, backend: Arc<dyn NbdBackend>) -> anyhow::Result<()> {
    handshake(&mut stream, backend.as_ref())?;
    transmission(&mut stream, backend.as_ref())?;
    Ok(())
}

#[cfg(unix)]
fn handshake(stream: &mut NbdStream, backend: &dyn NbdBackend) -> anyhow::Result<()> {
    stream.write_all(&NBDMAGIC.to_be_bytes())?;
    stream.write_all(&IHAVEOPT.to_be_bytes())?;
    let server_flags = NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES;
    stream.write_all(&server_flags.to_be_bytes())?;
    stream.flush()?;

    let mut buf = [0u8; 4];
    stream
        .read_exact(&mut buf)
        .context("while reading NBD client flags after server hello")?;
    let client_flags = u32::from_be_bytes(buf);
    let no_zeroes = (client_flags & NBD_FLAG_C_NO_ZEROES) != 0;
    debug!(
        "NBD client flags={:#x}, no_zeroes={}",
        client_flags, no_zeroes
    );

    loop {
        let mut opt_header = [0u8; 16];
        stream
            .read_exact(&mut opt_header)
            .context("while reading NBD option header during negotiation")?;
        let magic = u64::from_be_bytes(opt_header[0..8].try_into().expect("slice"));
        if magic != IHAVEOPT {
            bail!("bad option magic: {:#x}", magic);
        }
        let option = u32::from_be_bytes(opt_header[8..12].try_into().expect("slice"));
        let data_len = u32::from_be_bytes(opt_header[12..16].try_into().expect("slice"));
        debug!("NBD option={} data_len={}", option, data_len);

        let mut opt_data = vec![0u8; data_len as usize];
        if data_len > 0 {
            stream.read_exact(&mut opt_data).with_context(|| {
                format!("while reading NBD option payload for option {}", option)
            })?;
        }

        match option {
            NBD_OPT_EXPORT_NAME => {
                let export_name = String::from_utf8_lossy(&opt_data);
                debug!("NBD export name request='{}'", export_name);
                let trans_flags = NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH;
                stream.write_all(&backend.size().to_be_bytes())?;
                stream.write_all(&trans_flags.to_be_bytes())?;
                if !no_zeroes {
                    stream.write_all(&[0u8; 124])?;
                }
                stream.flush()?;
                debug!(
                    "NBD handshake complete (EXPORT_NAME), size={}",
                    backend.size()
                );
                return Ok(());
            }
            NBD_OPT_INFO => {
                let req =
                    parse_info_request(&opt_data).context("while parsing NBD_OPT_INFO request")?;
                debug!(
                    "NBD INFO export='{}' requested_infos={:?}",
                    req.export_name, req.requested_infos
                );
                send_info_replies(stream, option, backend.size(), &req.requested_infos)?;
                send_option_reply(stream, option, NBD_REP_ACK, &[])?;
                stream.flush()?;
            }
            NBD_OPT_GO => {
                let req =
                    parse_info_request(&opt_data).context("while parsing NBD_OPT_GO request")?;
                debug!(
                    "NBD GO export='{}' requested_infos={:?}",
                    req.export_name, req.requested_infos
                );
                send_info_replies(stream, option, backend.size(), &req.requested_infos)?;
                send_option_reply(stream, option, NBD_REP_ACK, &[])?;
                stream.flush()?;
                debug!("NBD handshake complete (GO), size={}", backend.size());
                return Ok(());
            }
            NBD_OPT_ABORT => {
                send_option_reply(stream, option, NBD_REP_ACK, &[])?;
                stream.flush()?;
                anyhow::bail!("client aborted");
            }
            _ => {
                warn!("unsupported NBD option: {} ({} bytes)", option, data_len);
                send_option_reply(stream, option, NBD_REP_ERR_UNSUP, &[])?;
                stream.flush()?;
            }
        }
    }
}

#[cfg(unix)]
struct InfoRequest {
    export_name: String,
    requested_infos: Vec<u16>,
}

#[cfg(unix)]
fn parse_info_request(data: &[u8]) -> anyhow::Result<InfoRequest> {
    if data.len() < 6 {
        bail!(
            "payload too short: expected at least 6 bytes, got {}",
            data.len()
        );
    }

    let name_len = u32::from_be_bytes(data[0..4].try_into().expect("slice")) as usize;
    let name_end = 4 + name_len;
    if data.len() < name_end + 2 {
        bail!(
            "payload too short for export name: name_len={}, payload_len={}",
            name_len,
            data.len()
        );
    }

    let export_name = String::from_utf8_lossy(&data[4..name_end]).to_string();
    let info_count =
        u16::from_be_bytes(data[name_end..name_end + 2].try_into().expect("slice")) as usize;
    let expected_len = name_end + 2 + info_count * 2;
    if data.len() != expected_len {
        bail!(
            "unexpected payload length: expected {}, got {}",
            expected_len,
            data.len()
        );
    }

    let requested_infos = (0..info_count)
        .map(|i| {
            let start = name_end + 2 + i * 2;
            u16::from_be_bytes(data[start..start + 2].try_into().expect("slice"))
        })
        .collect();

    Ok(InfoRequest {
        export_name,
        requested_infos,
    })
}

#[cfg(unix)]
fn send_info_replies(
    stream: &mut NbdStream,
    option: u32,
    size: u64,
    requested_infos: &[u16],
) -> std::io::Result<()> {
    send_export_info(stream, option, size)?;

    if requested_infos.contains(&NBD_INFO_BLOCK_SIZE) {
        let mut info = Vec::with_capacity(14);
        info.extend_from_slice(&NBD_INFO_BLOCK_SIZE.to_be_bytes());
        info.extend_from_slice(&512u32.to_be_bytes());
        info.extend_from_slice(&4096u32.to_be_bytes());
        info.extend_from_slice(&u32::MAX.to_be_bytes());
        send_option_reply(stream, option, NBD_REP_INFO, &info)?;
    }

    Ok(())
}

#[cfg(unix)]
fn send_export_info(stream: &mut NbdStream, option: u32, size: u64) -> std::io::Result<()> {
    let trans_flags = NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH;
    let mut info = Vec::with_capacity(12);
    info.extend_from_slice(&NBD_INFO_EXPORT.to_be_bytes());
    info.extend_from_slice(&size.to_be_bytes());
    info.extend_from_slice(&trans_flags.to_be_bytes());
    send_option_reply(stream, option, NBD_REP_INFO, &info)
}

#[cfg(unix)]
fn send_option_reply(
    stream: &mut NbdStream,
    option: u32,
    reply_type: u32,
    data: &[u8],
) -> std::io::Result<()> {
    stream.write_all(&REPLY_MAGIC.to_be_bytes())?;
    stream.write_all(&option.to_be_bytes())?;
    stream.write_all(&reply_type.to_be_bytes())?;
    stream.write_all(&(data.len() as u32).to_be_bytes())?;
    if !data.is_empty() {
        stream.write_all(data)?;
    }
    Ok(())
}

#[cfg(unix)]
fn transmission(stream: &mut NbdStream, backend: &dyn NbdBackend) -> anyhow::Result<()> {
    let mut req_header = [0u8; 28];

    loop {
        if let Err(e) = stream.read_exact(&mut req_header) {
            match e.kind() {
                std::io::ErrorKind::UnexpectedEof => {
                    debug!("NBD client disconnected");
                    return Ok(());
                }
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    debug!("NBD read timeout, exiting");
                    return Ok(());
                }
                _ => {
                    return Err(e).context("while reading NBD transmission request header");
                }
            }
        }

        let magic = u32::from_be_bytes(req_header[0..4].try_into().expect("slice"));
        if magic != 0x25609513 {
            anyhow::bail!("bad request magic: {:#x}", magic);
        }

        let cmd_type = u16::from_be_bytes(req_header[6..8].try_into().expect("slice"));
        let handle = &req_header[8..16];
        let offset = u64::from_be_bytes(req_header[16..24].try_into().expect("slice"));
        let length = u32::from_be_bytes(req_header[24..28].try_into().expect("slice"));

        match cmd_type {
            NBD_CMD_READ => {
                let mut buf = vec![0u8; length as usize];
                let error = match backend.read(offset, &mut buf) {
                    Ok(n) => {
                        if n < length as usize {
                            buf[n..].fill(0);
                        }
                        NBD_OK
                    }
                    Err(e) => {
                        warn!("NBD read error at offset {}: {}", offset, e);
                        NBD_EIO
                    }
                };
                send_reply(
                    stream,
                    error,
                    handle,
                    if error == NBD_OK { Some(&buf) } else { None },
                )?;
            }
            NBD_CMD_WRITE => {
                let mut data = vec![0u8; length as usize];
                stream.read_exact(&mut data).with_context(|| {
                    format!("while reading NBD write payload ({} bytes)", length)
                })?;
                let error = match backend.write(offset, &data) {
                    Ok(_) => NBD_OK,
                    Err(e) => {
                        warn!("NBD write error at offset {}: {}", offset, e);
                        NBD_EIO
                    }
                };
                send_reply(stream, error, handle, None)?;
            }
            NBD_CMD_FLUSH => {
                let error = match backend.flush() {
                    Ok(()) => NBD_OK,
                    Err(e) => {
                        warn!("NBD flush error: {}", e);
                        NBD_EIO
                    }
                };
                send_reply(stream, error, handle, None)?;
            }
            NBD_CMD_DISC => {
                debug!("NBD client sent disconnect");
                return Ok(());
            }
            _ => {
                warn!("unsupported NBD command: {}", cmd_type);
                send_reply(stream, NBD_EINVAL, handle, None)?;
            }
        }
    }
}

#[cfg(unix)]
fn send_reply(
    stream: &mut NbdStream,
    error: u32,
    handle: &[u8],
    data: Option<&[u8]>,
) -> std::io::Result<()> {
    stream.write_all(&NBD_SIMPLE_REPLY_MAGIC.to_be_bytes())?;
    stream.write_all(&error.to_be_bytes())?;
    stream.write_all(handle)?;
    if let Some(data) = data {
        stream.write_all(data)?;
    }
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::FlatFileBackend;
    use std::io::Write;
    use std::sync::Arc;

    fn create_test_backend() -> (tempfile::NamedTempFile, Arc<FlatFileBackend>) {
        let mut tmp = tempfile::NamedTempFile::new().expect("temp file");
        let data = vec![0xABu8; 1024 * 1024];
        tmp.write_all(&data).expect("write");
        tmp.flush().expect("flush");
        let backend =
            Arc::new(FlatFileBackend::open(tmp.path().to_str().expect("path")).expect("backend"));
        (tmp, backend)
    }

    #[test]
    fn backend_read_write() {
        let (_tmp, backend) = create_test_backend();
        let mut buf = [0u8; 4];
        backend.read(0, &mut buf).expect("read");
        assert_eq!(buf, [0xAB; 4]);

        backend.write(0, &[1, 2, 3, 4]).expect("write");
        backend.read(0, &mut buf).expect("read");
        assert_eq!(buf, [1, 2, 3, 4]);
    }
}
