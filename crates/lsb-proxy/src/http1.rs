use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::sync::Notify;

use crate::config::RequestHeaderRule;
use crate::policy::normalize_domain;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_LINE_BYTES: usize = 16 * 1024;

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct TransformStats {
    pub bytes_read: u64,
    pub requests: u64,
    pub replacements: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    None,
    Fixed(u64),
    Chunked,
}

struct ParsedRequest {
    request_line: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    framing: BodyFraming,
    upgrade_requested: bool,
}

pub(crate) async fn transform_requests<R, W>(
    reader: &mut R,
    writer: &mut W,
    expected_domain: &str,
    rules: &[RequestHeaderRule],
    substitutions: &[(String, String)],
    opaque_upgrade: Arc<AtomicBool>,
    upgrade_pending: Arc<AtomicBool>,
    upgrade_notify: Arc<Notify>,
) -> io::Result<TransformStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let patterns = substitution_bytes(substitutions)?;
    let mut reader = BufReader::new(reader);
    let mut stats = TransformStats::default();

    loop {
        if opaque_upgrade.load(Ordering::Acquire) {
            stats.bytes_read += tokio::io::copy(&mut reader, writer).await?;
            writer.flush().await?;
            return Ok(stats);
        }

        let mut block = Vec::new();
        let has_headers = loop {
            let notified = upgrade_notify.notified();
            tokio::pin!(notified);

            if opaque_upgrade.load(Ordering::Acquire) {
                break false;
            }

            tokio::select! {
                biased;
                _ = &mut notified => {
                    if opaque_upgrade.load(Ordering::Acquire) {
                        break false;
                    }
                }
                result = read_header_block(&mut reader, &mut block) => {
                    match result? {
                        true => break true,
                        false => return Ok(stats),
                    }
                }
            }
        };
        if !has_headers {
            stats.bytes_read += block.len() as u64;
            writer.write_all(&block).await?;
            stats.bytes_read += tokio::io::copy(&mut reader, writer).await?;
            writer.flush().await?;
            return Ok(stats);
        };
        stats.bytes_read += block.len() as u64;
        let request = parse_request(&block)?;
        authorize_request_host(&request.headers, expected_domain)?;
        stats.requests += 1;

        if request.upgrade_requested {
            upgrade_pending.store(true, Ordering::Release);
        }

        let scan_body = !patterns.is_empty();
        let original_framing = request.framing;
        let rewritten_framing = if scan_body && matches!(original_framing, BodyFraming::Fixed(_)) {
            BodyFraming::Chunked
        } else {
            request.framing
        };
        let (headers, replacements) =
            serialize_request(request, rules, &patterns, rewritten_framing)?;
        stats.replacements += replacements;
        writer.write_all(&headers).await?;

        match (original_framing, scan_body) {
            (BodyFraming::None, _) => {}
            (BodyFraming::Fixed(length), false) => {
                copy_exact(&mut reader, writer, length, &mut stats).await?;
            }
            (BodyFraming::Fixed(length), true) => {
                transform_fixed_body(&mut reader, writer, length, &patterns, &mut stats).await?;
            }
            (BodyFraming::Chunked, false) => {
                relay_chunked_body(&mut reader, writer, &mut stats).await?;
            }
            (BodyFraming::Chunked, true) => {
                transform_chunked_body(&mut reader, writer, &patterns, &mut stats).await?;
            }
        }
        writer.flush().await?;
    }
}

fn authorize_request_host(headers: &[(Vec<u8>, Vec<u8>)], expected_domain: &str) -> io::Result<()> {
    let hosts = header_values(headers, b"host").collect::<Vec<_>>();
    if hosts.len() != 1 {
        return Err(invalid_data(
            "intercepted HTTP request requires exactly one Host header",
        ));
    }
    let authority = std::str::from_utf8(trim_ascii(hosts[0]))
        .map_err(|_| invalid_data("intercepted HTTP Host is not UTF-8"))?;
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.parse::<u16>() == Ok(443) => host,
        Some(_) => return Err(invalid_data("intercepted HTTP Host authority is invalid")),
        None => authority,
    };
    let actual =
        normalize_domain(host).ok_or_else(|| invalid_data("intercepted HTTP Host is invalid"))?;
    let expected = normalize_domain(expected_domain)
        .ok_or_else(|| invalid_data("intercepted TLS domain is invalid"))?;
    if actual != expected {
        return Err(invalid_data(
            "intercepted HTTP Host differs from the authorized TLS domain",
        ));
    }
    Ok(())
}

fn substitution_bytes(substitutions: &[(String, String)]) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut patterns = substitutions
        .iter()
        .map(|(from, to)| (from.as_bytes().to_vec(), to.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    patterns.sort_by(|left, right| left.0.cmp(&right.0));
    for (index, (pattern, _)) in patterns.iter().enumerate() {
        if pattern.is_empty() {
            return Err(invalid_data("empty secret placeholder"));
        }
        if patterns[index + 1..]
            .iter()
            .any(|(other, _)| pattern.starts_with(other) || other.starts_with(pattern))
        {
            return Err(invalid_data("overlapping secret placeholders"));
        }
    }
    Ok(patterns)
}

async fn read_header_block<R>(reader: &mut R, block: &mut Vec<u8>) -> io::Result<bool>
where
    R: AsyncBufRead + Unpin,
{
    loop {
        let read = read_until_limited(
            reader,
            b'\n',
            block,
            MAX_HEADER_BYTES,
            "HTTP request headers exceed limit",
        )
        .await?;
        if read == 0 {
            if block.is_empty() {
                return Ok(false);
            }
            return Err(unexpected_eof("incomplete HTTP request headers"));
        }
        if block.ends_with(b"\r\n\r\n") {
            return Ok(true);
        }
        if block.ends_with(b"\n\n") {
            return Err(invalid_data("HTTP request headers require CRLF framing"));
        }
    }
}

fn parse_request(block: &[u8]) -> io::Result<ParsedRequest> {
    let mut parsed_headers = [httparse::EMPTY_HEADER; 128];
    let mut parsed = httparse::Request::new(&mut parsed_headers);
    let status = parsed
        .parse(block)
        .map_err(|_| invalid_data("malformed HTTP/1.1 request headers"))?;
    if !status.is_complete() || parsed.version != Some(1) {
        return Err(invalid_data(
            "interception requires a complete HTTP/1.1 request",
        ));
    }

    let first_end = block
        .windows(2)
        .position(|bytes| bytes == b"\r\n")
        .ok_or_else(|| invalid_data("malformed HTTP request line"))?;
    let request_line = block[..first_end].to_vec();
    let mut header_bytes = &block[first_end + 2..block.len() - 2];
    let mut headers = Vec::with_capacity(parsed.headers.len());
    while !header_bytes.is_empty() {
        let line_end = header_bytes
            .windows(2)
            .position(|bytes| bytes == b"\r\n")
            .ok_or_else(|| invalid_data("HTTP request headers require CRLF framing"))?;
        let line = &header_bytes[..line_end];
        header_bytes = &header_bytes[line_end + 2..];
        if line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            return Err(invalid_data("obsolete folded HTTP headers are rejected"));
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| invalid_data("malformed HTTP/1.1 request headers"))?;
        headers.push((line[..colon].to_vec(), line[colon + 1..].to_vec()));
    }
    if headers.len() != parsed.headers.len() {
        return Err(invalid_data("malformed HTTP/1.1 request headers"));
    }

    let content_lengths = header_values(&headers, b"content-length")
        .map(parse_content_length)
        .collect::<io::Result<Vec<_>>>()?;
    let content_length = content_lengths.first().copied();
    if content_lengths
        .iter()
        .any(|length| Some(*length) != content_length)
    {
        return Err(invalid_data("conflicting Content-Length headers"));
    }

    let transfer_encodings = header_values(&headers, b"transfer-encoding").collect::<Vec<_>>();
    if content_length.is_some() && !transfer_encodings.is_empty() {
        return Err(invalid_data(
            "Content-Length with Transfer-Encoding is rejected",
        ));
    }
    let chunked = if transfer_encodings.is_empty() {
        false
    } else if transfer_encodings.len() == 1
        && trim_ascii(transfer_encodings[0]).eq_ignore_ascii_case(b"chunked")
    {
        true
    } else {
        return Err(invalid_data("unsupported HTTP request transfer coding"));
    };

    let upgrade_requested = header_values(&headers, b"upgrade").next().is_some()
        && header_values(&headers, b"connection").any(|value| {
            value
                .split(|byte| *byte == b',')
                .any(|token| trim_ascii(token).eq_ignore_ascii_case(b"upgrade"))
        });
    let framing = if chunked {
        BodyFraming::Chunked
    } else if let Some(length) = content_length {
        if length == 0 {
            BodyFraming::None
        } else {
            BodyFraming::Fixed(length)
        }
    } else {
        BodyFraming::None
    };

    Ok(ParsedRequest {
        request_line,
        headers,
        framing,
        upgrade_requested,
    })
}

fn header_values<'a>(
    headers: &'a [(Vec<u8>, Vec<u8>)],
    name: &'a [u8],
) -> impl Iterator<Item = &'a [u8]> {
    headers
        .iter()
        .filter(move |(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_slice())
}

fn parse_content_length(value: &[u8]) -> io::Result<u64> {
    let value = trim_ascii(value);
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(invalid_data("invalid Content-Length"));
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| invalid_data("invalid Content-Length"))
}

fn serialize_request(
    mut request: ParsedRequest,
    rules: &[RequestHeaderRule],
    substitutions: &[(Vec<u8>, Vec<u8>)],
    framing: BodyFraming,
) -> io::Result<(Vec<u8>, u64)> {
    let mut replacements = 0;
    let mut parts = request.request_line.splitn(3, |byte| *byte == b' ');
    let method = parts
        .next()
        .ok_or_else(|| invalid_data("malformed HTTP request line"))?;
    let target = parts
        .next()
        .ok_or_else(|| invalid_data("malformed HTTP request line"))?;
    let version = parts
        .next()
        .ok_or_else(|| invalid_data("malformed HTTP request line"))?;
    let (target, count) = replace_complete(target, substitutions);
    replacements += count;
    if target.is_empty()
        || target
            .iter()
            .any(|byte| byte.is_ascii_control() || *byte == b' ')
    {
        return Err(invalid_data(
            "secret substitution produced an invalid request target",
        ));
    }

    for rule in rules {
        request
            .headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case(rule.name.as_bytes()));
    }
    if framing != request.framing {
        request.headers.retain(|(name, _)| {
            !name.eq_ignore_ascii_case(b"content-length")
                && !name.eq_ignore_ascii_case(b"transfer-encoding")
        });
    }

    let mut output = Vec::with_capacity(MAX_HEADER_BYTES.min(request.request_line.len() + 256));
    output.extend_from_slice(method);
    output.push(b' ');
    output.extend_from_slice(&target);
    output.push(b' ');
    output.extend_from_slice(version);
    output.extend_from_slice(b"\r\n");

    for (name, value) in &request.headers {
        let (value, count) = replace_complete(value, substitutions);
        replacements += count;
        validate_field_value(&value)?;
        output.extend_from_slice(name);
        output.extend_from_slice(b":");
        output.extend_from_slice(&value);
        output.extend_from_slice(b"\r\n");
    }
    for rule in rules {
        let (value, count) = replace_complete(rule.value.as_bytes(), substitutions);
        replacements += count;
        validate_field_value(&value)?;
        output.extend_from_slice(rule.name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(&value);
        output.extend_from_slice(b"\r\n");
    }
    if framing != request.framing {
        output.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    output.extend_from_slice(b"\r\n");
    if output.len() > MAX_HEADER_BYTES {
        return Err(invalid_data(
            "transformed HTTP request headers exceed limit",
        ));
    }
    Ok((output, replacements))
}

async fn copy_exact<R, W>(
    reader: &mut R,
    writer: &mut W,
    length: u64,
    stats: &mut TransformStats,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let copied = tokio::io::copy(&mut reader.take(length), writer).await?;
    if copied != length {
        return Err(unexpected_eof("incomplete fixed-length HTTP request body"));
    }
    stats.bytes_read += copied;
    Ok(())
}

async fn transform_fixed_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    length: u64,
    patterns: &[(Vec<u8>, Vec<u8>)],
    stats: &mut TransformStats,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = length;
    let mut replacer = StreamingReplacer::new(patterns);
    let mut buffer = vec![0; 16 * 1024];
    while remaining > 0 {
        let wanted = buffer.len().min(remaining as usize);
        let read = reader.read(&mut buffer[..wanted]).await?;
        if read == 0 {
            return Err(unexpected_eof("incomplete fixed-length HTTP request body"));
        }
        remaining -= read as u64;
        stats.bytes_read += read as u64;
        let output = replacer.feed(&buffer[..read]);
        write_chunk(writer, &output).await?;
    }
    let output = replacer.finish();
    write_chunk(writer, &output).await?;
    stats.replacements += replacer.replacements;
    writer.write_all(b"0\r\n\r\n").await
}

async fn relay_chunked_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    stats: &mut TransformStats,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let line = read_crlf_line(reader, "chunk size").await?;
        stats.bytes_read += line.len() as u64;
        let size = parse_chunk_size(&line)?;
        writer.write_all(&line).await?;
        if size == 0 {
            relay_trailers(reader, writer, &[], stats).await?;
            return Ok(());
        }
        copy_exact(reader, writer, size, stats).await?;
        let ending = read_exact_vec(reader, 2, "chunk terminator").await?;
        stats.bytes_read += 2;
        if ending != b"\r\n" {
            return Err(invalid_data("invalid HTTP chunk terminator"));
        }
        writer.write_all(&ending).await?;
    }
}

async fn transform_chunked_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    patterns: &[(Vec<u8>, Vec<u8>)],
    stats: &mut TransformStats,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut replacer = StreamingReplacer::new(patterns);
    loop {
        let line = read_crlf_line(reader, "chunk size").await?;
        stats.bytes_read += line.len() as u64;
        let size = parse_chunk_size(&line)?;
        if size == 0 {
            let output = replacer.finish();
            write_chunk(writer, &output).await?;
            stats.replacements += replacer.replacements;
            writer.write_all(b"0\r\n").await?;
            relay_trailers(reader, writer, patterns, stats).await?;
            return Ok(());
        }
        let mut remaining = size;
        let mut buffer = vec![0; 16 * 1024];
        while remaining > 0 {
            let wanted = buffer.len().min(remaining as usize);
            let read = reader.read(&mut buffer[..wanted]).await?;
            if read == 0 {
                return Err(unexpected_eof("incomplete HTTP chunk data"));
            }
            remaining -= read as u64;
            stats.bytes_read += read as u64;
            let output = replacer.feed(&buffer[..read]);
            write_chunk(writer, &output).await?;
        }
        let ending = read_exact_vec(reader, 2, "chunk terminator").await?;
        stats.bytes_read += 2;
        if ending != b"\r\n" {
            return Err(invalid_data("invalid HTTP chunk terminator"));
        }
    }
}

async fn relay_trailers<R, W>(
    reader: &mut R,
    writer: &mut W,
    patterns: &[(Vec<u8>, Vec<u8>)],
    stats: &mut TransformStats,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0;
    loop {
        let line = read_crlf_line(reader, "chunk trailer").await?;
        stats.bytes_read += line.len() as u64;
        total += line.len();
        if total > MAX_HEADER_BYTES {
            return Err(invalid_data("HTTP request trailers exceed limit"));
        }
        if line == b"\r\n" {
            writer.write_all(&line).await?;
            return Ok(());
        }
        let content = &line[..line.len() - 2];
        let colon = content
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| invalid_data("malformed HTTP request trailer"))?;
        let name = &content[..colon];
        if name.is_empty() || !name.iter().copied().all(is_token_byte) {
            return Err(invalid_data("malformed HTTP request trailer"));
        }
        let (value, count) = replace_complete(&content[colon + 1..], patterns);
        stats.replacements += count;
        validate_field_value(&value)?;
        writer.write_all(name).await?;
        writer.write_all(b":").await?;
        writer.write_all(&value).await?;
        writer.write_all(b"\r\n").await?;
    }
}

async fn read_crlf_line<R>(reader: &mut R, context: &str) -> io::Result<Vec<u8>>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    let read = read_until_limited(
        reader,
        b'\n',
        &mut line,
        MAX_LINE_BYTES,
        &format!("invalid HTTP {context}"),
    )
    .await?;
    if read == 0 {
        return Err(unexpected_eof(&format!("incomplete HTTP {context}")));
    }
    if !line.ends_with(b"\r\n") {
        return Err(invalid_data(&format!("invalid HTTP {context}")));
    }
    Ok(line)
}

async fn read_until_limited<R>(
    reader: &mut R,
    delimiter: u8,
    output: &mut Vec<u8>,
    limit: usize,
    limit_message: &str,
) -> io::Result<usize>
where
    R: AsyncBufRead + Unpin,
{
    let initial_length = output.len();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(output.len() - initial_length);
        }

        let length = available
            .iter()
            .position(|byte| *byte == delimiter)
            .map_or(available.len(), |position| position + 1);
        if output.len().saturating_add(length) > limit {
            return Err(invalid_data(limit_message));
        }

        output.extend_from_slice(&available[..length]);
        reader.consume(length);
        if output.last() == Some(&delimiter) {
            return Ok(output.len() - initial_length);
        }
    }
}

fn parse_chunk_size(line: &[u8]) -> io::Result<u64> {
    let size = line[..line.len() - 2]
        .split(|byte| *byte == b';')
        .next()
        .map(trim_ascii)
        .unwrap_or_default();
    if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid_data("invalid HTTP chunk size"));
    }
    std::str::from_utf8(size)
        .ok()
        .and_then(|size| u64::from_str_radix(size, 16).ok())
        .ok_or_else(|| invalid_data("invalid HTTP chunk size"))
}

async fn read_exact_vec<R>(reader: &mut R, length: usize, context: &str) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut value = vec![0; length];
    reader
        .read_exact(&mut value)
        .await
        .map_err(|_| unexpected_eof(&format!("incomplete HTTP {context}")))?;
    Ok(value)
}

async fn write_chunk<W>(writer: &mut W, data: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if data.is_empty() {
        return Ok(());
    }
    writer
        .write_all(format!("{:x}\r\n", data.len()).as_bytes())
        .await?;
    writer.write_all(data).await?;
    writer.write_all(b"\r\n").await
}

fn replace_complete(data: &[u8], patterns: &[(Vec<u8>, Vec<u8>)]) -> (Vec<u8>, u64) {
    if patterns.is_empty() {
        return (data.to_vec(), 0);
    }
    let mut replacer = StreamingReplacer::new(patterns);
    let mut output = replacer.feed(data);
    output.extend(replacer.finish());
    (output, replacer.replacements)
}

struct StreamingReplacer<'a> {
    patterns: &'a [(Vec<u8>, Vec<u8>)],
    pending: Vec<u8>,
    replacements: u64,
}

impl<'a> StreamingReplacer<'a> {
    fn new(patterns: &'a [(Vec<u8>, Vec<u8>)]) -> Self {
        Self {
            patterns,
            pending: Vec::new(),
            replacements: 0,
        }
    }

    fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(data);
        self.drain(false)
    }

    fn finish(&mut self) -> Vec<u8> {
        self.drain(true)
    }

    fn drain(&mut self, finishing: bool) -> Vec<u8> {
        let mut output = Vec::new();
        let mut cursor = 0;
        while cursor < self.pending.len() {
            let remaining = &self.pending[cursor..];
            if let Some((pattern, replacement)) = self
                .patterns
                .iter()
                .find(|(pattern, _)| remaining.starts_with(pattern))
            {
                output.extend_from_slice(replacement);
                cursor += pattern.len();
                self.replacements += 1;
                continue;
            }
            let could_be_prefix = self
                .patterns
                .iter()
                .any(|(pattern, _)| pattern.starts_with(remaining));
            if could_be_prefix && !finishing {
                break;
            }
            output.push(self.pending[cursor]);
            cursor += 1;
        }
        if cursor > 0 {
            self.pending.drain(..cursor);
        }
        output
    }
}

pub(crate) fn response_accepts_upgrade(buffer: &[u8]) -> bool {
    let line_end = buffer.windows(2).position(|bytes| bytes == b"\r\n");
    line_end.is_some_and(|end| {
        let mut parts = buffer[..end].split(|byte| *byte == b' ');
        parts.next() == Some(b"HTTP/1.1".as_slice()) && parts.next() == Some(b"101".as_slice())
    })
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn validate_field_value(value: &[u8]) -> io::Result<()> {
    if value
        .iter()
        .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(invalid_data(
            "secret substitution produced an invalid HTTP field value",
        ));
    }
    Ok(())
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn unexpected_eof(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, message)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use super::*;
    use crate::config::HostScope;
    use tokio::io::ReadBuf;

    fn rule(name: &str, value: &str) -> RequestHeaderRule {
        RequestHeaderRule {
            name: name.into(),
            value: value.into(),
            hosts: HostScope::default(),
        }
    }

    async fn transform(
        input: &[u8],
        rules: &[RequestHeaderRule],
        substitutions: &[(String, String)],
    ) -> io::Result<Vec<u8>> {
        let mut reader = input;
        let mut output = Vec::new();
        transform_requests(
            &mut reader,
            &mut output,
            "example.test",
            rules,
            substitutions,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Notify::new()),
        )
        .await?;
        Ok(output)
    }

    struct FragmentedReader {
        chunks: VecDeque<Vec<u8>>,
    }

    impl AsyncRead for FragmentedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let Some(mut chunk) = self.chunks.pop_front() else {
                return Poll::Ready(Ok(()));
            };
            let length = chunk.len().min(buffer.remaining());
            buffer.put_slice(&chunk[..length]);
            if length < chunk.len() {
                chunk.drain(..length);
                self.chunks.push_front(chunk);
            }
            Poll::Ready(Ok(()))
        }
    }

    async fn transform_fragmented(
        chunks: Vec<Vec<u8>>,
        rules: &[RequestHeaderRule],
    ) -> io::Result<Vec<u8>> {
        let mut reader = FragmentedReader {
            chunks: chunks
                .into_iter()
                .filter(|chunk| !chunk.is_empty())
                .collect(),
        };
        let mut output = Vec::new();
        transform_requests(
            &mut reader,
            &mut output,
            "example.test",
            rules,
            &[],
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Notify::new()),
        )
        .await?;
        Ok(output)
    }

    #[tokio::test]
    async fn inserts_replaces_and_collapses_headers_on_every_request() {
        let input = b"GET /one HTTP/1.1\r\nHost: example.test\r\nuser-agent: old\r\nUser-Agent: duplicate\r\n\r\nGET /two HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let output = transform(input, &[rule("User-Agent", "new")], &[])
            .await
            .unwrap();
        assert_eq!(output.iter().filter(|byte| **byte == b'G').count(), 2);
        assert_eq!(
            String::from_utf8_lossy(&output)
                .matches("User-Agent: new")
                .count(),
            2
        );
        assert!(!output.windows(3).any(|value| value == b"old"));
        assert!(!output.windows(9).any(|value| value == b"duplicate"));
    }

    #[tokio::test]
    async fn transforms_headers_split_at_every_input_boundary() {
        let input = b"GET /path HTTP/1.1\r\nHost: example.test\r\nUser-Agent: old\r\nX-Keep: exact bytes\r\n\r\n";
        let rules = [rule("User-Agent", "new")];
        let expected = transform_fragmented(vec![input.to_vec()], &rules)
            .await
            .unwrap();
        for split in 0..=input.len() {
            let actual = transform_fragmented(
                vec![input[..split].to_vec(), input[split..].to_vec()],
                &rules,
            )
            .await
            .unwrap();
            assert_eq!(actual, expected, "split {split}");
        }
    }

    #[tokio::test]
    async fn applies_multiple_rules_in_configuration_order() {
        let input = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let output = transform(
            input,
            &[rule("X-First", "one"), rule("X-Second", "two")],
            &[],
        )
        .await
        .unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.find("X-First: one").unwrap() < text.find("X-Second: two").unwrap());
    }

    #[tokio::test]
    async fn authorizes_every_request_host_against_the_tls_domain() {
        let normalized = b"GET / HTTP/1.1\r\nHost: EXAMPLE.TEST.:443\r\n\r\n";
        transform(normalized, &[], &[]).await.unwrap();

        for denied in [
            b"GET / HTTP/1.1\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: example.test\r\nHost: example.test\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: redirected.test\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: example.test:\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: example.test:444\r\n\r\n".as_slice(),
        ] {
            assert_eq!(
                transform(denied, &[], &[]).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[tokio::test]
    async fn cross_host_reuse_is_rejected_before_secret_or_header_injection() {
        let input = b"GET /one?token=TOKEN HTTP/1.1\r\nHost: example.test\r\n\r\nGET /two?token=TOKEN HTTP/1.1\r\nHost: redirected.test\r\n\r\n";
        let mut reader = input.as_slice();
        let mut output = Vec::new();
        let error = transform_requests(
            &mut reader,
            &mut output,
            "example.test",
            &[rule("Authorization", "scoped")],
            &[("TOKEN".into(), "secret".into())],
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Notify::new()),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.matches("secret").count(), 1);
        assert_eq!(output.matches("Authorization: scoped").count(), 1);
        assert!(!output.contains("redirected.test"));
    }

    #[tokio::test]
    async fn fixed_body_substitution_uses_valid_chunked_framing() {
        let input =
            b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 11\r\n\r\nbeforeTOKEN";
        let output = transform(input, &[], &[("TOKEN".into(), "replacement".into())])
            .await
            .unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("Transfer-Encoding: chunked\r\n"));
        assert!(!text.contains("Content-Length"));
        assert!(text.ends_with("11\r\nbeforereplacement\r\n0\r\n\r\n"));
    }

    #[tokio::test]
    async fn fixed_body_without_secrets_preserves_framing_and_bytes() {
        let input = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 11\r\nX-Keep:  exact\r\n\r\nhello world";
        let output = transform(input, &[rule("User-Agent", "agent")], &[])
            .await
            .unwrap();
        assert_eq!(
            output,
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 11\r\nX-Keep:  exact\r\nUser-Agent: agent\r\n\r\nhello world"
        );
    }

    #[tokio::test]
    async fn chunked_substitution_spans_original_chunks_and_transforms_trailers() {
        let input = b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n3\r\nabc\r\n3\r\nTOK\r\n2\r\nEN\r\n0\r\nX-End: TOKEN\r\n\r\n";
        let output = transform(input, &[], &[("TOKEN".into(), "secret".into())])
            .await
            .unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("3\r\nabc\r\n6\r\nsecret\r\n0\r\nX-End: secret\r\n\r\n"));
    }

    #[tokio::test]
    async fn rejects_ambiguous_framing() {
        let conflicting = b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx";
        assert_eq!(
            transform(conflicting, &[], &[]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let both = b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(
            transform(both, &[], &[]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn rejects_malformed_and_oversized_headers() {
        let malformed = b"GET / HTTP/1.1\r\nHost: example.test\r\nBroken\r\n\r\n";
        assert_eq!(
            transform(malformed, &[], &[]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut oversized = b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Large: ".to_vec();
        oversized.extend(vec![b'x'; MAX_HEADER_BYTES]);
        oversized.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            transform(&oversized, &[], &[]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn rejects_overlong_unterminated_headers_without_waiting_for_a_newline() {
        let (mut guest, mut proxy_reader) = tokio::io::duplex(1024);
        let relay = tokio::spawn(async move {
            let mut output = Vec::new();
            transform_requests(
                &mut proxy_reader,
                &mut output,
                "example.test",
                &[],
                &[],
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
                Arc::new(Notify::new()),
            )
            .await
        });

        let overlong = vec![b'x'; MAX_HEADER_BYTES + 1];
        let _ = guest.write_all(&overlong).await;
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("header limit should be enforced before EOF or a newline")
            .expect("request relay should not panic")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "HTTP request headers exceed limit");
    }

    #[tokio::test]
    async fn accepted_upgrade_wakes_header_read_and_relays_opaque_bytes() {
        let (mut guest, mut proxy_reader) = tokio::io::duplex(1024);
        let (mut proxy_writer, mut upstream) = tokio::io::duplex(1024);
        let opaque = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(Notify::new());
        let relay_opaque = opaque.clone();
        let relay_pending = pending.clone();
        let relay_notify = notify.clone();
        let relay = tokio::spawn(async move {
            transform_requests(
                &mut proxy_reader,
                &mut proxy_writer,
                "example.test",
                &[],
                &[],
                relay_opaque,
                relay_pending,
                relay_notify,
            )
            .await
        });

        let request = b"GET /chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        guest.write_all(request).await.unwrap();
        let mut forwarded_request = vec![0; request.len()];
        upstream.read_exact(&mut forwarded_request).await.unwrap();
        assert_eq!(forwarded_request, request);
        assert!(pending.load(Ordering::Acquire));

        opaque.store(true, Ordering::Release);
        pending.store(false, Ordering::Release);
        notify.notify_one();

        let frame = b"\x81\x05hello";
        guest.write_all(frame).await.unwrap();
        guest.shutdown().await.unwrap();
        let mut forwarded_frame = vec![0; frame.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read_exact(&mut forwarded_frame),
        )
        .await
        .expect("accepted upgrade should wake the pending header read")
        .unwrap();
        assert_eq!(forwarded_frame, frame);

        let stats = relay.await.unwrap().unwrap();
        assert_eq!(stats.requests, 1);
        assert_eq!(stats.bytes_read, (request.len() + frame.len()) as u64);
    }

    #[tokio::test]
    async fn substitutions_do_not_modify_method_version_or_header_names() {
        let input = b"TOKEN /TOKEN HTTP/1.1\r\nTOKEN: TOKEN\r\nHost: example.test\r\n\r\n";
        let output = transform(input, &[], &[("TOKEN".into(), "secret".into())])
            .await
            .unwrap();
        assert_eq!(
            output,
            b"TOKEN /secret HTTP/1.1\r\nTOKEN: secret\r\nHost: example.test\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn rejects_secret_values_that_corrupt_http_syntax() {
        let header = b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Token: TOKEN\r\n\r\n";
        let error = transform(
            header,
            &[],
            &[("TOKEN".into(), "bad\r\nInjected: yes".into())],
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let target = b"GET /TOKEN HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let error = transform(target, &[], &[("TOKEN".into(), "bad target".into())])
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn streaming_replacer_matches_at_every_boundary() {
        let patterns = vec![(b"TOKEN".to_vec(), b"secret".to_vec())];
        for split in 0..=5 {
            let mut replacer = StreamingReplacer::new(&patterns);
            let mut output = replacer.feed(&b"TOKEN"[..split]);
            output.extend(replacer.feed(&b"TOKEN"[split..]));
            output.extend(replacer.finish());
            assert_eq!(output, b"secret", "split {split}");
            assert_eq!(replacer.replacements, 1);
        }
    }

    #[test]
    fn streaming_replacer_handles_multiple_and_repeated_patterns_deterministically() {
        let patterns = vec![
            (b"ALPHA".to_vec(), b"one".to_vec()),
            (b"BETA".to_vec(), b"two-two".to_vec()),
        ];
        let mut replacer = StreamingReplacer::new(&patterns);
        let mut output = replacer.feed(b"ALPHAB");
        output.extend(replacer.feed(b"ETA/ALPHA"));
        output.extend(replacer.finish());
        assert_eq!(output, b"onetwo-two/one");
        assert_eq!(replacer.replacements, 3);
    }
}
