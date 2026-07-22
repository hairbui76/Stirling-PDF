use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

const TAIL_WINDOW_BYTES: usize = 8 * 1024;
const XREF_WINDOW_BYTES: usize = 64 * 1024;
const DEFAULT_TRAILER_SIZE: usize = 10;
const DEFAULT_ROOT_OBJECT: usize = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookmarkEntry {
    pub title: String,
    pub page_index: i32,
}

#[derive(Debug)]
struct OutlineMeta {
    previous_xref: u64,
    trailer_size: usize,
    root_object: usize,
    root_dictionary: Vec<u8>,
}

pub fn append_bookmarks(
    path: &Path,
    entries: &[BookmarkEntry],
    page_count: i32,
) -> std::io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let metadata = read_outline_metadata(path)?;
    let append_offset = std::fs::metadata(path)?.len();
    let appendix = build_outline_appendix(entries, page_count, &metadata, append_offset)?;
    OpenOptions::new()
        .append(true)
        .open(path)?
        .write_all(&appendix)
}

fn read_outline_metadata(path: &Path) -> std::io::Result<OutlineMeta> {
    let file_size = std::fs::metadata(path)?.len();
    let tail_length = usize::try_from(file_size.min(TAIL_WINDOW_BYTES as u64))
        .map_err(|_| std::io::Error::other("PDF tail length does not fit in memory"))?;
    let tail = read_window(
        path,
        file_size.saturating_sub(tail_length as u64),
        tail_length,
    )?;
    let previous_xref = find_number_after_last(&tail, b"startxref").unwrap_or_default();
    let trailer_size = find_number_after_last(&tail, b"/Size")
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(DEFAULT_TRAILER_SIZE);
    let root_object = find_number_after_last(&tail, b"/Root")
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(DEFAULT_ROOT_OBJECT);
    let root_offset = read_xref_entry_offset(path, previous_xref, root_object)?
        .or(find_object_offset_by_scan(path, root_object)?);
    let root_dictionary = match root_offset {
        Some(offset) => {
            let available = file_size
                .saturating_sub(offset)
                .min(TAIL_WINDOW_BYTES as u64);
            let length = usize::try_from(available)
                .map_err(|_| std::io::Error::other("PDF catalog window is too large"))?;
            extract_dictionary(&read_window(path, offset, length)?)
                .unwrap_or_else(|| b"<< /Type /Catalog >>".to_vec())
        }
        None => b"<< /Type /Catalog >>".to_vec(),
    };
    Ok(OutlineMeta {
        previous_xref,
        trailer_size,
        root_object,
        root_dictionary,
    })
}

fn read_window(path: &Path, offset: u64, length: usize) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_xref_entry_offset(
    path: &Path,
    xref_start: u64,
    wanted_object: usize,
) -> std::io::Result<Option<u64>> {
    let file_size = std::fs::metadata(path)?.len();
    if xref_start == 0 || xref_start >= file_size {
        return Ok(None);
    }
    let first_length = usize::try_from(
        file_size
            .saturating_sub(xref_start)
            .min(XREF_WINDOW_BYTES as u64),
    )
    .map_err(|_| std::io::Error::other("PDF xref window is too large"))?;
    let mut chunk = read_window(path, xref_start, first_length)?;
    if !chunk.starts_with(b"xref") {
        return Ok(None);
    }
    let mut position = 4;
    while chunk
        .get(position)
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        position += 1;
    }

    while position < chunk.len() {
        if chunk[position..].starts_with(b"trailer") {
            break;
        }
        let Some(line_end) = chunk[position..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|relative| position + relative)
        else {
            break;
        };
        let Some((start_object, count)) = parse_two_numbers(&chunk[position..line_end]) else {
            break;
        };
        position = line_end + 1;
        let Some(needed) = count.checked_mul(20) else {
            return Ok(None);
        };
        if position.saturating_add(needed) > chunk.len() {
            let subsection_start = xref_start.saturating_add(position as u64);
            let extended_length = needed.saturating_add(64);
            let available =
                usize::try_from(file_size.saturating_sub(subsection_start)).unwrap_or(usize::MAX);
            chunk = read_window(path, subsection_start, extended_length.min(available))?;
            position = 0;
        }
        if wanted_object >= start_object && wanted_object < start_object.saturating_add(count) {
            let Some(entry_start) = wanted_object
                .checked_sub(start_object)
                .and_then(|index| index.checked_mul(20))
                .and_then(|offset| position.checked_add(offset))
            else {
                return Ok(None);
            };
            let Some(entry) = chunk.get(entry_start..entry_start.saturating_add(20)) else {
                return Ok(None);
            };
            if entry.get(17) == Some(&b'f') {
                return Ok(None);
            }
            return Ok(parse_ascii_u64(&entry[..10]));
        }
        position = position.saturating_add(needed);
    }
    Ok(None)
}

fn find_object_offset_by_scan(path: &Path, object_number: usize) -> std::io::Result<Option<u64>> {
    let pattern = format!("{object_number} 0 obj").into_bytes();
    let mut file = File::open(path)?;
    let mut buffer = vec![0; XREF_WINDOW_BYTES];
    let mut carry = Vec::new();
    let mut bytes_read_total = 0u64;
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            return Ok(None);
        }
        let mut window = Vec::with_capacity(carry.len().saturating_add(bytes_read));
        window.extend_from_slice(&carry);
        window.extend_from_slice(&buffer[..bytes_read]);
        let window_start = bytes_read_total.saturating_sub(carry.len() as u64);
        for position in window
            .windows(pattern.len())
            .enumerate()
            .filter_map(|(position, candidate)| (candidate == pattern).then_some(position))
        {
            let valid_start = position == 0
                || window
                    .get(position - 1)
                    .is_some_and(u8::is_ascii_whitespace);
            let valid_end = window
                .get(position + pattern.len())
                .is_some_and(u8::is_ascii_whitespace);
            if valid_start && valid_end {
                return Ok(Some(window_start.saturating_add(position as u64)));
            }
        }
        bytes_read_total = bytes_read_total.saturating_add(bytes_read as u64);
        let carry_length = pattern.len().min(window.len());
        carry = window[window.len() - carry_length..].to_vec();
    }
}

fn build_outline_appendix(
    entries: &[BookmarkEntry],
    page_count: i32,
    metadata: &OutlineMeta,
    append_offset: u64,
) -> std::io::Result<Vec<u8>> {
    let outlines_object = metadata.trailer_size;
    let first_entry_object = outlines_object.saturating_add(1);
    let mut appendix = Vec::with_capacity(512usize.saturating_add(entries.len() * 128));
    let mut xref_entries = Vec::with_capacity(entries.len().saturating_add(2));

    push_object_offset(
        &mut xref_entries,
        metadata.root_object,
        append_offset,
        &appendix,
    )?;
    push_ascii(&mut appendix, &format!("{} 0 obj\n", metadata.root_object));
    appendix.extend_from_slice(&inject_outlines_reference(
        &metadata.root_dictionary,
        outlines_object,
    ));
    appendix.extend_from_slice(b"\nendobj\n");

    push_object_offset(&mut xref_entries, outlines_object, append_offset, &appendix)?;
    push_ascii(
        &mut appendix,
        &format!(
            "{outlines_object} 0 obj\n<< /Type /Outlines /First {first_entry_object} 0 R /Last {} 0 R /Count {} >>\nendobj\n",
            first_entry_object.saturating_add(entries.len().saturating_sub(1)),
            entries.len()
        ),
    );

    for (index, entry) in entries.iter().enumerate() {
        let object_number = first_entry_object.saturating_add(index);
        push_object_offset(&mut xref_entries, object_number, append_offset, &appendix)?;
        let maximum_page = page_count.saturating_sub(1).max(0);
        let target_page = entry.page_index.clamp(0, maximum_page);
        push_ascii(
            &mut appendix,
            &format!(
                "{object_number} 0 obj\n<< /Title {} /Parent {outlines_object} 0 R /Dest [{target_page} /Fit]",
                pdf_string(&entry.title)
            ),
        );
        if index > 0 {
            push_ascii(
                &mut appendix,
                &format!(" /Prev {} 0 R", object_number.saturating_sub(1)),
            );
        }
        if index + 1 < entries.len() {
            push_ascii(
                &mut appendix,
                &format!(" /Next {} 0 R", object_number.saturating_add(1)),
            );
        }
        appendix.extend_from_slice(b" >>\nendobj\n");
    }

    let appendix_length = u64::try_from(appendix.len())
        .map_err(|_| std::io::Error::other("bookmark appendix is too large"))?;
    let xref_offset = append_offset
        .checked_add(appendix_length)
        .ok_or_else(|| std::io::Error::other("bookmark xref offset overflowed"))?;
    xref_entries.sort_unstable_by_key(|entry| entry.0);
    appendix.extend_from_slice(b"xref\n");
    let mut index = 0;
    while index < xref_entries.len() {
        let start_object = xref_entries[index].0;
        let mut count = 1;
        while index + count < xref_entries.len()
            && xref_entries[index + count].0 == start_object.saturating_add(count)
        {
            count += 1;
        }
        push_ascii(&mut appendix, &format!("{start_object} {count}\n"));
        for entry in &xref_entries[index..index + count] {
            push_ascii(&mut appendix, &format!("{:010} 00000 n \n", entry.1));
        }
        index += count;
    }

    let new_size = outlines_object.max(first_entry_object.saturating_add(entries.len()));
    push_ascii(
        &mut appendix,
        &format!(
            "trailer\n<< /Size {new_size} /Prev {} /Root {} 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n",
            metadata.previous_xref, metadata.root_object
        ),
    );
    Ok(appendix)
}

fn push_object_offset(
    entries: &mut Vec<(usize, u64)>,
    object_number: usize,
    append_offset: u64,
    appendix: &[u8],
) -> std::io::Result<()> {
    let appendix_length = u64::try_from(appendix.len())
        .map_err(|_| std::io::Error::other("bookmark appendix is too large"))?;
    let offset = append_offset
        .checked_add(appendix_length)
        .ok_or_else(|| std::io::Error::other("bookmark object offset overflowed"))?;
    entries.push((object_number, offset));
    Ok(())
}

fn inject_outlines_reference(dictionary: &[u8], outlines_object: usize) -> Vec<u8> {
    let cleaned = remove_outlines_references(dictionary);
    let Some(closing) = rfind_subslice(&cleaned, b">>") else {
        return dictionary.to_vec();
    };
    let mut output = Vec::with_capacity(cleaned.len().saturating_add(32));
    output.extend_from_slice(&cleaned[..closing]);
    push_ascii(&mut output, &format!(" /Outlines {outlines_object} 0 R "));
    output.extend_from_slice(&cleaned[closing..]);
    output
}

fn remove_outlines_references(dictionary: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(dictionary.len());
    let mut cursor = 0;
    while let Some(relative) = find_subslice(&dictionary[cursor..], b"/Outlines") {
        let start = cursor + relative;
        output.extend_from_slice(&dictionary[cursor..start]);
        if let Some(end) = outlines_reference_end(dictionary, start + b"/Outlines".len()) {
            cursor = end;
        } else {
            output.extend_from_slice(b"/Outlines");
            cursor = start + b"/Outlines".len();
        }
    }
    output.extend_from_slice(&dictionary[cursor..]);
    output
}

fn outlines_reference_end(bytes: &[u8], mut position: usize) -> Option<usize> {
    position = consume_required_whitespace(bytes, position)?;
    position = consume_required_digits(bytes, position)?;
    position = consume_required_whitespace(bytes, position)?;
    position = consume_required_digits(bytes, position)?;
    position = consume_required_whitespace(bytes, position)?;
    (bytes.get(position) == Some(&b'R')).then_some(position + 1)
}

fn consume_required_whitespace(bytes: &[u8], mut position: usize) -> Option<usize> {
    let start = position;
    while bytes.get(position).is_some_and(u8::is_ascii_whitespace) {
        position += 1;
    }
    (position > start).then_some(position)
}

fn consume_required_digits(bytes: &[u8], mut position: usize) -> Option<usize> {
    let start = position;
    while bytes.get(position).is_some_and(u8::is_ascii_digit) {
        position += 1;
    }
    (position > start).then_some(position)
}

fn extract_dictionary(window: &[u8]) -> Option<Vec<u8>> {
    let start = find_subslice(window, b"<<")?;
    let mut depth = 0usize;
    let mut position = start;
    while position + 1 < window.len() {
        match &window[position..position + 2] {
            b"<<" => {
                depth = depth.saturating_add(1);
                position += 2;
            }
            b">>" => {
                depth = depth.saturating_sub(1);
                position += 2;
                if depth == 0 {
                    return Some(window[start..position].to_vec());
                }
            }
            _ => position += 1,
        }
    }
    None
}

fn find_number_after_last(bytes: &[u8], marker: &[u8]) -> Option<u64> {
    let position = rfind_subslice(bytes, marker)?.saturating_add(marker.len());
    parse_ascii_u64(&bytes[position..])
}

fn parse_two_numbers(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut numbers = bytes
        .split(u8::is_ascii_whitespace)
        .filter(|part| !part.is_empty())
        .filter_map(|part| parse_ascii_u64(part).and_then(|value| usize::try_from(value).ok()));
    Some((numbers.next()?, numbers.next()?))
}

fn parse_ascii_u64(bytes: &[u8]) -> Option<u64> {
    let bytes = trim_ascii_start(bytes);
    let digit_count = bytes
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digit_count == 0 {
        return None;
    }
    std::str::from_utf8(&bytes[..digit_count])
        .ok()?
        .parse()
        .ok()
}

fn trim_ascii_start(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    bytes
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn rfind_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

fn pdf_string(value: &str) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(6usize.saturating_add(value.len() * 4));
    output.push_str("<FEFF");
    for code_unit in value.encode_utf16() {
        for shift in [12, 8, 4, 0] {
            let nibble = usize::from((code_unit >> shift) & 0x0F);
            output.push(char::from(HEX_DIGITS[nibble]));
        }
    }
    output.push('>');
    output
}

fn push_ascii(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use lopdf::{Document, Object, Stream, dictionary};
    use tempfile::NamedTempFile;

    use super::{BookmarkEntry, append_bookmarks, pdf_string, read_outline_metadata};

    #[test]
    fn encodes_titles_as_utf16be_pdf_strings() {
        assert_eq!(pdf_string("A😀"), "<FEFF0041D83DDE00>");
    }

    #[test]
    fn appends_bookmarks_and_preserves_catalog_entries() -> Result<(), Box<dyn std::error::Error>> {
        let mut document = Document::with_version("1.7");
        let pages_id = document.new_object_id();
        let content_id = document.add_object(Stream::new(dictionary! {}, Vec::new()));
        let page_object_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
            "Contents" => content_id,
        });
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_object_id)],
                "Count" => 1,
            }),
        );
        let acroform_id = document.add_object(dictionary! { "Fields" => Vec::<Object>::new() });
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
            "AcroForm" => acroform_id,
        });
        document.trailer.set("Root", catalog_id);
        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;
        let mut file = NamedTempFile::new()?;
        file.write_all(&bytes)?;

        let metadata = read_outline_metadata(file.path())?;
        assert!(
            metadata
                .root_dictionary
                .windows(b"/AcroForm".len())
                .any(|window| window == b"/AcroForm"),
            "catalog dictionary was not recovered (xref={}, root={}): {}",
            metadata.previous_xref,
            metadata.root_object,
            String::from_utf8_lossy(&metadata.root_dictionary)
        );

        append_bookmarks(
            file.path(),
            &[BookmarkEntry {
                title: "Chapter 😀".to_owned(),
                page_index: 0,
            }],
            1,
        )?;

        let result = Document::load(file.path())?;
        assert!(result.catalog()?.get(b"AcroForm").is_ok());
        let output = std::fs::read(file.path())?;
        assert!(
            output
                .windows(b"/Title <FEFF00430068006100700074006500720020D83DDE00>".len())
                .any(|window| {
                    window == b"/Title <FEFF00430068006100700074006500720020D83DDE00>"
                })
        );
        assert!(
            output
                .windows(b"/Dest [0 /Fit]".len())
                .any(|window| window == b"/Dest [0 /Fit]")
        );
        Ok(())
    }
}
