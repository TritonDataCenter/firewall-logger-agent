// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2019 Joyent, Inc.

use std::io;
use std::io::prelude::*;
use std::io::{Seek, SeekFrom};

/// Represents the total length of the Reader and position of the character of interest.
pub struct ReaderSeekInfo {
    /// Total Reader length
    pub length: u64,
    /// Location of specified character if any.
    pub index: Option<u64>,
}

/// Iterates through the given bytes backwards looking for the provided char
fn rev_locate_char(bytes: &[u8], c: u8) -> Option<usize> {
    bytes.iter().rposition(|p| *p == c)
}

/// Seeks to the end of a given `Reader` and processes a chunk of bytes looking for a specific
/// char. This process is repeated until the given char is found, otherwise returns None if it's
/// not found. This function panics if the chunk size is 0.
pub fn rseek_and_scan<R: Read + Seek>(r: &mut R, chunk: u64, c: u8) -> io::Result<ReaderSeekInfo> {
    assert!(chunk > 0, "chunk size must be greater than 0");
    let mut buf = String::with_capacity(chunk as usize);
    // Track the overall seek offset
    let mut ptr = r.seek(SeekFrom::End(0))?;
    let file_len = ptr;
    // Used to calculate the next seek offset when reading a chunk
    let mut pos = ptr;

    loop {
        // Set the buffer len back to 0 leaving capacity alone.
        buf.truncate(0);
        pos = pos.saturating_sub(chunk);
        // Seek to the next chunk of bytes.
        r.seek(SeekFrom::Start(pos))?;
        // Avoid overlapping chunks when there is less than a chunk's worth of data left
        let max = if ptr < chunk { ptr } else { chunk };
        // Read the max number of bytes into the buffer.
        r.take(max).read_to_string(&mut buf)?;

        // Attempt to locate the char.
        if let Some(found) = rev_locate_char(buf.as_bytes(), c) {
            return Ok(ReaderSeekInfo {
                length: file_len,
                index: Some(found as u64 + pos),
            });
        }

        // If our pos is 0 there's nothing left to read. Using `saturating_sub` guarantees we
        // will never dip below 0.
        if pos == 0 {
            break;
        };

        // Move our offset pointer to reflect how much was read and where we are in the Reader
        ptr -= max;
    }
    Ok(ReaderSeekInfo {
        length: file_len,
        index: None,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_beginning() {
        let mut data = Cursor::new(vec![b'\n', 2, 3, 4, 5]);
        let pos = rseek_and_scan(&mut data, 100, b'\n').unwrap().index;
        assert_eq!(Some(0), pos, "newline is in the first position");
        assert_eq!(
            b'\n',
            data.get_ref()[pos.unwrap() as usize],
            r#"byte should be \n"#
        );
    }

    #[test]
    fn test_middle() {
        let mut data = Cursor::new(vec![1, 2, 3, b'\n', 5, 6, 7]);
        let pos = rseek_and_scan(&mut data, 100, b'\n').unwrap().index;
        assert_eq!(Some(3), pos, "newline is in the middle position");
        assert_eq!(
            b'\n',
            data.get_ref()[pos.unwrap() as usize],
            r#"byte should be \n"#
        );
    }

    #[test]
    fn test_end() {
        let mut data = Cursor::new(vec![1, 2, 3, 4, 5, b'\n']);
        let pos = rseek_and_scan(&mut data, 100, b'\n').unwrap().index;
        assert_eq!(Some(5), pos, "newline is in the last position");
        assert_eq!(
            b'\n',
            data.get_ref()[pos.unwrap() as usize],
            r#"byte should be \n"#
        );
    }

    #[test]
    fn test_reading_single_byte() {
        let mut data = Cursor::new(vec![b'\n', 2, 3, 4, 5]);
        let pos = rseek_and_scan(&mut data, 1, b'\n').unwrap().index;
        assert_eq!(Some(0), pos, "newline is in the first position");
        assert_eq!(
            b'\n',
            data.get_ref()[pos.unwrap() as usize],
            r#"byte should be \n"#
        );
    }

    #[test]
    fn test_overlapping_chunks() {
        let mut data = Cursor::new(vec![b'\n', 2, 3, 4, 5]);
        let pos = rseek_and_scan(&mut data, 2, b'\n').unwrap().index;
        assert_eq!(Some(0), pos, "newline is in the first position");
        assert_eq!(
            b'\n',
            data.get_ref()[pos.unwrap() as usize],
            r#"byte should be \n"#
        );
    }

    #[test]
    fn test_multiple_newlines() {
        let mut data = Cursor::new(vec![1, 2, b'\n', 4, b'\n', b'\n']);
        let pos = rseek_and_scan(&mut data, 100, b'\n').unwrap().index;
        assert_eq!(Some(5), pos, "newline is in the last position");
        assert_eq!(
            b'\n',
            data.get_ref()[pos.unwrap() as usize],
            r#"byte should be \n"#
        );

        data.get_mut().remove(pos.unwrap() as usize);
        let pos = rseek_and_scan(&mut data, 50, b'\n').unwrap().index;
        assert_eq!(Some(4), pos, "newline is in the last position");
        assert_eq!(
            b'\n',
            data.get_ref()[pos.unwrap() as usize],
            r#"byte should be \n"#
        );
    }
}
