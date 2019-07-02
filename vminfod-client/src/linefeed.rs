// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2019 Joyent, Inc.

use std::mem::replace;
use std::string::FromUtf8Error;

use futures::stream::Fuse;
use futures::{try_ready, Async, Poll, Stream};

/// The following code is a modified version of:
/// https://play.rust-lang.org/?gist=971e438cabd6f91efb76b7e45b15edf3&version=stable
///
/// The original author of that snippet is:
/// https://github.com/hyperium/hyper/issues/1335#issuecomment-331682968

#[derive(Debug)]
pub struct Lines<S: Stream> {
    buffered: Option<Vec<u8>>,
    stream: Fuse<S>,
}

impl<S: Stream> Lines<S> {
    pub fn new(stream: S) -> Lines<S> {
        Lines {
            buffered: None,
            stream: stream.fuse(),
        }
    }

    fn process(&mut self, flush: bool) -> Option<Result<String, FromUtf8Error>> {
        let buffered = replace(&mut self.buffered, None);
        if let Some(ref buffer) = buffered {
            let mut split = buffer.splitn(2, |c| *c == b'\n');
            if let Some(first) = split.next() {
                if let Some(second) = split.next() {
                    replace(&mut self.buffered, Some(second.to_vec()));
                    return Some(String::from_utf8(first.to_vec()));
                } else if flush {
                    return Some(String::from_utf8(first.to_vec()));
                }
            }
        }
        replace(&mut self.buffered, buffered);
        None
    }
}

impl<S> Stream for Lines<S>
where
    S: Stream,
    S::Item: AsRef<[u8]>,
    S::Error: From<FromUtf8Error>,
{
    type Item = String;
    type Error = S::Error;

    fn poll(&mut self) -> Poll<Option<String>, S::Error> {
        // It's important that we loop here so that we only return Async::NotReady when our inner
        // Stream does.  Otherwise the current task will never be polled again and things will
        // stall
        loop {
            match try_ready!(self.stream.poll()) {
                // We got a chunk of data from the inner stream
                Some(chunk) => {
                    if let Some(ref mut buffer) = self.buffered {
                        buffer.extend(chunk.as_ref());
                    } else {
                        self.buffered = Some(chunk.as_ref().to_vec());
                    }
                    match self.process(false) {
                        Some(Ok(line)) => return Ok(Async::Ready(Some(line))),
                        Some(Err(err)) => return Err(err.into()),
                        None => (),
                    }
                }
                // The inner stream has finished
                None => match self.process(true) {
                    Some(Ok(line)) => return Ok(Async::Ready(Some(line))),
                    Some(Err(err)) => return Err(err.into()),
                    None => return Ok(Async::Ready(None)),
                },
            }
        }
    }
}

#[cfg(test)]
mod linefeed_tests {
    use super::*;
    use futures::stream::iter_ok;
    use futures::Async;

    #[test]
    // test that `Lines` is able to buffer and split by new lines
    fn test_lines() {
        let chunks = vec![
            "hello",
            " world\n",
            "good\nbye\n",
            "world\n",
            "escaped\\n\n",
        ];
        let stream = iter_ok::<_, FromUtf8Error>(chunks);
        let mut lines = Lines::new(stream);

        // iter_ok gives us an iterator that is always Ready
        assert_eq!(
            lines.poll().unwrap(),
            Async::Ready(Some("hello world".to_string()))
        );
        assert_eq!(
            lines.poll().unwrap(),
            Async::Ready(Some("good".to_string()))
        );
        assert_eq!(lines.poll().unwrap(), Async::Ready(Some("bye".to_string())));
        assert_eq!(
            lines.poll().unwrap(),
            Async::Ready(Some("world".to_string()))
        );
        assert_eq!(
            lines.poll().unwrap(),
            Async::Ready(Some("escaped\\n".to_string()))
        );
        assert_eq!(lines.poll().unwrap(), Async::Ready(Some("".to_string())));
        assert_eq!(lines.poll().unwrap(), Async::Ready(None));
    }

}
