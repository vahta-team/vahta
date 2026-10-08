//! The streaming scrubber: a command's output with the secret values taken out.
//!
//! Every value injected into a run is replaced, wherever it appears in what the
//! command writes, by `***REDACTED(NAME)***`. The scrubber works on a stream:
//! a value can be split across two reads, so it keeps back the tail of what it
//! has seen that could still turn out to be the start of a value, and decides
//! about it when more arrives, or at the end of the stream, when
//! [`Scrubber::finish`] flushes everything. The tail is the longest suffix that
//! is a proper prefix of some value, and so at most `max_len - 1` bytes: output
//! that cannot begin a value (a line like `ready`) is written at once, which
//! matters to a command whose output someone is waiting on. Each stream
//! (stdout, stderr) has its own scrubber.
//!
//! Matches are found at every position, longest value first, and matches that
//! overlap or touch are merged into one span, so a value that contains another
//! is redacted as the larger one, and two values that overlap leave no
//! fragment of either. Each span is written as one marker per value that is not
//! already covered by an earlier one in it. The result is the same whatever the
//! chunking of the input.
//!
//! **Encodings.** [`Scrubber::with_encodings`] also takes out a value written
//! as base64 (either alphabet, padded or not, wherever it sits in a longer
//! encoded text), hex, URL-encoded or reversed, under the label
//! `NAME (base64)` and so on (see `encoded.rs`). A value shorter than
//! `MIN_EXACT` is taken out raw only, as it was.
//!
//! **Not covered**, by design and in the documentation: a value split by the
//! program's own formatting (line-wrapped base64, say), or transformed in any
//! other way (compressed, encrypted, rot13), is not recognised, and the few
//! bytes held back because they look like the start of a value appear late,
//! at the next read or at the end.

use zeroize::Zeroizing;

/// One value to take out, and the name to put in its place.
struct Target {
    name: String,
    value: Zeroizing<Vec<u8>>,
}

pub struct Scrubber {
    /// Longest value first, so the longest match at a position comes first.
    targets: Vec<Target>,
    max_len: usize,
    /// What has been read and not yet written: the held-back tail, and
    /// whatever has arrived since.
    pending: Zeroizing<Vec<u8>>,
}

/// A match: where it is and which target.
#[derive(Clone, Copy)]
struct Hit {
    start: usize,
    end: usize,
    target: usize,
}

impl Scrubber {
    /// A scrubber for `values`, as `(name, bytes)`. An empty value is ignored:
    /// it would match everywhere and is not a secret.
    pub fn new(values: Vec<(String, Vec<u8>)>) -> Scrubber {
        let mut targets: Vec<Target> = values
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(name, value)| Target {
                name,
                value: Zeroizing::new(value),
            })
            .collect();
        targets.sort_by_key(|t| std::cmp::Reverse(t.value.len()));
        let max_len = targets.first().map_or(0, |t| t.value.len());
        Scrubber {
            targets,
            max_len,
            pending: Zeroizing::new(Vec::new()),
        }
    }

    /// As [`Scrubber::new`], and each value of at least `MIN_EXACT` bytes in
    /// its encoded forms too, labelled `NAME (form)`.
    pub fn with_encodings(values: Vec<(String, Vec<u8>)>) -> Scrubber {
        let forms = crate::encoded::EncodedSet::build(
            values.iter().map(|(n, v)| (n.as_str(), v.as_slice())),
        );
        let mut all = values;
        all.extend(forms.encoded_targets());
        Scrubber::new(all)
    }

    /// Feed more output; get back the part that is now certain.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.targets.is_empty() {
            return chunk.to_vec();
        }
        self.pending.extend_from_slice(chunk);
        self.process(false)
    }

    /// The stream has ended: everything that was held back is decided and
    /// returned.
    pub fn finish(&mut self) -> Vec<u8> {
        if self.targets.is_empty() {
            return Vec::new();
        }
        self.process(true)
    }

    /// Where the values are in a whole `buf`, as the streaming path would
    /// redact them: matches that overlap or touch merged into one span, named
    /// after the first (longest) value in it. For a text that is complete
    /// already, a tool's output the hook sends.
    pub fn spans(&self, buf: &[u8]) -> Vec<(usize, usize, String)> {
        let mut out: Vec<(usize, usize, String)> = Vec::new();
        for h in self.hits(buf) {
            match out.last_mut() {
                Some((_, end, _)) if h.start <= *end => *end = (*end).max(h.end),
                _ => out.push((h.start, h.end, self.targets[h.target].name.clone())),
            }
        }
        out
    }

    fn hits(&self, buf: &[u8]) -> Vec<Hit> {
        let mut hits = Vec::new();
        for start in 0..buf.len() {
            for (target, t) in self.targets.iter().enumerate() {
                let v = &t.value;
                if buf[start] == v[0] && buf[start..].starts_with(v) {
                    hits.push(Hit {
                        start,
                        end: start + v.len(),
                        target,
                    });
                }
            }
        }
        hits
    }

    /// How many bytes at the end of `buf` could be the start of a value that
    /// the next bytes complete: the longest suffix that is a proper prefix of
    /// some value.
    fn partial_suffix(&self, buf: &[u8]) -> usize {
        let n = buf.len();
        (1..=n.min(self.max_len.saturating_sub(1)))
            .rev()
            .find(|&k| {
                let suffix = &buf[n - k..];
                self.targets
                    .iter()
                    .any(|t| t.value.len() > k && t.value.starts_with(suffix))
            })
            .unwrap_or(0)
    }

    fn marker(&self, target: usize, out: &mut Vec<u8>) {
        out.extend_from_slice(b"***REDACTED(");
        out.extend_from_slice(self.targets[target].name.as_bytes());
        out.extend_from_slice(b")***");
    }

    fn process(&mut self, eof: bool) -> Vec<u8> {
        let buf: Zeroizing<Vec<u8>> = std::mem::take(&mut self.pending);
        let n = buf.len();
        // What precedes the held-back tail is decided now: no match that starts
        // there can still be waiting for bytes that have not arrived.
        let mut emit_to = if eof {
            n
        } else {
            n - self.partial_suffix(&buf)
        };
        let hits = self.hits(&buf);

        // Merge matches that overlap or touch into spans, in order.
        let mut spans: Vec<(usize, usize, Vec<Hit>)> = Vec::new();
        for h in hits {
            match spans.last_mut() {
                Some((_, end, members)) if h.start <= *end => {
                    *end = (*end).max(h.end);
                    members.push(h);
                }
                _ => spans.push((h.start, h.end, vec![h])),
            }
        }

        let mut out = Vec::with_capacity(n);
        let mut pos = 0;
        for (start, end, members) in &spans {
            if *start >= emit_to {
                break;
            }
            if *end > emit_to && !eof {
                // The span reaches into the held-back tail and a later match
                // could still extend it: hold it back whole.
                emit_to = *start;
                break;
            }
            out.extend_from_slice(&buf[pos..*start]);
            // One marker for each match not already covered by an earlier one,
            // longest first at each start (the hits are in that order).
            let mut covered = *start;
            let mut last = None;
            for h in members {
                if h.end > covered {
                    // The same value found again, overlapping itself, is the
                    // same redaction, not a second one.
                    if !(last == Some(h.target) && h.start < covered) {
                        self.marker(h.target, &mut out);
                    }
                    last = Some(h.target);
                    covered = h.end;
                }
            }
            pos = *end;
        }
        if pos < emit_to {
            out.extend_from_slice(&buf[pos..emit_to]);
            pos = emit_to;
        }
        self.pending = Zeroizing::new(buf[pos.min(n)..].to_vec());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(v: &[(&str, &str)]) -> Vec<(String, Vec<u8>)> {
        v.iter()
            .map(|(n, x)| ((*n).to_string(), x.as_bytes().to_vec()))
            .collect()
    }

    /// The whole input in chunks of `size`.
    fn scrub(v: &[(&str, &str)], input: &[u8], size: usize) -> Vec<u8> {
        let mut s = Scrubber::new(values(v));
        let mut out = Vec::new();
        for chunk in input.chunks(size.max(1)) {
            out.extend(s.push(chunk));
        }
        out.extend(s.finish());
        out
    }

    fn all_chunkings(v: &[(&str, &str)], input: &[u8]) -> Vec<u8> {
        let whole = scrub(v, input, input.len().max(1));
        for size in 1..=input.len().max(1) {
            assert_eq!(
                String::from_utf8_lossy(&scrub(v, input, size)),
                String::from_utf8_lossy(&whole),
                "chunk size {size}"
            );
        }
        whole
    }

    fn text(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    #[test]
    fn a_value_is_replaced_wherever_the_input_is_cut() {
        let input = b"before fake-one after fake-one";
        let out = all_chunkings(&[("A", "fake-one")], input);
        assert_eq!(
            text(&out),
            "before ***REDACTED(A)*** after ***REDACTED(A)***"
        );
        // Split exactly in the middle of the value, at every offset into it.
        let mut s = Scrubber::new(values(&[("A", "fake-one")]));
        let mut out = s.push(b"xx fake");
        out.extend(s.push(b"-one yy"));
        out.extend(s.finish());
        assert_eq!(text(&out), "xx ***REDACTED(A)*** yy");
    }

    #[test]
    fn output_that_cannot_start_a_value_is_not_held_back() {
        let mut s = Scrubber::new(values(&[("A", "fake-one")]));
        // A command's line, written at once.
        assert_eq!(s.push(b"ready\n"), b"ready\n");
        // Only what looks like the start of the value waits for the rest.
        assert_eq!(s.push(b"ok f"), b"ok ");
        assert_eq!(s.push(b"ake-"), b"");
        assert_eq!(text(&s.push(b"one!")), "***REDACTED(A)***!");
        // A false start is let go as soon as it is known to be one.
        assert_eq!(s.push(b"fak"), b"");
        assert_eq!(s.push(b"x\n"), b"fakx\n");
        assert_eq!(s.finish(), b"");
        // At the end of the stream a partial value is just text.
        let mut s = Scrubber::new(values(&[("A", "fake-one")]));
        assert_eq!(s.push(b"fake-on"), b"");
        assert_eq!(s.finish(), b"fake-on");
    }

    #[test]
    fn nothing_that_is_not_a_value_is_changed() {
        let input = "plain output, fake-on and ake-one, fake_one\n".as_bytes();
        assert_eq!(all_chunkings(&[("A", "fake-one")], input), input.to_vec());
        // No values: the stream is passed through untouched, at once.
        let mut s = Scrubber::new(vec![]);
        assert_eq!(s.push(b"abc"), b"abc");
        assert_eq!(s.finish(), b"");
    }

    #[test]
    fn a_value_that_contains_another_is_redacted_as_the_larger() {
        let out = all_chunkings(
            &[("SHORT", "abc"), ("LONG", "xxabcxx")],
            b"1 xxabcxx 2 abc 3",
        );
        assert_eq!(
            text(&out),
            "1 ***REDACTED(LONG)*** 2 ***REDACTED(SHORT)*** 3"
        );
    }

    #[test]
    fn overlapping_values_leave_no_fragment_of_either() {
        // "abcd" and "cdef" overlap in "cd".
        let out = all_chunkings(&[("P", "abcd"), ("Q", "cdef")], b"x abcdef y");
        let shown = text(&out);
        assert!(
            !shown.contains("ef") && !shown.contains("ab") && !shown.contains("cd"),
            "{shown}"
        );
        assert!(
            shown.contains("REDACTED(P)") && shown.contains("REDACTED(Q)"),
            "{shown}"
        );
        assert_eq!(shown, "x ***REDACTED(P)******REDACTED(Q)*** y");
        // The same value twice under two names: one marker, the longer/first.
        let out = all_chunkings(&[("A", "same"), ("B", "same")], b"a same b");
        assert_eq!(out.windows(10).filter(|w| *w == b"***REDACTE").count(), 1);
    }

    #[test]
    fn an_empty_value_is_ignored() {
        let out = all_chunkings(&[("E", ""), ("A", "fake-one")], b"a fake-one b");
        assert_eq!(text(&out), "a ***REDACTED(A)*** b");
        assert_eq!(
            all_chunkings(&[("E", "")], b"anything"),
            b"anything".to_vec()
        );
    }

    #[test]
    fn a_value_at_the_very_start_end_and_alone() {
        assert_eq!(
            text(&all_chunkings(&[("A", "fake-one")], b"fake-one")),
            "***REDACTED(A)***"
        );
        assert_eq!(
            text(&all_chunkings(&[("A", "fake-one")], b"fake-onefake-one")),
            "***REDACTED(A)******REDACTED(A)***"
        );
        assert_eq!(all_chunkings(&[("A", "fake-one")], b""), b"");
        // A value is written the moment it is complete, unless a longer value
        // could still contain it.
        let mut s = Scrubber::new(values(&[("A", "fake-one")]));
        assert_eq!(s.push(b"fake-on"), b"");
        assert_eq!(text(&s.push(b"e")), "***REDACTED(A)***");
        assert_eq!(s.finish(), b"");
        let mut s = Scrubber::new(values(&[("S", "abc"), ("L", "abcdef")]));
        assert_eq!(s.push(b"abc"), b"");
        assert_eq!(text(&s.push(b"def")), "***REDACTED(L)***");
        let mut s = Scrubber::new(values(&[("S", "abc"), ("L", "abcdef")]));
        assert_eq!(s.push(b"abc"), b"");
        assert_eq!(text(&s.finish()), "***REDACTED(S)***");
    }

    #[test]
    fn binary_output_and_a_repeated_pattern_survive() {
        let mut input = vec![0u8, 255, 1, 2, 3];
        input.extend_from_slice(b"fake-one");
        input.extend_from_slice(&[0, 0, 9]);
        let out = all_chunkings(&[("A", "fake-one")], &input);
        let mut want = vec![0u8, 255, 1, 2, 3];
        want.extend_from_slice(b"***REDACTED(A)***");
        want.extend_from_slice(&[0, 0, 9]);
        assert_eq!(out, want);
        // A run of overlapping occurrences is one span.
        let out = all_chunkings(&[("A", "aaaa")], b"aaaaaaaaaaaa");
        assert!(!text(&out).contains('a') || text(&out).starts_with("***REDACTED(A)***"));
        assert!(!text(&out).replace("***REDACTED(A)***", "").contains("aaaa"));
    }

    #[test]
    fn spans_of_a_whole_text_match_what_the_stream_redacts() {
        let s = Scrubber::new(values(&[("SHORT", "abc"), ("LONG", "xxabcxx")]));
        let text = b"1 xxabcxx 2 abc 3 abcabc";
        let spans = s.spans(text);
        let named: Vec<(&[u8], &str)> = spans
            .iter()
            .map(|(a, b, n)| (&text[*a..*b], n.as_str()))
            .collect();
        assert_eq!(
            named,
            [
                (&b"xxabcxx"[..], "LONG"),
                (&b"abc"[..], "SHORT"),
                (&b"abcabc"[..], "SHORT")
            ]
        );
        assert!(Scrubber::new(vec![]).spans(text).is_empty());
    }

    #[test]
    fn a_megabyte_of_output_is_scrubbed_and_nothing_leaks() {
        let value = "fake-secret-value-0123456789";
        let mut input = Vec::with_capacity(1 << 20);
        let mut n = 0u32;
        while input.len() < (1 << 20) {
            input.extend_from_slice(format!("line {n} of output ").as_bytes());
            if n.is_multiple_of(97) {
                input.extend_from_slice(value.as_bytes());
            }
            input.push(b'\n');
            n += 1;
        }
        // Whole, and in 4 KiB and 7-byte chunks.
        let whole = scrub(&[("S", value)], &input, input.len());
        assert!(!text(&whole).contains(value));
        assert!(text(&whole).contains("***REDACTED(S)***"));
        assert_eq!(scrub(&[("S", value)], &input, 4096), whole);
        assert_eq!(scrub(&[("S", value)], &input, 7), whole);
    }

    #[test]
    fn encoded_values_are_taken_out_with_their_form_in_the_label() {
        let value = "fake-one-value!";
        let mut s = Scrubber::with_encodings(values(&[("A", value), ("S", "abc")]));
        let b64 = {
            let set = crate::encoded::EncodedSet::build([("A", value.as_bytes())]);
            let (_, bytes) = set
                .targets()
                .into_iter()
                .find(|(l, _)| l == "A (base64)")
                .unwrap();
            String::from_utf8(bytes).unwrap()
        };
        let input = format!("raw {value}, b64 {b64}, short abc, tail");
        let mut out = s.push(input.as_bytes());
        out.extend(s.finish());
        let out = text(&out);
        assert_eq!(
            out,
            "raw ***REDACTED(A)***, b64 ***REDACTED(A (base64))***, short ***REDACTED(S)***, tail"
        );
        // Short values are taken out raw only: no encoded form of "abc".
        let mut s = Scrubber::with_encodings(values(&[("S", "abc")]));
        let mut out = s.push(b"YWJj abc");
        out.extend(s.finish());
        assert_eq!(text(&out), "YWJj ***REDACTED(S)***");
    }
}
