// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Public decoding boundaries, including input consumed before YAML decoding.

use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use openshell_policy_schema::{
    ParseLimits, ParseProfile, RawValueParseError, RawValueParseErrorKind as Kind, parse_document,
    parse_document_file, parse_document_reader, parse_document_with_limits, parse_policy,
    parse_policy_bytes, parse_policy_file, parse_policy_reader, parse_policy_with_limits,
    parse_raw_value, parse_raw_value_bytes, parse_raw_value_bytes_with_limits,
    parse_raw_value_file, parse_raw_value_reader, parse_raw_value_with_limits,
};

struct InputFile(PathBuf);

impl InputFile {
    fn new(bytes: &[u8]) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "openshell-raw-value-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .expect("create unique input fixture");
        file.write_all(bytes).expect("write input fixture");
        Self(path)
    }
}

impl Drop for InputFile {
    fn drop(&mut self) {
        // Tests may remove the source intentionally; cleanup is best effort.
        let _ = std::fs::remove_file(&self.0);
    }
}

fn assert_safe_error(error: RawValueParseError, expected: Kind) {
    assert_eq!(error.kind(), expected);
    assert!(error.to_string().len() <= 80);
    assert!(format!("{error:?}").len() <= 180);
    assert!(error.source().is_none());
}

fn assert_boundary(
    source: &str,
    exact_limit: usize,
    set_limit: fn(&mut ParseLimits, usize),
    expected: Kind,
) {
    let file = InputFile::new(source.as_bytes());
    let mut limits = ParseLimits::default();
    set_limit(&mut limits, exact_limit);
    let value = parse_raw_value_with_limits(source, limits).expect("exact budget must pass");
    assert_eq!(
        parse_raw_value_bytes_with_limits(source.as_bytes(), limits).expect("exact bytes budget"),
        value
    );
    assert_eq!(
        parse_raw_value_reader(source.as_bytes(), limits).expect("exact reader budget"),
        value
    );
    assert_eq!(
        parse_raw_value_file(&file.0, limits).expect("exact file budget"),
        value
    );

    set_limit(&mut limits, exact_limit - 1);
    for result in [
        parse_raw_value_with_limits(source, limits),
        parse_raw_value_bytes_with_limits(source.as_bytes(), limits),
        parse_raw_value_reader(source.as_bytes(), limits),
        parse_raw_value_file(&file.0, limits),
    ] {
        assert_safe_error(result.expect_err("one over budget must fail"), expected);
    }
}

#[test]
fn encoded_bytes_exact_and_one_over_include_multibyte_and_comments() {
    let source = "é # comment\n";
    assert_boundary(
        source,
        source.len(),
        |l, n| l.max_bytes = n,
        Kind::InputBytes,
    );
}

#[test]
fn nesting_depth_exact_and_one_over() {
    assert_boundary("[[]]", 2, |l, n| l.max_depth = n, Kind::Depth);
}

#[test]
fn parser_events_exact_and_one_over_include_stream_boundaries() {
    // One scalar emits stream start/end, document start/end, and scalar.
    assert_boundary("a", 5, |l, n| l.max_events = n, Kind::Events);
}

#[test]
fn authored_nodes_exact_and_one_over_include_keys_and_collections() {
    assert_boundary("a: [b]", 4, |l, n| l.max_nodes = n, Kind::Nodes);
}

#[test]
fn aggregate_scalar_bytes_exact_and_one_over_include_keys_and_utf8() {
    assert_boundary(
        "ab: [cd, é]",
        6,
        |l, n| l.max_scalar_bytes = n,
        Kind::ScalarBytes,
    );
}

#[test]
fn alias_expansions_exact_and_one_over() {
    assert_boundary(
        "[&a foo, *a, *a]",
        2,
        |l, n| l.max_alias_expansions = n,
        Kind::AliasExpansions,
    );
    assert!(
        parse_raw_value_with_limits(
            "[foo]",
            ParseLimits {
                max_alias_expansions: 0,
                ..ParseLimits::default()
            },
        )
        .is_ok()
    );
}

#[test]
fn alias_anchor_ratio_exact_and_one_over() {
    let source = "[&a foo, *a, *a]";
    let exact = ParseLimits {
        alias_anchor_ratio: Some(2.0),
        ..ParseLimits::default()
    };
    assert!(parse_raw_value_with_limits(source, exact).is_ok());
    assert_safe_error(
        parse_raw_value_with_limits(
            source,
            ParseLimits {
                alias_anchor_ratio: Some(1.0),
                ..exact
            },
        )
        .expect_err("second alias exceeds ratio"),
        Kind::AliasAnchorRatio,
    );
}

#[test]
fn mapping_keys_exact_and_one_over() {
    assert_boundary(
        "a: 1\nb: 2",
        2,
        |l, n| l.max_mapping_keys = n,
        Kind::MappingKeys,
    );
}

#[test]
fn sequence_elements_exact_and_one_over() {
    assert_boundary(
        "[a, b]",
        2,
        |l, n| l.max_sequence_elements = n,
        Kind::SequenceElements,
    );
}

#[test]
fn documents_exact_and_one_over_and_larger_budget_stays_single_document() {
    assert_boundary("---\na\n", 1, |l, n| l.max_documents = n, Kind::Documents);
    for max_documents in [1, 2] {
        assert_safe_error(
            parse_raw_value_with_limits(
                "---\na\n---\nb\n",
                ParseLimits {
                    max_documents,
                    ..ParseLimits::default()
                },
            )
            .expect_err("multiple documents never silently discard a document"),
            Kind::Documents,
        );
    }
}

#[test]
fn duplicate_keys_and_typed_key_collisions_fail_at_public_boundaries() {
    for source in ["a: 1\na: 2\n", "1: a\n\"1\": b\n"] {
        let file = InputFile::new(source.as_bytes());
        for result in [
            parse_raw_value(source),
            parse_raw_value_bytes(source.as_bytes()),
            parse_raw_value_reader(source.as_bytes(), ParseLimits::default()),
            parse_raw_value_file(&file.0, ParseLimits::default()),
        ] {
            assert_safe_error(result.expect_err("ambiguous keys"), Kind::DuplicateKey);
        }
    }
}

#[test]
fn zero_merge_keys_pass_and_one_is_rejected_even_with_larger_budget() {
    for max_merge_keys in [0, 1] {
        let limits = ParseLimits {
            max_merge_keys,
            ..ParseLimits::default()
        };
        assert!(parse_raw_value_with_limits("a: b", limits).is_ok());
        assert!(parse_raw_value_with_limits("\"<<\": literal", limits).is_ok());
        let source = "defaults: &d {a: b}\nselected: {<<: *d}\n";
        let file = InputFile::new(source.as_bytes());
        for result in [
            parse_raw_value_with_limits(source, limits),
            parse_raw_value_bytes_with_limits(source.as_bytes(), limits),
            parse_raw_value_reader(source.as_bytes(), limits),
            parse_raw_value_file(&file.0, limits),
        ] {
            assert_safe_error(
                result.expect_err("merge syntax is forbidden"),
                Kind::MergeKeys,
            );
        }
    }
}

#[test]
fn default_entrypoints_apply_byte_budget_before_utf8_or_yaml_decode() {
    let bytes = vec![0xff; ParseLimits::default().max_bytes + 1];
    assert_safe_error(
        parse_raw_value_bytes(&bytes).expect_err("byte budget precedes UTF-8"),
        Kind::InputBytes,
    );
    let source = "#".repeat(ParseLimits::default().max_bytes + 1);
    assert_safe_error(
        parse_raw_value(&source).expect_err("comments consume input bytes"),
        Kind::InputBytes,
    );
}

#[test]
fn reader_consumes_only_budget_plus_one_probe_byte() {
    let mut reader = Cursor::new(vec![b'x'; 64]);
    let limits = ParseLimits {
        max_bytes: 9,
        ..ParseLimits::default()
    };
    assert_safe_error(
        parse_raw_value_reader(&mut reader, limits).expect_err("stream exceeds byte budget"),
        Kind::InputBytes,
    );
    assert_eq!(reader.position(), 10);
    let mut zero = Cursor::new(b"a");
    assert_safe_error(
        parse_raw_value_reader(
            &mut zero,
            ParseLimits {
                max_bytes: 0,
                ..limits
            },
        )
        .expect_err("zero byte budget reads only the probe"),
        Kind::InputBytes,
    );
    assert_eq!(zero.position(), 1);
}

#[test]
fn invalid_utf8_is_rejected_by_byte_reader_and_file_entrypoints() {
    let bytes = b"x: \xff";
    let file = InputFile::new(bytes);
    for result in [
        parse_raw_value_bytes(bytes),
        parse_raw_value_reader(bytes.as_slice(), ParseLimits::default()),
        parse_raw_value_file(&file.0, ParseLimits::default()),
    ] {
        assert_safe_error(result.expect_err("UTF-8 required"), Kind::InvalidUtf8);
    }
}

struct SecretReadError;

impl Read for SecretReadError {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("credential=reader-secret-do-not-emit"))
    }
}

#[test]
fn reader_errors_have_no_source_or_payload() {
    let error = parse_raw_value_reader(SecretReadError, ParseLimits::default())
        .expect_err("failing reader must fail");
    assert_safe_error(error, Kind::Io);
    assert!(!format!("{error:?} {error}").contains("reader-secret"));
}

struct InvalidReadCount;

impl Read for InvalidReadCount {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        Ok(buffer.len() + 1)
    }
}

#[test]
fn reader_rejects_invalid_reported_counts_without_panicking() {
    assert_safe_error(
        parse_raw_value_reader(InvalidReadCount, ParseLimits::default())
            .expect_err("faulty Read implementation must fail"),
        Kind::Io,
    );
}

struct InterruptOnce<R> {
    reader: R,
    interrupted: bool,
}

impl<R: Read> Read for InterruptOnce<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.reader.read(buffer)
    }
}

#[test]
fn reader_retries_interrupted_reads_without_losing_input() {
    let value = parse_raw_value_reader(
        InterruptOnce {
            reader: &b"a: b"[..],
            interrupted: false,
        },
        ParseLimits::default(),
    )
    .expect("interrupted read is retried");
    assert_eq!(value, parse_raw_value("a: b").expect("valid fixture"));
}

#[test]
fn file_errors_are_payload_free_and_non_regular_sources_are_rejected() {
    assert_safe_error(
        parse_raw_value_file(&std::env::temp_dir(), ParseLimits::default())
            .expect_err("directory cannot be a policy"),
        Kind::NotRegularFile,
    );
    let fixture = InputFile::new(b"a");
    std::fs::remove_file(&fixture.0).expect("remove fixture before open");
    let error = parse_raw_value_file(&fixture.0, ParseLimits::default())
        .expect_err("missing source must fail");
    assert_safe_error(error, Kind::Io);
    assert!(!format!("{error:?} {error}").contains("openshell-raw-value"));
}

#[test]
fn reader_rechecks_actual_length_when_open_regular_file_grows() {
    let file = InputFile::new(b"a");
    let reader = File::open(&file.0).expect("open initially bounded regular file");
    let initial_length = usize::try_from(reader.metadata().expect("file metadata").len())
        .expect("small fixture length");
    OpenOptions::new()
        .append(true)
        .open(&file.0)
        .expect("open append handle")
        .write_all(b"b")
        .expect("grow fixture after metadata read");
    assert_safe_error(
        parse_raw_value_reader(
            reader,
            ParseLimits {
                max_bytes: initial_length,
                ..ParseLimits::default()
            },
        )
        .expect_err("bounded read must catch growth"),
        Kind::InputBytes,
    );
}

#[test]
fn parser_diagnostics_omit_arbitrary_keys_scalars_and_anchor_names() {
    let secret = "credential-secret-do-not-emit".repeat(200);
    for source in [
        format!("{secret}: 1\n{secret}: 2"),
        format!("a: *{secret}"),
        format!("a: [\"{secret}\", {{"),
    ] {
        let error = parse_raw_value(&source).expect_err("malformed fixture");
        assert!(error.to_string().len() <= 80);
        assert!(format!("{error:?}").len() <= 180);
        assert!(!format!("{error:?} {error}").contains("credential-secret"));
        assert!(error.source().is_none());
    }
}

#[test]
fn authored_entrypoints_share_the_raw_boundary_and_preserve_valid_policy() {
    let source = "version: 1\nfilesystem_policy: {}\n";
    let file = InputFile::new(source.as_bytes());
    let limits = ParseLimits {
        max_bytes: source.len(),
        ..ParseLimits::default()
    };
    let profile = ParseProfile::RuntimeStrict;
    let expected = parse_policy(source, profile).expect("valid authored policy");
    for result in [
        parse_policy_bytes(source.as_bytes(), profile),
        parse_policy_with_limits(source, profile, limits),
        parse_policy_reader(source.as_bytes(), profile, limits),
        parse_policy_file(&file.0, profile, limits),
        parse_document(source, profile).map(|document| document.policy),
        parse_document_with_limits(source, profile, limits).map(|document| document.policy),
        parse_document_reader(source.as_bytes(), profile, limits).map(|document| document.policy),
        parse_document_file(&file.0, profile, limits).map(|document| document.policy),
    ] {
        assert_eq!(result.expect("authored public entrypoint"), expected);
    }
    let rejected = "version: 1\nversion: 1\n";
    let file = InputFile::new(rejected.as_bytes());
    for result in [
        parse_document_with_limits(rejected, profile, limits),
        parse_document_reader(rejected.as_bytes(), profile, limits),
        parse_document_file(&file.0, profile, limits),
    ] {
        let error = result.expect_err("authored decoder shares duplicate rejection");
        // IntoDiagnostic preserves the safe message while erasing the concrete
        // Error type; raw API tests above assert the typed classification.
        assert!(
            error
                .chain()
                .any(|cause| cause.to_string() == Kind::DuplicateKey.to_string())
        );
    }
}
