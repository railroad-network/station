//! Smoke test for `scripts/field-test-lora.sh --dry-run`.
//!
//! The LoRa field-acceptance script is human-run against real radios, but its
//! stage sequencing and pass/fail reporting must not rot. `--dry-run` exercises
//! every stage with no daemon, no `rnsd`, and no radio, so CI can prove the
//! script's own logic stays green without hardware.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

fn script_path() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/rrn-station; the script lives at the repo root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/field-test-lora.sh")
        .canonicalize()
        .expect("field-test-lora.sh should exist at the repo root")
}

fn run_dry_run(extra: &[&str]) -> (bool, String, String) {
    let mut cmd = Command::new("bash");
    cmd.arg(script_path()).arg("--dry-run");
    for a in extra {
        cmd.arg(a);
    }
    let out = cmd.output().expect("running the dry-run script");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn assert_all_pass(stdout: &str, stderr: &str, ok: bool, stages: &[&str]) {
    assert!(
        ok,
        "dry run should exit 0.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    for stage in stages {
        assert!(stdout.contains(stage), "missing {stage:?} in:\n{stdout}");
    }
    assert!(
        stdout.contains("ALL STAGES PASSED"),
        "expected an all-pass summary:\n{stdout}"
    );
    assert!(
        !stdout.contains("[FAIL]") && !stderr.contains("[FAIL]"),
        "no stage should fail in a dry run.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn dry_run_sender_passes_every_stage() {
    let (ok, stdout, stderr) = run_dry_run(&["--role", "sender"]);
    assert_all_pass(
        &stdout,
        &stderr,
        ok,
        &[
            "Stage 1 — health checks",
            "Stage 2 — push the signed bundle to the peer over radio",
            "Stage 3 — the delivery receipt returns over radio",
        ],
    );
}

#[test]
fn dry_run_receiver_passes_every_stage() {
    let (ok, stdout, stderr) = run_dry_run(&["--role", "receiver"]);
    assert_all_pass(
        &stdout,
        &stderr,
        ok,
        &[
            "Stage 1 — health checks",
            "Stage 3 — the pushed bundle arrives and is ingested over radio",
        ],
    );
}

#[test]
fn dry_run_defaults_to_the_sender_rehearsal() {
    // No --role: dry-run rehearses the fuller (sender) path.
    let (ok, stdout, stderr) = run_dry_run(&[]);
    assert_all_pass(&stdout, &stderr, ok, &["Stage 1 — health checks"]);
    assert!(
        stdout.contains("Role: sender"),
        "expected sender role:\n{stdout}"
    );
}

#[test]
fn unknown_argument_is_rejected() {
    let out = Command::new("bash")
        .arg(script_path())
        .arg("--not-a-flag")
        .output()
        .expect("running the script with a bad flag");
    // Usage error exit code, not a silent success.
    assert_eq!(out.status.code(), Some(2));
}
