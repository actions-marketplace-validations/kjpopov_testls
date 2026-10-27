//! End-to-end tests for the help layout, generated shell completions and man
//! page.

use std::path::PathBuf;
use std::process::Command;

/// Directory under `CARGO_TARGET_TMPDIR` unique to this test process,
/// removed again on drop.
struct TempDir(PathBuf);

impl TempDir {
    /// Creates a fresh directory named after `name` and the process id, so
    /// concurrent `cargo test` runs sharing a target directory do not clash.
    fn new(name: &str) -> Self {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    /// Removes the directory and its contents.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs `testls` with `args` and returns its exit code and stdout.
fn run(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .args(args)
        .output()
        .expect("run testls");
    (
        out.status.code(),
        String::from_utf8(out.stdout).expect("UTF-8 stdout"),
    )
}

/// `testls --help` lays options out as two columns: flags on the left,
/// descriptions wrapped in an aligned right column at most 100 columns wide,
/// even on a wider terminal.
#[test]
fn help_is_two_columns() {
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg("--help")
        .env("COLUMNS", "200")
        .env("NO_COLOR", "1")
        .env_remove("CLICOLOR_FORCE")
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(0));
    let help = String::from_utf8(out.stdout).expect("UTF-8 stdout");
    let options = help.split_once("Options:\n").expect("options section").1;
    let first = options.lines().next().expect("first option");
    let column = first.find("Read more targets").expect("--file description");
    for line in options.lines() {
        assert!(line.chars().count() <= 100, "too wide: {line:?}");
        let (Some(left), Some(right)) = (line.get(..column), line.get(column..)) else {
            panic!("shorter than the flag column: {line:?}");
        };
        assert!(!right.starts_with(' '), "misaligned: {line:?}");
        let flag = left.trim_start();
        assert!(
            flag.is_empty() || flag.starts_with('-'),
            "description in flag column: {line:?}"
        );
    }
    assert!(options.lines().count() > 40, "descriptions are wrapped");
}

/// `testls completions SHELL` prints a script for each supported shell.
#[test]
fn completions_for_each_shell() {
    for (shell, marker) in [
        ("bash", "complete -F"),
        ("zsh", "#compdef testls"),
        ("fish", "complete -c testls"),
        ("powershell", "Register-ArgumentCompleter"),
        ("elvish", "edit:completion:arg-completer[testls]"),
    ] {
        let (code, script) = run(&["completions", shell]);
        assert_eq!(code, Some(0), "{shell}");
        assert!(script.contains(marker), "{shell}: {script}");
    }
    assert_eq!(run(&["completions", "tcsh"]).0, Some(2));
}

/// `testls man` prints a roff man page for section 1.
#[test]
fn man_page() {
    let (code, page) = run(&["man"]);
    assert_eq!(code, Some(0));
    assert!(page.contains(".TH testls 1"), "{page}");
    assert!(page.contains(".SH SUBCOMMANDS"), "{page}");
}

/// `testls man --dir DIR` writes the pages the main page refers to, and
/// fails with exit code 2 when the directory is missing.
#[test]
fn man_pages_in_dir() {
    let guard = TempDir::new("man-pages");
    let dir = &guard.0;
    let path = dir.to_str().expect("UTF-8 path");
    assert_eq!(run(&["man", "--dir", path]).0, Some(0));
    let main = std::fs::read_to_string(dir.join("testls.1")).expect("testls.1");
    for sub in ["explain", "completions", "man"] {
        assert!(
            main.contains(&format!("testls\\-{sub}(1)")),
            "{sub}: {main}"
        );
        let page = std::fs::read_to_string(dir.join(format!("testls-{sub}.1"))).expect(sub);
        assert!(
            page.contains(&format!(".TH testls-{sub} 1")),
            "{sub}: {page}"
        );
    }
    assert!(!dir.join("testls-help.1").exists());
    let missing = dir.join("missing");
    let missing = missing.to_str().expect("UTF-8 path");
    assert_eq!(run(&["man", "--dir", missing]).0, Some(2));
}
