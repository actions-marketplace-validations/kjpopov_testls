//! End-to-end tests for the generated shell completions and man page.

use std::process::Command;

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
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("man-pages");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");
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
