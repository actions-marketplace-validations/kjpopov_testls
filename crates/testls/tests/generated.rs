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
