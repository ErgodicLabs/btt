use serde::Serialize;

use crate::error::BttError;

/// Envelope for all command output.
#[derive(Serialize)]
struct SuccessEnvelope<T: Serialize> {
    ok: bool,
    data: T,
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    ok: bool,
    error: &'a BttError,
}

/// Print a success result as JSON to stdout.
/// When `quiet` is true, output is suppressed entirely.
pub fn print_success<T: Serialize>(data: &T, pretty: bool, quiet: bool) {
    if quiet {
        return;
    }
    let envelope = SuccessEnvelope { ok: true, data };
    let json = if pretty {
        serde_json::to_string_pretty(&envelope)
    } else {
        serde_json::to_string(&envelope)
    };
    match json {
        Ok(s) => println!("{}", s),
        Err(e) => {
            // Serialization of a known-good Serialize type should never fail.
            // If it does, something is fundamentally wrong — panic rather than
            // silently calling process::exit from a library function.
            panic!("fatal: failed to serialize output: {}", e);
        }
    }
}

/// Print an error result as JSON to stdout.
/// The caller is responsible for setting the process exit code.
pub fn print_error(err: &BttError, pretty: bool) {
    let envelope = ErrorEnvelope {
        ok: false,
        error: err,
    };
    let json = if pretty {
        serde_json::to_string_pretty(&envelope)
    } else {
        serde_json::to_string(&envelope)
    };
    match json {
        Ok(s) => println!("{}", s),
        Err(e) => {
            panic!("fatal: failed to serialize error output: {}", e);
        }
    }
}
